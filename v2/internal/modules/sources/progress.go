package sources

import (
	"context"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/jackc/pgx/v5"
)

func (Store) RecordSuccess(ctx context.Context, tx pgx.Tx, o contracts.Observation) error {
	if o.Clock != "trusted" {
		return nil
	}
	var at time.Time
	collected := false
	for _, s := range o.Sections {
		if s.Status == "not_requested" {
			continue
		}
		if s.CollectedAt.After(time.Now().Add(5 * time.Minute)) {
			return nil
		}
		if o.Version.Minor == 2 {
			// Профиль 1.2 частичный по замыслу (R-027, решение 2А): успех — ни один раздел не «недоступен»
			// (не поддерживаемые платформой разделы успеху не мешают) и хотя бы один раздел собран.
			switch s.Status {
			case "partial":
				collected = true
			case "unsupported":
				continue
			default:
				return nil
			}
		} else if s.Status != "ok" || !s.Complete {
			return nil
		}
		if s.CollectedAt.After(at) {
			at = s.CollectedAt
		}
	}
	if o.Version.Minor == 2 && !collected {
		return nil
	}
	if at.IsZero() {
		return nil
	}
	_, e := tx.Exec(ctx, `INSERT INTO sources.inventory_progress(tenant_id,source_id,generation_id,last_successful_inventory_at) VALUES($1,$2,$3,$4) ON CONFLICT(tenant_id,source_id,generation_id) DO UPDATE SET last_successful_inventory_at=GREATEST(sources.inventory_progress.last_successful_inventory_at,excluded.last_successful_inventory_at)`, o.TenantID, o.Origin.SourceID, o.Origin.GenerationID, at)
	return e
}
func (Store) Summaries(ctx context.Context, tx pgx.Tx, tenant string, ids []string) ([]contracts.SourceSummary, error) {
	out := []contracts.SourceSummary{}
	rows, e := tx.Query(ctx, `SELECT s.tenant_id::text,s.source_id::text,s.source_kind,s.site_id::text,s.state,s.generation_id::text,GREATEST(s.last_contact_at,(SELECT h.last_contact_at FROM sources.heartbeat_state h WHERE h.tenant_id=s.tenant_id AND h.source_id=s.source_id AND h.generation_id=s.generation_id)),GREATEST(s.last_successful_inventory_at,p.last_successful_inventory_at) FROM sources.sources s LEFT JOIN sources.inventory_progress p USING(tenant_id,source_id,generation_id) WHERE s.tenant_id=$1 AND s.source_id=ANY($2::uuid[]) ORDER BY s.source_id`, tenant, ids)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	for rows.Next() {
		var s contracts.SourceSummary
		if e = rows.Scan(&s.TenantID, &s.SourceID, &s.Kind, &s.SiteID, &s.State, &s.Generation, &s.LastContact, &s.LastInventory); e != nil {
			return out, e
		}
		s.ContactStatus = "unknown"
		if s.LastContact != nil {
			v := s.LastContact.UTC()
			s.LastContact = &v
			s.ContactStatus = "stale"
			if !v.After(time.Now().Add(5*time.Minute)) && time.Since(v) <= 180*time.Second {
				s.ContactStatus = "recently_seen"
			}
		}
		if s.LastInventory != nil {
			v := s.LastInventory.UTC()
			s.LastInventory = &v
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
