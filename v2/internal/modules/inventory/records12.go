package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
	"github.com/jackc/pgx/v5"
)

type record12 struct {
	key    string
	fields map[string]json.RawMessage
}

// recordKey12 is a provider locator within one asset/section, not an asset UID.
// Do not hash the entire mutable row: changing a service state must retain its key.
func recordKey12(section string, row map[string]any) (string, error) {
	keys := []string{}
	switch section {
	case "identity", "os": // Exactly one host record per section.
	case "network", "services":
		keys = []string{"name"}
	case "hardware", "resources":
		keys = []string{"kind", "name"}
	case "software":
		keys = []string{"source", "scope", "registry_view", "registry_key", "principal_sid"}
		if row["registry_key"] == nil || row["scope"] == "current_user" && row["principal_sid"] == nil {
			return "", domain.Invalid
		}
	case "updates":
		keys = []string{"source", "id"}
	case "users_groups":
		keys = []string{"kind", "sid"}
		if row["kind"] == "membership" {
			keys = append(keys, "group_sid")
		}
	case "routes_ports":
		keys = []string{"kind", "family"}
		if row["kind"] == "route" {
			keys = append(keys, "destination", "gateway", "interface_index")
		} else {
			keys = append(keys, "local_address", "local_port", "remote_address", "remote_port", "interface_index")
		}
	case "protection":
		keys = []string{"kind", "provider", "name"}
	case "neighbors":
		keys = []string{"family", "interface_index", "address"}
	default:
		return "", domain.Invalid
	}
	parts := []any{section}
	for _, key := range keys {
		value := row[key]
		if text, ok := value.(string); ok && (section == "software" && (key == "registry_key" || key == "principal_sid") || section == "services" && key == "name") {
			value = strings.ToUpper(text)
		}
		parts = append(parts, key, value)
	}
	b, err := json.Marshal(map[string]any{"parts": parts})
	if err != nil {
		return "", err
	}
	b, err = wire.Canonical(b)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func preparePartial12(o contracts.Observation) (map[string][]record12, error) {
	v, err := wire.NewInventory12()
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(o)
	if err != nil {
		return nil, domain.Invalid
	}
	if _, err = v.Payload(b); err != nil {
		return nil, err
	}
	out := map[string][]record12{}
	for _, section := range o.Sections {
		// Complete snapshots require provider coverage and scoped deletion first.
		if section.Complete || section.Status == "ok" {
			return nil, domain.Invalid
		}
		seen := map[string]bool{}
		for _, row := range section.Records {
			key, err := recordKey12(section.Name, row)
			if err != nil || seen[key] {
				return nil, domain.Invalid
			}
			seen[key] = true
			r := record12{key: key, fields: map[string]json.RawMessage{}}
			for field, value := range row {
				b, err := json.Marshal(map[string]any{"value": value})
				if err != nil {
					return nil, domain.Invalid
				}
				b, err = wire.Canonical(b)
				if err != nil {
					return nil, err
				}
				var wrapped map[string]json.RawMessage
				if err = json.Unmarshal(b, &wrapped); err != nil {
					return nil, err
				}
				r.fields[field] = wrapped["value"]
			}
			out[section.Name] = append(out[section.Name], r)
		}
	}
	return out, nil
}

// ProjectPartial12 is an internal projection primitive, not an ingest endpoint.
// Caller must authorize, verify the signature/source continuity, store immutable
// evidence, link the observation, and emit the usual asset/audit/outbox effects
// in the same transaction. Existing HTTP ingest deliberately does not call this.
// No row or field can be deleted by a partial/unavailable provider response.
func (Store) ProjectPartial12(ctx context.Context, tx pgx.Tx, o contracts.Observation, asset, link, record string, priority int) (bool, error) {
	prepared, err := preparePartial12(o)
	if err != nil {
		return false, err
	}
	// Serialize first insert as well as updates. Hash collisions only serialize
	// unrelated assets; every data query still uses the full tenant/asset key.
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,1512))", o.TenantID+"/"+asset); err != nil {
		return false, err
	}
	changed := false
	for _, section := range o.Sections {
		if o.Clock == "skewed" || section.CollectedAt.After(time.Now().Add(5*time.Minute)) {
			continue
		}
		next := rank{o.Origin.SourceID, o.Origin.GenerationID, record, o.Sequence, o.Clock, priority, section.CollectedAt}
		var previous string
		err = tx.QueryRow(ctx, "SELECT last_attempt_id::text FROM inventory.record_section_state12 WHERE tenant_id=$1 AND asset_uid=$2 AND section_name=$3", o.TenantID, asset, section.Name).Scan(&previous)
		uncertain := o.Clock != "trusted"
		if err == nil {
			old, err := existingRank(ctx, tx, o.TenantID, previous, section.Name)
			if err != nil {
				return false, err
			}
			if !Newer(next, old) {
				continue
			}
			uncertain = uncertain || next.Source == old.Source && next.Collected.Before(old.Collected)
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return false, err
		}
		_, err = tx.Exec(ctx, `INSERT INTO inventory.record_section_state12(tenant_id,asset_uid,section_name,last_attempt_id,last_status,clock_uncertain) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,asset_uid,section_name) DO UPDATE SET last_attempt_id=excluded.last_attempt_id,last_status=excluded.last_status,clock_uncertain=excluded.clock_uncertain,projection_revision=inventory.record_section_state12.projection_revision+1`, o.TenantID, asset, section.Name, o.ID, section.Status, uncertain)
		if err != nil {
			return false, err
		}
		changed = true
		for _, row := range prepared[section.Name] {
			for field, value := range row.fields {
				var oldID string
				err = tx.QueryRow(ctx, "SELECT observation_id::text FROM inventory.record_facts12 WHERE tenant_id=$1 AND asset_uid=$2 AND section_name=$3 AND record_key=$4 AND field_name=$5", o.TenantID, asset, section.Name, row.key, field).Scan(&oldID)
				if err == nil {
					old, err := existingRank(ctx, tx, o.TenantID, oldID, section.Name)
					if err != nil {
						return false, err
					}
					if !Newer(next, old) {
						continue
					}
				} else if !errors.Is(err, pgx.ErrNoRows) {
					return false, err
				}
				_, err = tx.Exec(ctx, `INSERT INTO inventory.record_facts12(tenant_id,asset_uid,section_name,record_key,field_name,value,observation_id,link_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(tenant_id,asset_uid,section_name,record_key,field_name) DO UPDATE SET value=excluded.value,observation_id=excluded.observation_id,link_id=excluded.link_id,projection_revision=inventory.record_facts12.projection_revision+1`, o.TenantID, asset, section.Name, row.key, field, value, o.ID, link)
				if err != nil {
					return false, err
				}
			}
		}
	}
	return changed, nil
}
