package sources

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	access "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/messaging"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/sourceprofile"
	"github.com/jackc/pgx/v5"
	"strconv"
	"time"
)

func (s *MachineService) configTx(ctx context.Context, tx pgx.Tx, tenant, source string) (contracts.MachineConfig, bool, error) {
	c := contracts.MachineConfig{SourceID: source, Revision: "1", Sections: []string{"identity", "os", "network"}, Heartbeat: 60, Inventory: 900, Jitter: 10, SpoolBytes: 64 * 1024 * 1024}
	e := tx.QueryRow(ctx, `SELECT collector_id::text FROM sources.agents WHERE tenant_id=$1 AND source_id=$2 UNION ALL SELECT collector_id::text FROM sources.collectors WHERE tenant_id=$1 AND source_id=$2`, tenant, source).Scan(&c.CollectorID)
	if e != nil && e != pgx.ErrNoRows {
		return c, false, e
	}
	e = tx.QueryRow(ctx, `SELECT revision::text,heartbeat_seconds,inventory_seconds,jitter_percent,spool_limit_bytes FROM sources.profiles WHERE tenant_id=$1 AND source_id=$2`, tenant, source).Scan(&c.Revision, &c.Heartbeat, &c.Inventory, &c.Jitter, &c.SpoolBytes)
	if e == pgx.ErrNoRows {
		return c, false, nil
	}
	return c, e == nil, e
}
func (s *MachineService) profileTx(ctx context.Context, tx pgx.Tx, tenant, source string) (contracts.SourceProfile, error) {
	out := contracts.SourceProfile{Tenant: tenant, Source: source}
	view, e := s.viewTx(ctx, tx, tenant, source)
	if e != nil {
		return out, e
	}
	out.State = view.State
	out.LastContact = view.LastContact
	out.LastInventory = view.LastInventory
	out.Config, out.Managed, e = s.configTx(ctx, tx, tenant, source)
	if e != nil {
		return out, e
	}
	e = tx.QueryRow(ctx, `SELECT p.applied_revision::text,p.last_config_contact_at FROM sources.profile_progress p JOIN sources.sources s USING(tenant_id,source_id,generation_id) WHERE p.tenant_id=$1 AND p.source_id=$2`, tenant, source).Scan(&out.Applied, &out.LastConfigContact)
	if e == pgx.ErrNoRows {
		e = nil
	}
	return out, e
}
func (s *MachineService) Profile(ctx context.Context, actor access.Identity, source string) (contracts.SourceProfile, error) {
	var out contracts.SourceProfile
	if !identifier.Valid(source) {
		return out, domain.NotFound
	}
	tx, e := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	if _, e = s.Auth.Authorize(ctx, tx, actor.CredentialID, actor.TenantID, "sources:read"); e != nil {
		return out, e
	}
	out, e = s.profileTx(ctx, tx, actor.TenantID, source)
	if e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}
func (s *MachineService) UpdateProfile(ctx context.Context, actor access.Identity, source, expected string, options contracts.ProfileOptions) (contracts.SourceProfile, error) {
	var out contracts.SourceProfile
	raw, _ := json.Marshal(options)
	if e := s.Wire.Validate("SourceProfileUpdate", raw); e != nil {
		return out, e
	}
	if !identifier.Valid(source) {
		return out, domain.NotFound
	}
	if n, e := strconv.ParseUint(expected, 10, 64); e != nil || n == 0 || n == ^uint64(0) {
		return out, domain.Invalid
	}
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	if _, e = s.Auth.Authorize(ctx, tx, actor.CredentialID, actor.TenantID, "sources:admin"); e != nil {
		return out, e
	}
	var state, kind string
	e = tx.QueryRow(ctx, "SELECT state,source_kind FROM sources.sources WHERE tenant_id=$1 AND source_id=$2 FOR UPDATE", actor.TenantID, source).Scan(&state, &kind)
	if e == pgx.ErrNoRows {
		return out, domain.NotFound
	}
	if e != nil {
		return out, e
	}
	if kind != "agent" && kind != "collector" {
		return out, domain.Invalid
	}
	if kind == "collector" && options.Inventory != 900 {
		return out, domain.Invalid
	}
	if state != "active" {
		return out, domain.Conflict
	}
	current, _, e := s.configTx(ctx, tx, actor.TenantID, source)
	if e != nil {
		return out, e
	}
	if expected != current.Revision {
		return out, domain.Revision
	}
	_, e = tx.Exec(ctx, `INSERT INTO sources.profiles(tenant_id,source_id,heartbeat_seconds,inventory_seconds,jitter_percent,spool_limit_bytes) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,source_id) DO UPDATE SET revision=sources.profiles.revision+1,heartbeat_seconds=excluded.heartbeat_seconds,inventory_seconds=excluded.inventory_seconds,jitter_percent=excluded.jitter_percent,spool_limit_bytes=excluded.spool_limit_bytes,updated_at=clock_timestamp()`, actor.TenantID, source, options.Heartbeat, options.Inventory, options.Jitter, options.SpoolBytes)
	if e != nil {
		return out, e
	}
	var revision string
	e = tx.QueryRow(ctx, "UPDATE sources.sources SET revision=revision+1 WHERE tenant_id=$1 AND source_id=$2 RETURNING revision::text", actor.TenantID, source).Scan(&revision)
	if e != nil {
		return out, e
	}
	if e = s.Audit.Record(ctx, tx, actor.TenantID, actor.UserID, "source.profile_updated", "source", source); e != nil {
		return out, e
	}
	if e = (messaging.Writer{}).Emit(ctx, tx, messaging.Event{Tenant: actor.TenantID, Producer: "Sources", Aggregate: "source", AssetID: source, Version: revision, Type: "source.profile_updated.v1", Data: map[string]string{"source_id": source}}); e != nil {
		return out, e
	}
	out, e = s.profileTx(ctx, tx, actor.TenantID, source)
	if e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}
func (s *MachineService) PollProfile(ctx context.Context, fp string, frame contracts.ProfileFrame) (contracts.ProfilePayload, error) {
	var out contracts.ProfilePayload
	raw, _ := json.Marshal(frame)
	if e := s.Wire.Validate("ProfileRequest", raw); e != nil {
		return out, e
	}
	var req contracts.ProfileRequestPayload
	_ = json.Unmarshal(frame.Payload, &req)
	if req.Version.Major != 1 || req.Version.Minor > 1 {
		return out, domain.Invalid
	}
	tx, e := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	o, e := s.heartbeatOrigin(ctx, tx, fp, req.Tenant, req.Origin.SourceID)
	if e != nil {
		return out, e
	}
	if o.Origin != req.Origin {
		return out, domain.Unauthorized
	}
	var public []byte
	e = tx.QueryRow(ctx, `SELECT public_key FROM sources.ingest_bindings WHERE tenant_id=$1 AND source_id=$2 AND generation_id=$3 AND key_id=$4 AND active LIMIT 1 FOR SHARE`, req.Tenant, req.Origin.SourceID, req.Origin.GenerationID, frame.KeyID).Scan(&public)
	if e == pgx.ErrNoRows {
		return out, domain.Unauthorized
	}
	if e != nil {
		return out, e
	}
	if e = sourceprofile.Verify(frame, sourceprofile.RequestDomain, frame.KeyID, public); e != nil {
		return out, e
	}
	nonce, e := base64.RawURLEncoding.Strict().DecodeString(req.Nonce)
	if e != nil || len(nonce) != 32 {
		return out, domain.Invalid
	}
	var now time.Time
	if e = tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); e != nil {
		return out, e
	}
	now = now.UTC()
	if req.Sent.After(now.Add(30*time.Second)) || now.Sub(req.Sent) > 2*time.Minute {
		return out, domain.Invalid
	}
	config, managed, e := s.configTx(ctx, tx, req.Tenant, req.Origin.SourceID)
	if e != nil {
		return out, e
	}
	if req.Applied != nil {
		n, e := strconv.ParseUint(*req.Applied, 10, 64)
		current, _ := strconv.ParseUint(config.Revision, 10, 64)
		if e != nil || n < 2 || n > current {
			return out, domain.Invalid
		}
	}
	_, e = tx.Exec(ctx, `INSERT INTO sources.profile_progress(tenant_id,source_id,generation_id,applied_revision) VALUES($1,$2,$3,$4) ON CONFLICT(tenant_id,source_id,generation_id) DO UPDATE SET applied_revision=GREATEST(sources.profile_progress.applied_revision,excluded.applied_revision),last_config_contact_at=clock_timestamp()`, req.Tenant, req.Origin.SourceID, req.Origin.GenerationID, req.Applied)
	if e != nil {
		return out, e
	}
	if d := req.Diagnostics; d != nil {
		if req.Version.Minor < 1 || d.Collected.After(now.Add(30*time.Second)) || now.Sub(d.Collected) > 2*time.Minute {
			return out, domain.Invalid
		}
		_, e = tx.Exec(ctx, `INSERT INTO sources.runtime_diagnostics(tenant_id,source_id,generation_id,collected_at,pending_files,pending_bytes,oldest_pending_at,disk_available_bytes,certificate_expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(tenant_id,source_id,generation_id) DO UPDATE SET collected_at=excluded.collected_at,received_at=clock_timestamp(),pending_files=excluded.pending_files,pending_bytes=excluded.pending_bytes,oldest_pending_at=excluded.oldest_pending_at,disk_available_bytes=excluded.disk_available_bytes,certificate_expires_at=excluded.certificate_expires_at WHERE excluded.collected_at>=sources.runtime_diagnostics.collected_at`, req.Tenant, req.Origin.SourceID, req.Origin.GenerationID, d.Collected, d.PendingFiles, d.PendingBytes, d.OldestPending, d.DiskAvailable, d.CertificateExpires)
		if e != nil {
			return out, e
		}
	}
	out = contracts.ProfilePayload{Version: contracts.Version{Major: 1}, Tenant: req.Tenant, Origin: req.Origin, Nonce: req.Nonce, Issued: now, Expires: now.Add(2 * time.Minute), Managed: managed, Config: config}
	return out, tx.Commit(ctx)
}
