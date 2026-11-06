package sources

import (
	"context"
	"encoding/json"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	access "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
	"github.com/jackc/pgx/v5"
)

func (s *MachineService) PollInventoryProfile12(ctx context.Context, fp string, raw []byte) (contracts.InventoryProfile12, error) {
	var empty contracts.InventoryProfile12
	frame, req, err := wire.InventoryProfileRequest12(raw)
	if err != nil {
		return empty, domain.Invalid
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return empty, err
	}
	defer tx.Rollback(ctx)
	origin, err := s.heartbeatOrigin(ctx, tx, fp, req.Tenant, req.Origin.SourceID)
	if err != nil {
		return empty, err
	}
	if origin.Origin != req.Origin || origin.Origin.SourceKind != "agent" {
		return empty, domain.Unauthorized
	}
	var public []byte
	err = tx.QueryRow(ctx, `SELECT public_key FROM sources.ingest_bindings WHERE tenant_id=$1 AND source_id=$2 AND generation_id=$3 AND key_id=$4 AND active LIMIT 1 FOR SHARE`, req.Tenant, req.Origin.SourceID, req.Origin.GenerationID, frame.KeyID).Scan(&public)
	if err == pgx.ErrNoRows {
		return empty, domain.Unauthorized
	}
	if err != nil {
		return empty, err
	}
	if err = wire.VerifyProfileFrame12(frame, wire.InventoryProfileRequestDomain12, frame.KeyID, public); err != nil {
		return empty, domain.Unauthorized
	}
	var now time.Time
	if err = tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return empty, err
	}
	now = now.UTC()
	if req.Sent.After(now.Add(30*time.Second)) || now.Sub(req.Sent) > 2*time.Minute {
		return empty, domain.Invalid
	}
	common, managed, err := s.configTx(ctx, tx, req.Tenant, req.Origin.SourceID)
	if err != nil {
		return empty, err
	}
	config, err := wire.InventoryConfigFromCommon12(common)
	if err != nil {
		return empty, err
	}
	var applied *string
	if req.Applied != nil {
		// Application is origin-reported, not hardware attestation. A revision must
		// at least have been offered previously to this exact source generation.
		var offered string
		err = tx.QueryRow(ctx, `SELECT offered_revision::text FROM sources.inventory_profile_progress12 WHERE tenant_id=$1 AND source_id=$2 AND generation_id=$3 AND policy_id=$4 FOR UPDATE`, req.Tenant, req.Origin.SourceID, req.Origin.GenerationID, req.Applied.Policy).Scan(&offered)
		if err == pgx.ErrNoRows {
			return empty, domain.Invalid
		}
		if err != nil {
			return empty, err
		}
		value, _ := wire.ProfileRevision12(req.Applied.Common)
		previous, _ := wire.ProfileRevision12(offered)
		current, _ := wire.ProfileRevision12(common.Revision)
		if value > previous || value > current {
			return empty, domain.Invalid
		}
		applied = &req.Applied.Common
	}
	_, err = tx.Exec(ctx, `INSERT INTO sources.inventory_profile_progress12(tenant_id,source_id,generation_id,policy_id,offered_revision,applied_revision) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,source_id,generation_id) DO UPDATE SET offered_revision=GREATEST(sources.inventory_profile_progress12.offered_revision,excluded.offered_revision),applied_revision=GREATEST(sources.inventory_profile_progress12.applied_revision,excluded.applied_revision),last_profile_contact_at=clock_timestamp()`, req.Tenant, req.Origin.SourceID, req.Origin.GenerationID, contracts.InventoryPolicy12, config.Revision, applied)
	if err != nil {
		return empty, err
	}
	out := contracts.InventoryProfile12{Version: contracts.Version{Major: 1, Minor: 2}, Tenant: req.Tenant, Origin: req.Origin, Nonce: req.Nonce, Issued: now, Expires: now.Add(2 * time.Minute), Managed: managed, Config: config}
	// Validate the generated payload before recording any offer/progress.
	body, _ := json.Marshal(out)
	if err = wire.ValidateInventoryProfile12("Response", body); err != nil {
		return empty, err
	}
	if err = tx.Commit(ctx); err != nil {
		return empty, err
	}
	return out, nil
}

func (s *MachineService) InventoryProfile12View(ctx context.Context, actor access.Identity, source string) (contracts.SourceInventoryProfile12, error) {
	var out contracts.SourceInventoryProfile12
	if !identifier.Valid(source) {
		return out, domain.NotFound
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return out, err
	}
	defer tx.Rollback(ctx)
	if _, err = s.Auth.Authorize(ctx, tx, actor.CredentialID, actor.TenantID, "sources:read"); err != nil {
		return out, err
	}
	err = tx.QueryRow(ctx, `SELECT tenant_id::text,source_id::text,generation_id::text FROM sources.sources WHERE tenant_id=$1 AND source_id=$2 AND source_kind='agent'`, actor.TenantID, source).Scan(&out.Tenant, &out.Source, &out.Generation)
	if err == pgx.ErrNoRows {
		return out, domain.NotFound
	}
	if err != nil {
		return out, err
	}
	common, managed, err := s.configTx(ctx, tx, actor.TenantID, source)
	if err != nil {
		return out, err
	}
	out.Config, err = wire.InventoryConfigFromCommon12(common)
	if err != nil {
		return out, err
	}
	out.Managed = managed
	var applied *string
	var policy string
	err = tx.QueryRow(ctx, `SELECT applied_revision::text,policy_id,last_profile_contact_at FROM sources.inventory_profile_progress12 WHERE tenant_id=$1 AND source_id=$2 AND generation_id=$3`, out.Tenant, out.Source, out.Generation).Scan(&applied, &policy, &out.LastContact)
	if err != nil && err != pgx.ErrNoRows {
		return out, err
	}
	if applied != nil {
		out.Applied = &contracts.InventoryRevision12{Common: *applied, Policy: policy}
	}
	return out, tx.Commit(ctx)
}
