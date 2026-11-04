package app

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	access "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/assets"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/audit"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/inventory"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/responsibility"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	sourceport "github.com/QgMixtate/surveyscan/v2/internal/modules/sources/port"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/messaging"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type EventSink interface {
	Emit(context.Context, pgx.Tx, messaging.Event) error
}
type Registry struct {
	Machine   *MachineAPI
	Pool      *pgxpool.Pool
	Auth      access.Authorizer
	Sources   sourceport.Reader
	Assets    assets.Store
	Inventory inventory.Store
	Owners    responsibility.Store
	Audit     audit.Store
	Events    EventSink
	Wire      *wire.Validator
}

func NewRegistry(pool *pgxpool.Pool, auth access.Authorizer) (*Registry, error) {
	v, e := wire.New()
	if e != nil {
		return nil, e
	}
	return &Registry{Pool: pool, Auth: auth, Sources: sources.Store{}, Events: messaging.Writer{}, Wire: v}, nil
}
func lockRegistry(ctx context.Context, tx pgx.Tx, tenant string) error {
	_, e := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "registry:"+tenant)
	return e
}
func (r *Registry) assetEvent(ctx context.Context, tx pgx.Tx, tenant, uid, version, kind, producer, reason, actor, correlation string, subject ...string) error {
	if e := r.Assets.History(ctx, tx, tenant, uid, version, reason, actor); e != nil {
		return e
	}
	if e := r.Audit.Record(ctx, tx, tenant, actor, kind, "asset", uid); e != nil {
		return e
	}
	data := map[string]string{"asset_uid": uid, "reason_code": reason}
	if len(subject) > 0 {
		data["subject_id"] = subject[0]
	}
	return r.Events.Emit(ctx, tx, messaging.Event{Tenant: tenant, Producer: producer, Aggregate: "asset", AssetID: uid, Version: version, Type: kind, Correlation: correlation, Data: data})
}

// Ingest вызывается доверенным transport adapter после проверки его tenant/source principal.
// Origin key, generation, namespace и scope повторно проверяются внутри transaction.
func (r *Registry) Ingest(ctx context.Context, tenant, source string, raw []byte) (inventory.Result, error) {
	return r.IngestAuthorized(ctx, tenant, source, raw, nil)
}
func (r *Registry) IngestAuthorized(ctx context.Context, tenant, source string, raw []byte, authorize func(context.Context, pgx.Tx, contracts.Observation) error) (inventory.Result, error) {
	signed, o, canonical, e := r.Wire.Observation(raw)
	if e != nil {
		return inventory.Result{}, e
	}
	if tenant != o.TenantID || source != o.Origin.SourceID {
		return inventory.Result{}, domain.Unauthorized
	}
	tx, e := r.Pool.Begin(ctx)
	if e != nil {
		return inventory.Result{}, e
	}
	defer tx.Rollback(ctx)
	if e = lockRegistry(ctx, tx, tenant); e != nil {
		return inventory.Result{}, e
	}
	if authorize != nil {
		if e = authorize(ctx, tx, o); e != nil {
			return inventory.Result{}, e
		}
	}
	trust, e := r.Sources.Trust(ctx, tx, o, signed.KeyID)
	if e != nil {
		return inventory.Result{}, e
	}
	digest := sha256.Sum256(canonical)
	signature, e := base64.RawURLEncoding.DecodeString(signed.Signature)
	if e != nil || hex.EncodeToString(digest[:]) != signed.Digest || !ed25519.Verify(trust.PublicKey, append([]byte("SURVEYSCAN-OBSERVATION-V1\n"), canonical...), signature) {
		return inventory.Result{}, domain.Invalid
	}
	if result, exists, e := r.Inventory.Duplicate(ctx, tx, o, signed.Digest); e != nil || exists {
		return result, e
	}
	resolved, e := r.Assets.Resolve(ctx, tx, o)
	if e != nil {
		return inventory.Result{}, e
	}
	if e = r.Inventory.Record(ctx, tx, o, signed, canonical, signature, resolved.RecordKey, trust.Priority); e != nil {
		return inventory.Result{}, e
	}
	result := inventory.Result{ObservationID: o.ID, Disposition: "recorded_pending_resolution", Reason: resolved.Reason}
	if !resolved.Pending {
		result.AssetID = &resolved.AssetID
		result.Disposition = "applied"
		result.Reason = "SOURCE_MAPPING"
		if resolved.Created {
			subject, e := r.Owners.Assign(ctx, tx, tenant, resolved.AssetID, o.Scope.SiteID)
			if e != nil {
				return result, e
			}
			if e = r.assetEvent(ctx, tx, tenant, resolved.AssetID, "1", "asset.created.v1", "Assets", "SOURCE_MAPPING", source, o.ID); e != nil {
				return result, e
			}
			version, e := r.Assets.Bump(ctx, tx, tenant, resolved.AssetID)
			if e != nil {
				return result, e
			}
			if e = r.assetEvent(ctx, tx, tenant, resolved.AssetID, version, "responsibility.assigned.v1", "Responsibility", "SITE_FALLBACK", source, o.ID, subject); e != nil {
				return result, e
			}
		}
		link, e := r.Assets.Link(ctx, tx, o, resolved.AssetID)
		if e != nil {
			return result, e
		}
		changed, e := r.Inventory.Project(ctx, tx, o, resolved.AssetID, link, resolved.RecordKey, trust.Priority)
		if e != nil {
			return result, e
		}
		if changed {
			version, e := r.Assets.Bump(ctx, tx, tenant, resolved.AssetID)
			if e != nil {
				return result, e
			}
			if e = r.assetEvent(ctx, tx, tenant, resolved.AssetID, version, "asset.facts_changed.v1", "Assets", "INVENTORY_PROJECTED", source, o.ID); e != nil {
				return result, e
			}
		}
	}
	if e = r.Inventory.Result(ctx, tx, tenant, result); e != nil {
		return result, e
	}
	if e = r.Audit.Record(ctx, tx, tenant, source, "observation.recorded.v1", "observation", o.ID); e != nil {
		return result, e
	}
	data := map[string]string{"observation_id": o.ID, "source_id": source, "reason_code": result.Reason}
	if result.AssetID != nil {
		data["asset_uid"] = *result.AssetID
	}
	if e = r.Events.Emit(ctx, tx, messaging.Event{Tenant: tenant, Producer: "Inventory", Aggregate: "observation", AssetID: o.ID, Version: "1", Type: "observation.recorded.v1", Correlation: o.ID, Data: data}); e != nil {
		return result, e
	}
	if e = tx.Commit(ctx); e != nil {
		return result, e
	}
	return result, nil
}
func (r *Registry) readAsset(ctx context.Context, tx pgx.Tx, tenant, uid string) (contracts.Asset, error) {
	a, e := r.Assets.Get(ctx, tx, tenant, uid)
	if e != nil {
		return a, e
	}
	if e = r.Inventory.Enrich(ctx, tx, &a); e != nil {
		return a, e
	}
	a.Accountable, e = r.Owners.Accountable(ctx, tx, tenant, uid)
	return a, e
}
func (r *Registry) Get(ctx context.Context, id access.Identity, uid string) (contracts.Asset, error) {
	tx, e := r.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if e != nil {
		return contracts.Asset{}, e
	}
	defer tx.Rollback(ctx)
	if _, e = r.Auth.Authorize(ctx, tx, id.CredentialID, id.TenantID, "assets:read"); e != nil {
		return contracts.Asset{}, e
	}
	a, e := r.readAsset(ctx, tx, id.TenantID, uid)
	if e != nil {
		return a, e
	}
	return a, tx.Commit(ctx)
}
func (r *Registry) List(ctx context.Context, id access.Identity, after string, limit int) (contracts.AssetPage, error) {
	page := contracts.AssetPage{Items: []contracts.Asset{}}
	if limit < 1 || limit > 200 {
		return page, domain.Invalid
	}
	tx, e := r.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if e != nil {
		return page, e
	}
	defer tx.Rollback(ctx)
	if _, e = r.Auth.Authorize(ctx, tx, id.CredentialID, id.TenantID, "assets:read"); e != nil {
		return page, e
	}
	ids, e := r.Assets.IDs(ctx, tx, id.TenantID, after, limit+1)
	if e != nil {
		return page, e
	}
	if len(ids) > limit {
		ids = ids[:limit]
		last := ids[len(ids)-1]
		cursor, _ := json.Marshal([]string{id.TenantID, last})
		token := base64.RawURLEncoding.EncodeToString(cursor)
		page.NextCursor = &token
	}
	for _, uid := range ids {
		a, e := r.readAsset(ctx, tx, id.TenantID, uid)
		if e != nil {
			return page, e
		}
		page.Items = append(page.Items, a)
	}
	return page, tx.Commit(ctx)
}
func (r *Registry) Patch(ctx context.Context, id access.Identity, uid, revision string, p contracts.BusinessPatch) (contracts.Asset, error) {
	raw, validationErr := json.Marshal(p)
	if validationErr != nil {
		return contracts.Asset{}, domain.Invalid
	}
	if validationErr = r.Wire.Validate("BusinessPatch", raw); validationErr != nil {
		return contracts.Asset{}, validationErr
	}
	tx, e := r.Pool.Begin(ctx)
	if e != nil {
		return contracts.Asset{}, e
	}
	defer tx.Rollback(ctx)
	if _, e = r.Auth.Authorize(ctx, tx, id.CredentialID, id.TenantID, "assets:write"); e != nil {
		return contracts.Asset{}, e
	}
	if e = lockRegistry(ctx, tx, id.TenantID); e != nil {
		return contracts.Asset{}, e
	}
	if _, e = r.Assets.Get(ctx, tx, id.TenantID, uid); e != nil {
		return contracts.Asset{}, e
	}
	if e = r.Assets.Patch(ctx, tx, id.TenantID, uid, revision, p); e != nil {
		return contracts.Asset{}, e
	}
	v, e := r.Assets.Bump(ctx, tx, id.TenantID, uid)
	if e != nil {
		return contracts.Asset{}, e
	}
	if e = r.assetEvent(ctx, tx, id.TenantID, uid, v, "asset.facts_changed.v1", "Assets", "BUSINESS_FIELDS_CHANGED", id.UserID, ""); e != nil {
		return contracts.Asset{}, e
	}
	a, e := r.readAsset(ctx, tx, id.TenantID, uid)
	if e != nil {
		return a, e
	}
	return a, tx.Commit(ctx)
}
func (r *Registry) ConsumeOne(ctx context.Context, tenant string) (bool, error) {
	return messaging.ConsumeOne(ctx, r.Pool, tenant, "registry-version", func(ctx context.Context, tx pgx.Tx, event messaging.Event) error {
		if event.Aggregate != "asset" {
			return nil
		}
		return r.Assets.ApplyEvent(ctx, tx, tenant, event.AssetID, event.Version)
	})
}
