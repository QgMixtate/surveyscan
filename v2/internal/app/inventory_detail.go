package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	accessport "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
)

func (r *Registry) InventoryDetail(ctx context.Context, id accessport.Identity, uid string) (contracts.InventoryDetail, error) {
	out := contracts.InventoryDetail{Version: contracts.Version{Major: 1}, Tenant: id.TenantID, Asset: uid}
	if !identifier.Valid(uid) {
		return out, domain.NotFound
	}
	tx, e := r.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	if _, e = r.Auth.Authorize(ctx, tx, id.CredentialID, id.TenantID, "assets:read"); e != nil {
		return out, e
	}
	// Проверить tenant-bound asset до доступа к подробным observations и source metadata.
	if out.Snapshot, e = r.readAsset(ctx, tx, id.TenantID, uid); e != nil {
		return out, e
	}
	subject, e := r.Owners.Accountable(ctx, tx, id.TenantID, uid)
	if e != nil {
		return out, e
	}
	out.Accountable, e = r.Owners.Subject(ctx, tx, id.TenantID, subject)
	if e != nil {
		return out, e
	}
	out.Facts, out.Sections, e = r.Inventory.Detail(ctx, tx, id.TenantID, uid)
	if e != nil {
		return out, e
	}
	ids := map[string]bool{}
	for _, f := range out.Facts {
		ids[f.Evidence.Origin.SourceID] = true
	}
	for _, s := range out.Sections {
		for _, p := range []*contracts.FactEvidence{s.Attempt, s.Success} {
			if p != nil {
				ids[p.Origin.SourceID] = true
			}
		}
	}
	sources := make([]string, 0, len(ids))
	for id := range ids {
		sources = append(sources, id)
	}
	out.Sources, e = r.Sources.Summaries(ctx, tx, id.TenantID, sources)
	if e != nil {
		return out, e
	}
	raw, e := json.Marshal(out)
	if e != nil {
		return out, e
	}
	if e = r.Wire.Validate("InventoryDetail", raw); e != nil {
		return out, errors.New("inventory detail snapshot unavailable")
	}
	return out, tx.Commit(ctx)
}
func (r *Registry) inventoryHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.RawQuery != "" {
			access.APIError(w, 400, "INVALID_QUERY")
			return
		}
		ctx, cancel := context.WithTimeout(req.Context(), 10*time.Second)
		defer cancel()
		id, _ := access.Identity(ctx)
		out, e := r.InventoryDetail(ctx, id, req.PathValue("asset_uid"))
		if e != nil {
			registryError(w, e)
			return
		}
		registryJSON(w, out)
	})
}
