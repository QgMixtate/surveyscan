package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	accessport "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/cmdb"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/jackc/pgx/v5"
)

// C22.04: ручной слой схемы сети — общий для тенанта документ с ревизией. Чтение — assets:read, правка —
// assets:write (администратор, оператор); каждое сохранение пишет событие аудита topology.map_saved.

type NetworkMapPut struct {
	Revision string          `json:"revision"`
	Document json.RawMessage `json:"document"`
}

func (r *Registry) NetworkMap(ctx context.Context, id accessport.Identity) (cmdb.NetworkMap, error) {
	tx, e := r.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if e != nil {
		return cmdb.NetworkMap{}, e
	}
	defer tx.Rollback(ctx)
	if _, e = r.Auth.Authorize(ctx, tx, id.CredentialID, id.TenantID, "assets:read"); e != nil {
		return cmdb.NetworkMap{}, e
	}
	out, e := r.CMDB.NetworkMap(ctx, tx, id.TenantID)
	if e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}

func (r *Registry) SaveNetworkMap(ctx context.Context, id accessport.Identity, p NetworkMapPut) (cmdb.NetworkMap, error) {
	if p.Revision == "" || len(p.Revision) > 20 {
		return cmdb.NetworkMap{}, domain.Invalid
	}
	doc, e := cmdb.ParseMap(p.Document)
	if e != nil {
		return cmdb.NetworkMap{}, e
	}
	tx, e := r.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if e != nil {
		return cmdb.NetworkMap{}, e
	}
	defer tx.Rollback(ctx)
	if _, e = r.Auth.Authorize(ctx, tx, id.CredentialID, id.TenantID, "assets:write"); e != nil {
		return cmdb.NetworkMap{}, e
	}
	out, e := r.CMDB.SaveNetworkMap(ctx, tx, id.TenantID, id.UserID, p.Revision, doc)
	if e != nil {
		return out, e
	}
	if e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "topology.map_saved", "network_map", id.TenantID); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}

func (r *Registry) networkMapHandlers() map[string]http.Handler {
	return map[string]http.Handler{
		"GET /api/v1/topology/map": http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.URL.RawQuery != "" {
				access.APIError(w, 400, "INVALID_QUERY")
				return
			}
			ctx, cancel, id := cmdbContext(req)
			defer cancel()
			out, e := r.NetworkMap(ctx, id)
			if e != nil {
				cmdbError(w, req, e)
				return
			}
			registryJSON(w, out)
		}),
		"PUT /api/v1/topology/map": http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.URL.RawQuery != "" {
				access.APIError(w, 400, "INVALID_QUERY")
				return
			}
			raw, err := io.ReadAll(http.MaxBytesReader(w, req.Body, 2<<20))
			var body NetworkMapPut
			if err != nil || sources.Strict(raw, &body) != nil {
				access.APIError(w, 400, "INVALID_BODY")
				return
			}
			ctx, cancel, id := cmdbContext(req)
			defer cancel()
			out, e := r.SaveNetworkMap(ctx, id, body)
			if e != nil {
				cmdbError(w, req, e)
				return
			}
			registryJSON(w, out)
		}),
	}
}
