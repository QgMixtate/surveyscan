package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	accessport "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/cmdb"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/inventory"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
)

// C26.02/C26.03 — CMDB: класс актива, ПО, компоненты, сервисы и связи (ADR decisions/C26-cmdb-model.md).
// Контракт — contracts/c26-cmdb.schema.json. Изменения — в одной транзакции с аудитом и собственной историей cmdb;
// актив-конец связи получает asset.facts_changed.v1 с причиной RELATION_CHANGED (C03 не расширяется).

var assetClasses = map[string]bool{"server": true, "workstation": true, "network_device": true, "printer": true, "virtual_machine": true, "unknown": true}

type AssetClass struct {
	Observed       string  `json:"observed"`
	ObservedReason string  `json:"observed_reason"`
	Manual         *string `json:"manual"`
	Effective      string  `json:"effective"`
}

type AssetCMDB struct {
	Tenant           string          `json:"tenant_id"`
	Asset            string          `json:"asset_uid"`
	Class            AssetClass      `json:"class"`
	BusinessRevision string          `json:"business_revision"`
	SoftwareCount    int             `json:"software_count"`
	ComponentCount   int             `json:"component_count"`
	Relations        []cmdb.Relation `json:"relations"`
}

type SoftwarePage struct {
	Tenant     string                   `json:"tenant_id"`
	Asset      string                   `json:"asset_uid"`
	Items      []inventory.Installation `json:"items"`
	NextCursor *string                  `json:"next_cursor"`
}

type ComponentList struct {
	Tenant string                `json:"tenant_id"`
	Asset  string                `json:"asset_uid"`
	Items  []inventory.Component `json:"items"`
}

type ProductList struct {
	Tenant string              `json:"tenant_id"`
	Query  string              `json:"query"`
	Items  []inventory.Product `json:"items"`
}

type ServicePage struct {
	Tenant     string         `json:"tenant_id"`
	Items      []cmdb.Service `json:"items"`
	NextCursor *string        `json:"next_cursor"`
}

type ServiceDetail struct {
	cmdb.Service
	Tenant    string          `json:"tenant_id"`
	Relations []cmdb.Relation `json:"relations"`
}

type ServicePatch struct {
	cmdb.ServiceInput
	Revision string `json:"revision"`
	Retire   bool   `json:"retire,omitempty"`
}

type ClassPatch struct {
	Class    *string `json:"asset_class"`
	Revision string  `json:"revision"`
}

func (r *Registry) readTx(ctx context.Context, id accessport.Identity) (pgx.Tx, error) {
	tx, e := r.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if e != nil {
		return nil, e
	}
	if _, e = r.Auth.Authorize(ctx, tx, id.CredentialID, id.TenantID, "assets:read"); e != nil {
		tx.Rollback(ctx)
		return nil, e
	}
	return tx, nil
}

func (r *Registry) AssetCMDB(ctx context.Context, id accessport.Identity, uid string) (AssetCMDB, error) {
	out := AssetCMDB{Tenant: id.TenantID, Asset: uid, Relations: []cmdb.Relation{}}
	if !identifier.Valid(uid) {
		return out, domain.NotFound
	}
	tx, e := r.readTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	if _, e = r.Assets.Get(ctx, tx, id.TenantID, uid); e != nil {
		return out, e
	}
	if out.Class.Manual, out.BusinessRevision, e = r.Assets.ManualClass(ctx, tx, id.TenantID, uid); e != nil {
		return out, e
	}
	if out.Class.Observed, out.Class.ObservedReason, e = r.Inventory.ObservedClass(ctx, tx, id.TenantID, uid); e != nil {
		return out, e
	}
	out.Class.Effective = out.Class.Observed
	if out.Class.Manual != nil {
		out.Class.Effective = *out.Class.Manual
	}
	if out.SoftwareCount, out.ComponentCount, e = r.Inventory.Counts(ctx, tx, id.TenantID, uid); e != nil {
		return out, e
	}
	if out.Relations, e = r.CMDB.RelationsOf(ctx, tx, id.TenantID, cmdb.End{Kind: "asset", ID: uid}); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}

func (r *Registry) SetAssetClass(ctx context.Context, id accessport.Identity, uid string, p ClassPatch) (AssetCMDB, error) {
	if !identifier.Valid(uid) {
		return AssetCMDB{}, domain.NotFound
	}
	if p.Class != nil && !assetClasses[*p.Class] || p.Revision == "" {
		return AssetCMDB{}, domain.Invalid
	}
	tx, e := r.assetOperationTx(ctx, id)
	if e != nil {
		return AssetCMDB{}, e
	}
	defer tx.Rollback(ctx)
	if _, e = r.Assets.Get(ctx, tx, id.TenantID, uid); e != nil {
		return AssetCMDB{}, e
	}
	if e = r.Assets.SetClass(ctx, tx, id.TenantID, uid, p.Revision, p.Class); e != nil {
		return AssetCMDB{}, e
	}
	version, e := r.Assets.Bump(ctx, tx, id.TenantID, uid)
	if e != nil {
		return AssetCMDB{}, e
	}
	if e = r.assetEvent(ctx, tx, id.TenantID, uid, version, "asset.facts_changed.v1", "Assets", "ASSET_CLASS_CHANGED", id.UserID, identifier.New()); e != nil {
		return AssetCMDB{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return AssetCMDB{}, e
	}
	return r.AssetCMDB(ctx, id, uid)
}

func (r *Registry) AssetSoftware(ctx context.Context, id accessport.Identity, uid, filter, cursor string, limit int) (SoftwarePage, error) {
	out := SoftwarePage{Tenant: id.TenantID, Asset: uid, Items: []inventory.Installation{}}
	if !identifier.Valid(uid) {
		return out, domain.NotFound
	}
	tx, e := r.readTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	if _, e = r.Assets.Get(ctx, tx, id.TenantID, uid); e != nil {
		return out, e
	}
	items, e := r.Inventory.Software(ctx, tx, id.TenantID, uid, filter, cursor, limit+1)
	if e != nil {
		return out, e
	}
	if len(items) > limit {
		items = items[:limit]
		next := items[limit-1].RecordKey
		out.NextCursor = &next
	}
	out.Items = items
	return out, tx.Commit(ctx)
}

func (r *Registry) AssetComponents(ctx context.Context, id accessport.Identity, uid string) (ComponentList, error) {
	out := ComponentList{Tenant: id.TenantID, Asset: uid, Items: []inventory.Component{}}
	if !identifier.Valid(uid) {
		return out, domain.NotFound
	}
	tx, e := r.readTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	if _, e = r.Assets.Get(ctx, tx, id.TenantID, uid); e != nil {
		return out, e
	}
	if out.Items, e = r.Inventory.Components(ctx, tx, id.TenantID, uid); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}

func (r *Registry) SoftwareProducts(ctx context.Context, id accessport.Identity, query string) (ProductList, error) {
	out := ProductList{Tenant: id.TenantID, Query: query, Items: []inventory.Product{}}
	if l := len([]rune(query)); l < 2 || l > 128 {
		return out, domain.Invalid
	}
	tx, e := r.readTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	if out.Items, e = r.Inventory.Products(ctx, tx, id.TenantID, query, 100); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}

func (r *Registry) Services(ctx context.Context, id accessport.Identity, cursor string, limit int, retired bool) (ServicePage, error) {
	out := ServicePage{Tenant: id.TenantID, Items: []cmdb.Service{}}
	tx, e := r.readTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	items, e := r.CMDB.Services(ctx, tx, id.TenantID, cursor, limit+1, retired)
	if e != nil {
		return out, e
	}
	if len(items) > limit {
		items = items[:limit]
		next := items[limit-1].UID
		out.NextCursor = &next
	}
	out.Items = items
	return out, tx.Commit(ctx)
}

func (r *Registry) ServiceDetail(ctx context.Context, id accessport.Identity, uid string) (ServiceDetail, error) {
	out := ServiceDetail{Tenant: id.TenantID, Relations: []cmdb.Relation{}}
	tx, e := r.readTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	if out.Service, e = r.CMDB.Service(ctx, tx, id.TenantID, uid); e != nil {
		return out, e
	}
	if out.Relations, e = r.CMDB.RelationsOf(ctx, tx, id.TenantID, cmdb.End{Kind: "service", ID: uid}); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}

func (r *Registry) CreateService(ctx context.Context, id accessport.Identity, in cmdb.ServiceInput) (ServiceDetail, error) {
	tx, e := r.assetOperationTx(ctx, id)
	if e != nil {
		return ServiceDetail{}, e
	}
	defer tx.Rollback(ctx)
	s, e := r.CMDB.CreateService(ctx, tx, id.TenantID, id.UserID, in)
	if e != nil {
		return ServiceDetail{}, e
	}
	if e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "cmdb.service_created", "service", s.UID); e != nil {
		return ServiceDetail{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return ServiceDetail{}, e
	}
	return r.ServiceDetail(ctx, id, s.UID)
}

func (r *Registry) PatchService(ctx context.Context, id accessport.Identity, uid string, p ServicePatch) (ServiceDetail, error) {
	if p.Revision == "" {
		return ServiceDetail{}, domain.Invalid
	}
	tx, e := r.assetOperationTx(ctx, id)
	if e != nil {
		return ServiceDetail{}, e
	}
	defer tx.Rollback(ctx)
	// связи выводимого сервиса закрываются: активы-концы получают событие
	var touched []cmdb.Relation
	if p.Retire {
		if touched, e = r.CMDB.RelationsOf(ctx, tx, id.TenantID, cmdb.End{Kind: "service", ID: uid}); e != nil {
			return ServiceDetail{}, e
		}
	}
	if _, e = r.CMDB.UpdateService(ctx, tx, id.TenantID, uid, p.Revision, id.UserID, p.ServiceInput, p.Retire); e != nil {
		return ServiceDetail{}, e
	}
	action := "cmdb.service_updated"
	if p.Retire {
		action = "cmdb.service_retired"
	}
	if e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, action, "service", uid); e != nil {
		return ServiceDetail{}, e
	}
	if e = r.relationAssetEvents(ctx, tx, id, uid, touched...); e != nil {
		return ServiceDetail{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return ServiceDetail{}, e
	}
	return r.ServiceDetail(ctx, id, uid)
}

// relationAssetEvents — у каждого актива-конца изменённых связей: версия, история, аудит, outbox.
func (r *Registry) relationAssetEvents(ctx context.Context, tx pgx.Tx, id accessport.Identity, correlation string, relations ...cmdb.Relation) error {
	seen := map[string]bool{}
	for _, rel := range relations {
		for _, end := range []cmdb.End{rel.From, rel.To} {
			if end.Kind != "asset" || seen[end.ID] {
				continue
			}
			seen[end.ID] = true
			version, e := r.Assets.Bump(ctx, tx, id.TenantID, end.ID)
			if e != nil {
				return e
			}
			if e = r.assetEvent(ctx, tx, id.TenantID, end.ID, version, "asset.facts_changed.v1", "Assets", "RELATION_CHANGED", id.UserID, correlation); e != nil {
				return e
			}
		}
	}
	return nil
}

func (r *Registry) CreateRelation(ctx context.Context, id accessport.Identity, in cmdb.RelationInput) (cmdb.Relation, error) {
	tx, e := r.assetOperationTx(ctx, id)
	if e != nil {
		return cmdb.Relation{}, e
	}
	defer tx.Rollback(ctx)
	rel, e := r.CMDB.CreateRelation(ctx, tx, id.TenantID, id.UserID, in)
	if e != nil {
		return rel, e
	}
	if e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "cmdb.relation_created", "relation", rel.ID); e != nil {
		return rel, e
	}
	if e = r.relationAssetEvents(ctx, tx, id, rel.ID, rel); e != nil {
		return rel, e
	}
	return rel, tx.Commit(ctx)
}

func (r *Registry) RetireRelation(ctx context.Context, id accessport.Identity, relation string) (cmdb.Relation, error) {
	tx, e := r.assetOperationTx(ctx, id)
	if e != nil {
		return cmdb.Relation{}, e
	}
	defer tx.Rollback(ctx)
	rel, e := r.CMDB.RetireRelation(ctx, tx, id.TenantID, relation, id.UserID)
	if e != nil {
		return rel, e
	}
	if e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "cmdb.relation_retired", "relation", rel.ID); e != nil {
		return rel, e
	}
	if e = r.relationAssetEvents(ctx, tx, id, rel.ID, rel); e != nil {
		return rel, e
	}
	return rel, tx.Commit(ctx)
}

// --- HTTP ---

func cmdbError(w http.ResponseWriter, req *http.Request, e error) {
	if redirectMerged(w, req, e) {
		return
	}
	if errors.Is(e, domain.Invalid) {
		access.APIError(w, 422, "INVALID_INPUT")
		return
	}
	registryError(w, e)
}

func queryOnly(w http.ResponseWriter, req *http.Request, keys ...string) (url.Values, bool) {
	q, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		access.APIError(w, 400, "INVALID_QUERY")
		return nil, false
	}
	for key, values := range q {
		known := false
		for _, k := range keys {
			known = known || k == key
		}
		if !known || len(values) != 1 || values[0] == "" || len(values[0]) > 256 {
			access.APIError(w, 400, "INVALID_QUERY")
			return nil, false
		}
	}
	return q, true
}

func pageLimit(w http.ResponseWriter, q url.Values, def, max int) (int, bool) {
	v := q.Get("limit")
	if v == "" {
		return def, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > max {
		access.APIError(w, 400, "INVALID_QUERY")
		return 0, false
	}
	return n, true
}

func cmdbContext(req *http.Request) (context.Context, context.CancelFunc, accessport.Identity) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(req.Context()), 20*time.Second)
	id, _ := access.Identity(req.Context())
	return ctx, cancel, id
}

func (r *Registry) cmdbHandlers() map[string]http.Handler {
	h := map[string]http.Handler{}
	h["GET /api/v1/assets/{asset_uid}/cmdb"] = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if _, ok := queryOnly(w, req); !ok {
			return
		}
		ctx, cancel, id := cmdbContext(req)
		defer cancel()
		out, e := r.AssetCMDB(ctx, id, req.PathValue("asset_uid"))
		if e != nil {
			cmdbError(w, req, e)
			return
		}
		registryJSON(w, out)
	})
	h["PATCH /api/v1/assets/{asset_uid}/classification"] = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body ClassPatch
		if !readOperationBody(w, req, &body) {
			return
		}
		ctx, cancel, id := cmdbContext(req)
		defer cancel()
		out, e := r.SetAssetClass(ctx, id, req.PathValue("asset_uid"), body)
		if e != nil {
			cmdbError(w, req, e)
			return
		}
		registryJSON(w, out)
	})
	h["GET /api/v1/assets/{asset_uid}/software"] = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		q, ok := queryOnly(w, req, "filter", "cursor", "limit")
		if !ok {
			return
		}
		limit, ok := pageLimit(w, q, 100, 500)
		if !ok {
			return
		}
		cursor := ""
		if c := q.Get("cursor"); c != "" {
			b, err := base64.RawURLEncoding.DecodeString(c)
			if err != nil || len(b) != 64 {
				access.APIError(w, 400, "INVALID_QUERY")
				return
			}
			cursor = string(b)
		}
		ctx, cancel, id := cmdbContext(req)
		defer cancel()
		out, e := r.AssetSoftware(ctx, id, req.PathValue("asset_uid"), q.Get("filter"), cursor, limit)
		if e != nil {
			cmdbError(w, req, e)
			return
		}
		if out.NextCursor != nil {
			c := base64.RawURLEncoding.EncodeToString([]byte(*out.NextCursor))
			out.NextCursor = &c
		}
		registryJSON(w, out)
	})
	h["GET /api/v1/assets/{asset_uid}/components"] = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if _, ok := queryOnly(w, req); !ok {
			return
		}
		ctx, cancel, id := cmdbContext(req)
		defer cancel()
		out, e := r.AssetComponents(ctx, id, req.PathValue("asset_uid"))
		if e != nil {
			cmdbError(w, req, e)
			return
		}
		registryJSON(w, out)
	})
	h["GET /api/v1/software"] = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		q, ok := queryOnly(w, req, "q")
		if !ok {
			return
		}
		ctx, cancel, id := cmdbContext(req)
		defer cancel()
		out, e := r.SoftwareProducts(ctx, id, q.Get("q"))
		if e != nil {
			if errors.Is(e, domain.Invalid) {
				access.APIError(w, 400, "INVALID_QUERY")
				return
			}
			cmdbError(w, req, e)
			return
		}
		registryJSON(w, out)
	})
	h["GET /api/v1/services"] = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		q, ok := queryOnly(w, req, "cursor", "limit", "include_retired")
		if !ok {
			return
		}
		limit, ok := pageLimit(w, q, 50, 200)
		if !ok {
			return
		}
		cursor, retired := q.Get("cursor"), q.Get("include_retired") == "true"
		if cursor != "" && !identifier.Valid(cursor) || q.Has("include_retired") && !retired && q.Get("include_retired") != "false" {
			access.APIError(w, 400, "INVALID_QUERY")
			return
		}
		ctx, cancel, id := cmdbContext(req)
		defer cancel()
		out, e := r.Services(ctx, id, cursor, limit, retired)
		if e != nil {
			cmdbError(w, req, e)
			return
		}
		registryJSON(w, out)
	})
	h["POST /api/v1/services"] = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body cmdb.ServiceInput
		if !readOperationBody(w, req, &body) {
			return
		}
		ctx, cancel, id := cmdbContext(req)
		defer cancel()
		out, e := r.CreateService(ctx, id, body)
		if e != nil {
			cmdbError(w, req, e)
			return
		}
		w.Header().Set("Location", "/api/v1/services/"+out.UID)
		registryJSONStatus(w, http.StatusCreated, out)
	})
	h["GET /api/v1/services/{service_uid}"] = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if _, ok := queryOnly(w, req); !ok {
			return
		}
		ctx, cancel, id := cmdbContext(req)
		defer cancel()
		out, e := r.ServiceDetail(ctx, id, req.PathValue("service_uid"))
		if e != nil {
			cmdbError(w, req, e)
			return
		}
		registryJSON(w, out)
	})
	h["PATCH /api/v1/services/{service_uid}"] = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body ServicePatch
		if !readOperationBody(w, req, &body) {
			return
		}
		ctx, cancel, id := cmdbContext(req)
		defer cancel()
		out, e := r.PatchService(ctx, id, req.PathValue("service_uid"), body)
		if e != nil {
			cmdbError(w, req, e)
			return
		}
		registryJSON(w, out)
	})
	h["POST /api/v1/relations"] = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body cmdb.RelationInput
		if !readOperationBody(w, req, &body) {
			return
		}
		ctx, cancel, id := cmdbContext(req)
		defer cancel()
		out, e := r.CreateRelation(ctx, id, body)
		if e != nil {
			cmdbError(w, req, e)
			return
		}
		registryJSONStatus(w, http.StatusCreated, out)
	})
	h["DELETE /api/v1/relations/{relation_id}"] = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if _, ok := queryOnly(w, req); !ok {
			return
		}
		ctx, cancel, id := cmdbContext(req)
		defer cancel()
		out, e := r.RetireRelation(ctx, id, req.PathValue("relation_id"))
		if e != nil {
			cmdbError(w, req, e)
			return
		}
		registryJSON(w, out)
	})
	return h
}

func registryJSONStatus(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
