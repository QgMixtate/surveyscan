package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	accessport "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/assets"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/jackc/pgx/v5"
)

// C25.02 — очередь ручного разбора конфликтов сопоставления. Оператор (assets:write) для записи источника без актива:
// привязывает её к активу (attach), создаёт для неё новый актив (create_asset) или откладывает (dismiss); для записи,
// уже сопоставленной с активом, подтверждает текущую привязку (confirm). После привязки ожидавшие наблюдения записи
// применяются к активу по обычным правилам ранга. Всё — в одной транзакции с историей, outbox и аудитом.

type ConflictItem struct {
	assets.Conflict
	PendingObservations int    `json:"pending_observations"`
	ObservedHostname    string `json:"observed_hostname,omitempty"`
}

type ConflictPage struct {
	Tenant     string         `json:"tenant_id"`
	State      string         `json:"state"`
	Items      []ConflictItem `json:"items"`
	NextCursor *string        `json:"next_cursor"`
}

type ConflictResolution struct {
	Action   string `json:"action"` // attach | create_asset | confirm | dismiss
	AssetUID string `json:"asset_uid,omitempty"`
	Revision string `json:"revision,omitempty"`
}

type ConflictResult struct {
	ConflictID string  `json:"conflict_id"`
	Action     string  `json:"action"`
	AssetUID   *string `json:"asset_uid"`
	Replayed   int     `json:"replayed_observations"`
}

const conflictPageMax = 100

func (r *Registry) Conflicts(ctx context.Context, id accessport.Identity, state, cursor string, limit int) (ConflictPage, error) {
	out := ConflictPage{Tenant: id.TenantID, State: state, Items: []ConflictItem{}}
	tx, e := r.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	if _, e = r.Auth.Authorize(ctx, tx, id.CredentialID, id.TenantID, "assets:read"); e != nil {
		return out, e
	}
	rows, e := r.Assets.Conflicts(ctx, tx, id.TenantID, state, cursor, limit+1)
	if e != nil {
		return out, e
	}
	if len(rows) > limit {
		next := rows[limit-1].ID
		out.NextCursor = &next
		rows = rows[:limit]
	}
	for _, c := range rows {
		item := ConflictItem{Conflict: c}
		pending, e := r.Inventory.PendingObservations(ctx, tx, id.TenantID, c.RecordKey, 10000)
		if e != nil {
			return out, e
		}
		item.PendingObservations = len(pending)
		if n := len(pending); n > 0 {
			item.ObservedHostname = hostnameOf(pending[n-1].Observation.Candidates)
		}
		out.Items = append(out.Items, item)
	}
	return out, tx.Commit(ctx)
}

func hostnameOf(candidates []contracts.Candidate) string {
	for _, c := range candidates {
		if c.Kind == "hostname" {
			return c.Value
		}
	}
	return ""
}

func (r *Registry) ResolveConflict(ctx context.Context, id accessport.Identity, conflictID string, req ConflictResolution) (ConflictResult, error) {
	out := ConflictResult{ConflictID: conflictID, Action: req.Action}
	tx, e := r.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	if _, e = r.Auth.Authorize(ctx, tx, id.CredentialID, id.TenantID, "assets:write"); e != nil {
		return out, e
	}
	if e = lockRegistry(ctx, tx, id.TenantID); e != nil {
		return out, e
	}
	c, e := r.Assets.ConflictFor(ctx, tx, id.TenantID, conflictID)
	if e != nil {
		return out, e
	}
	if c.State != "open" {
		return out, domain.Conflict
	}
	if req.Revision != "" && req.Revision != c.Revision {
		return out, domain.Revision
	}
	pending, e := r.Inventory.PendingObservations(ctx, tx, id.TenantID, c.RecordKey, 10000)
	if e != nil {
		return out, e
	}
	tenant, actor := id.TenantID, id.UserID
	switch req.Action {
	case "dismiss":
		if req.AssetUID != "" {
			return out, domain.Invalid
		}
		if e = r.Assets.DismissConflict(ctx, tx, tenant, conflictID); e != nil {
			return out, e
		}
		if e = r.Audit.Record(ctx, tx, tenant, actor, "reconciliation.conflict_dismissed", "conflict", conflictID); e != nil {
			return out, e
		}
		return out, tx.Commit(ctx)
	case "confirm":
		// запись уже сопоставлена с активом: подтверждаем текущую привязку
		if c.AssetID == nil || req.AssetUID != "" && req.AssetUID != *c.AssetID {
			return out, domain.Invalid
		}
		req.AssetUID = *c.AssetID
	case "attach", "create_asset":
		if c.AssetID != nil {
			return out, domain.Invalid // перепривязка уже сопоставленной записи — это merge/split (C25.03)
		}
	default:
		return out, domain.Invalid
	}
	var last *PendingObservationRef
	if n := len(pending); n > 0 {
		last = &PendingObservationRef{Site: pending[n-1].Observation.Scope.SiteID, Scope: pending[n-1].Observation.Scope.ScopeID}
	}
	asset := req.AssetUID
	switch req.Action {
	case "attach", "confirm":
		_, scope, e := r.Assets.AssetScope(ctx, tx, tenant, asset)
		if e != nil {
			return out, e
		}
		if last != nil && last.Scope != scope {
			return out, domain.Conflict // привязка через границу network scope запрещена
		}
	case "create_asset":
		if req.AssetUID != "" || last == nil {
			return out, domain.Invalid // новый актив создаётся по данным ожидающего наблюдения записи
		}
		if asset, e = r.Assets.CreateAsset(ctx, tx, tenant, last.Site, last.Scope); e != nil {
			return out, e
		}
		subject, e := r.Owners.Assign(ctx, tx, tenant, asset, last.Site)
		if e != nil {
			return out, e
		}
		if e = r.assetEvent(ctx, tx, tenant, asset, "1", "asset.created.v1", "Assets", "MANUAL_RECONCILIATION", actor, conflictID); e != nil {
			return out, e
		}
		version, e := r.Assets.Bump(ctx, tx, tenant, asset)
		if e != nil {
			return out, e
		}
		if e = r.assetEvent(ctx, tx, tenant, asset, version, "responsibility.assigned.v1", "Responsibility", "SITE_FALLBACK", actor, conflictID, subject); e != nil {
			return out, e
		}
	}
	var candidates []contracts.Candidate
	if n := len(pending); n > 0 {
		candidates = pending[n-1].Observation.Candidates
	}
	if e = r.Assets.AttachRecord(ctx, tx, tenant, c.RecordKey, asset, candidates); e != nil {
		return out, e
	}
	for _, p := range pending {
		link, e := r.Assets.LinkReason(ctx, tx, p.Observation, asset, "MANUAL_RECONCILIATION")
		if e != nil {
			return out, e
		}
		var ch bool
		if p.Observation.Version.Minor == 2 {
			ch, e = r.Inventory.ProjectPartial12(ctx, tx, p.Observation, asset, link, c.RecordKey, p.Priority)
		} else {
			ch, e = r.Inventory.Project(ctx, tx, p.Observation, asset, link, c.RecordKey, p.Priority)
		}
		if e != nil {
			return out, e
		}
		_ = ch // факты применяются по рангу; событие ниже фиксирует решение оператора в любом случае
		out.Replayed++
	}
	// история решения оператора на активе (и применённые факты, если были)
	version, e := r.Assets.Bump(ctx, tx, tenant, asset)
	if e != nil {
		return out, e
	}
	reason := "MANUAL_RECONCILIATION"
	if e = r.assetEvent(ctx, tx, tenant, asset, version, "asset.facts_changed.v1", "Assets", reason, actor, conflictID); e != nil {
		return out, e
	}
	out.AssetUID = &asset
	return out, tx.Commit(ctx)
}

// PendingObservationRef — площадка и scope последнего ожидающего наблюдения записи.
type PendingObservationRef struct{ Site, Scope string }

func (r *Registry) conflictsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		q, err := url.ParseQuery(req.URL.RawQuery)
		if err != nil {
			access.APIError(w, 400, "INVALID_QUERY")
			return
		}
		for key, values := range q {
			if (key != "state" && key != "limit" && key != "cursor") || len(values) != 1 || values[0] == "" {
				access.APIError(w, 400, "INVALID_QUERY")
				return
			}
		}
		state, limit := q.Get("state"), 50
		if state == "" {
			state = "open"
		}
		if v := q.Get("limit"); v != "" {
			if limit, err = strconv.Atoi(v); err != nil || limit < 1 || limit > conflictPageMax {
				access.APIError(w, 400, "INVALID_QUERY")
				return
			}
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(req.Context()), 15*time.Second)
		defer cancel()
		id, _ := access.Identity(req.Context())
		out, e := r.Conflicts(ctx, id, state, q.Get("cursor"), limit)
		if e != nil {
			registryError(w, e)
			return
		}
		registryJSON(w, out)
	})
}

func (r *Registry) resolveConflictHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.RawQuery != "" {
			access.APIError(w, 400, "INVALID_QUERY")
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, req.Body, 4096))
		var body ConflictResolution
		if err != nil || json.Unmarshal(raw, &body) != nil {
			access.APIError(w, 400, "INVALID_BODY")
			return
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(req.Context()), 60*time.Second)
		defer cancel()
		id, _ := access.Identity(req.Context())
		out, e := r.ResolveConflict(ctx, id, req.PathValue("conflict_id"), body)
		if e != nil {
			if errors.Is(e, domain.Invalid) {
				access.APIError(w, 422, "INVALID_RESOLUTION")
				return
			}
			registryError(w, e)
			return
		}
		registryJSON(w, out)
	})
}
