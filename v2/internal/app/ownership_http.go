package app

import (
	"context"
	"errors"
	"net/http"

	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	accessport "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/responsibility"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
)

// C27.02/C27.03 — субъекты, назначения, передача, рабочие списки и массовое назначение (ADR decisions/C27-ownership.md).
// Каждое изменение назначения на активе: версия актива, история, аудит и responsibility.assigned.v1 в той же транзакции.

type SubjectPage struct {
	Tenant     string                       `json:"tenant_id"`
	Items      []responsibility.SubjectInfo `json:"items"`
	NextCursor *string                      `json:"next_cursor"`
}

type SubjectPatch struct {
	responsibility.SubjectInput
	Revision   string `json:"revision"`
	Deactivate bool   `json:"deactivate,omitempty"`
}

type SubjectResult struct {
	Subject  responsibility.SubjectInfo `json:"subject"`
	Reassign int                        `json:"reassigned_assignments"`
}

type AssetAssignments struct {
	Tenant  string                      `json:"tenant_id"`
	Asset   string                      `json:"asset_uid"`
	Version string                      `json:"version"`
	Active  []responsibility.Assignment `json:"active"`
	History []responsibility.Assignment `json:"history"`
}

type AssignRequest struct {
	Role            string  `json:"role"`
	Subject         *string `json:"subject_id"` // null — снять необязательную роль
	Note            *string `json:"note,omitempty"`
	ExpectedVersion string  `json:"expected_version"`
}

type BulkItem struct {
	Asset           string `json:"asset_uid"`
	ExpectedVersion string `json:"expected_version"`
}

type BulkAssignRequest struct {
	Role    string     `json:"role"`
	Subject string     `json:"subject_id"`
	Note    *string    `json:"note,omitempty"`
	Items   []BulkItem `json:"items"`
}

type BulkAssignResult struct {
	Applied   int      `json:"applied"`
	Unchanged int      `json:"unchanged"`
	Stale     []string `json:"stale_asset_uids"`
}

type WorklistItem struct {
	Asset       string                      `json:"asset_uid"`
	Version     string                      `json:"version"`
	DisplayName *string                     `json:"display_name"`
	Hostname    *string                     `json:"observed_hostname"`
	Assignments []responsibility.Assignment `json:"assignments"`
}

type WorklistPage struct {
	Tenant     string         `json:"tenant_id"`
	Scope      string         `json:"scope"`
	Items      []WorklistItem `json:"items"`
	NextCursor *string        `json:"next_cursor"`
}

// ErrStale — массовая операция отклонена целиком: перечислены активы с устаревшей версией.
type ErrStale struct{ Assets []string }

func (e ErrStale) Error() string { return "stale asset versions" }

func (r *Registry) adminTx(ctx context.Context, id accessport.Identity, permission string) (pgx.Tx, error) {
	tx, e := r.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if e != nil {
		return nil, e
	}
	if _, e = r.Auth.Authorize(ctx, tx, id.CredentialID, id.TenantID, permission); e != nil {
		tx.Rollback(ctx)
		return nil, e
	}
	if e = lockRegistry(ctx, tx, id.TenantID); e != nil {
		tx.Rollback(ctx)
		return nil, e
	}
	return tx, nil
}

func (r *Registry) assignmentEvent(ctx context.Context, tx pgx.Tx, id accessport.Identity, c responsibility.Change) error {
	version, e := r.Assets.Bump(ctx, tx, id.TenantID, c.Asset)
	if e != nil {
		return e
	}
	subject := c.Subject
	if subject == "" {
		// роль снята: событие C03 требует субъекта — указываем действующего ответственного актива
		if subject, e = r.Owners.Accountable(ctx, tx, id.TenantID, c.Asset); e != nil {
			return e
		}
	}
	return r.assetEvent(ctx, tx, id.TenantID, c.Asset, version, "responsibility.assigned.v1", "Responsibility", c.Reason, id.UserID, identifier.New(), subject)
}

func (r *Registry) Subjects(ctx context.Context, id accessport.Identity, kind, cursor string, inactive bool, limit int) (SubjectPage, error) {
	out := SubjectPage{Tenant: id.TenantID, Items: []responsibility.SubjectInfo{}}
	tx, e := r.readTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	items, e := r.Owners.Subjects(ctx, tx, id.TenantID, kind, cursor, inactive, limit+1)
	if e != nil {
		return out, e
	}
	if len(items) > limit {
		items = items[:limit]
		next := items[limit-1].ID
		out.NextCursor = &next
	}
	out.Items = items
	return out, tx.Commit(ctx)
}

func (r *Registry) CreateSubject(ctx context.Context, id accessport.Identity, in responsibility.SubjectInput) (SubjectResult, error) {
	tx, e := r.adminTx(ctx, id, "sources:admin")
	if e != nil {
		return SubjectResult{}, e
	}
	defer tx.Rollback(ctx)
	s, e := r.Owners.CreateSubject(ctx, tx, id.TenantID, in)
	if e != nil {
		return SubjectResult{}, e
	}
	if e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "responsibility.subject_created", "subject", s.ID); e != nil {
		return SubjectResult{}, e
	}
	return SubjectResult{Subject: s}, tx.Commit(ctx)
}

func (r *Registry) PatchSubject(ctx context.Context, id accessport.Identity, subject string, p SubjectPatch) (SubjectResult, error) {
	if p.Revision == "" {
		return SubjectResult{}, domain.Invalid
	}
	tx, e := r.adminTx(ctx, id, "sources:admin")
	if e != nil {
		return SubjectResult{}, e
	}
	defer tx.Rollback(ctx)
	out := SubjectResult{}
	if p.Deactivate {
		if p.Name != nil || p.Contact != nil || p.Username != nil {
			return out, domain.Invalid
		}
		changes, e := r.Owners.Deactivate(ctx, tx, id.TenantID, subject, p.Revision, id.UserID)
		if e != nil {
			return out, e
		}
		for _, c := range changes {
			if e = r.assignmentEvent(ctx, tx, id, c); e != nil {
				return out, e
			}
		}
		out.Reassign = len(changes)
		if e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "responsibility.subject_deactivated", "subject", subject); e != nil {
			return out, e
		}
	} else {
		if _, e = r.Owners.UpdateSubject(ctx, tx, id.TenantID, subject, p.Revision, p.SubjectInput); e != nil {
			return out, e
		}
		if e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "responsibility.subject_updated", "subject", subject); e != nil {
			return out, e
		}
	}
	if out.Subject, e = r.Owners.SubjectByID(ctx, tx, id.TenantID, subject); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}

func (r *Registry) ChangeMember(ctx context.Context, id accessport.Identity, team, person string, add bool) (responsibility.SubjectInfo, error) {
	if !identifier.Valid(team) || !identifier.Valid(person) {
		return responsibility.SubjectInfo{}, domain.NotFound
	}
	tx, e := r.adminTx(ctx, id, "sources:admin")
	if e != nil {
		return responsibility.SubjectInfo{}, e
	}
	defer tx.Rollback(ctx)
	action := "responsibility.member_added"
	if add {
		e = r.Owners.AddMember(ctx, tx, id.TenantID, team, person, id.UserID)
	} else {
		action = "responsibility.member_removed"
		e = r.Owners.RemoveMember(ctx, tx, id.TenantID, team, person)
	}
	if e != nil {
		return responsibility.SubjectInfo{}, e
	}
	if e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, action, "subject", team); e != nil {
		return responsibility.SubjectInfo{}, e
	}
	s, e := r.Owners.SubjectByID(ctx, tx, id.TenantID, team)
	if e != nil {
		return s, e
	}
	return s, tx.Commit(ctx)
}

func (r *Registry) AssetAssignments(ctx context.Context, id accessport.Identity, uid string) (AssetAssignments, error) {
	out := AssetAssignments{Tenant: id.TenantID, Asset: uid}
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
	if e = tx.QueryRow(ctx, "SELECT aggregate_version::text FROM assets.assets WHERE tenant_id=$1 AND asset_uid=$2", id.TenantID, uid).Scan(&out.Version); e != nil {
		return out, e
	}
	if out.Active, e = r.Owners.Assignments(ctx, tx, id.TenantID, uid, false); e != nil {
		return out, e
	}
	if out.History, e = r.Owners.Assignments(ctx, tx, id.TenantID, uid, true); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}

// assignLocked — одно назначение в уже открытой транзакции: актив тенанта, не слитый, версия совпадает.
func (r *Registry) assignLocked(ctx context.Context, tx pgx.Tx, id accessport.Identity, asset, expected, role, subject string, note *string) (bool, error) {
	row, e := r.Assets.Lock(ctx, tx, id.TenantID, asset)
	if e != nil {
		return false, e
	}
	if row.MergedInto != nil {
		return false, domain.Conflict
	}
	if expected != row.Version {
		return false, domain.Revision
	}
	changed, e := r.Owners.Transfer(ctx, tx, id.TenantID, asset, role, subject, "MANUAL_ASSIGNMENT", note, id.UserID)
	if e != nil || !changed {
		return changed, e
	}
	return true, r.assignmentEvent(ctx, tx, id, responsibility.Change{Asset: asset, Role: role, Subject: subject, Reason: "MANUAL_ASSIGNMENT"})
}

func (r *Registry) Assign(ctx context.Context, id accessport.Identity, uid string, req AssignRequest) (AssetAssignments, error) {
	if !identifier.Valid(uid) {
		return AssetAssignments{}, domain.NotFound
	}
	if req.ExpectedVersion == "" || !responsibility.Roles[req.Role] || req.Subject != nil && !identifier.Valid(*req.Subject) {
		return AssetAssignments{}, domain.Invalid
	}
	subject := ""
	if req.Subject != nil {
		subject = *req.Subject
	}
	tx, e := r.adminTx(ctx, id, "assets:write")
	if e != nil {
		return AssetAssignments{}, e
	}
	defer tx.Rollback(ctx)
	if _, e = r.assignLocked(ctx, tx, id, uid, req.ExpectedVersion, req.Role, subject, req.Note); e != nil {
		return AssetAssignments{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return AssetAssignments{}, e
	}
	return r.AssetAssignments(ctx, id, uid)
}

// BulkAssign — до 200 активов, всё или ничего: устаревшая версия любого актива отменяет операцию целиком.
func (r *Registry) BulkAssign(ctx context.Context, id accessport.Identity, req BulkAssignRequest) (BulkAssignResult, error) {
	out := BulkAssignResult{Stale: []string{}}
	if len(req.Items) == 0 || len(req.Items) > 200 || !responsibility.Roles[req.Role] || !identifier.Valid(req.Subject) {
		return out, domain.Invalid
	}
	seen := map[string]bool{}
	for _, it := range req.Items {
		if !identifier.Valid(it.Asset) || it.ExpectedVersion == "" || seen[it.Asset] {
			return out, domain.Invalid
		}
		seen[it.Asset] = true
	}
	tx, e := r.adminTx(ctx, id, "assets:write")
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	for _, it := range req.Items {
		changed, e := r.assignLocked(ctx, tx, id, it.Asset, it.ExpectedVersion, req.Role, req.Subject, req.Note)
		switch {
		case errors.Is(e, domain.Revision):
			out.Stale = append(out.Stale, it.Asset)
		case e != nil:
			return out, e
		case changed:
			out.Applied++
		default:
			out.Unchanged++
		}
	}
	if len(out.Stale) > 0 {
		return out, ErrStale{Assets: out.Stale}
	}
	return out, tx.Commit(ctx)
}

func (r *Registry) Worklist(ctx context.Context, id accessport.Identity, scope, cursor string, limit int) (WorklistPage, error) {
	out := WorklistPage{Tenant: id.TenantID, Scope: scope, Items: []WorklistItem{}}
	tx, e := r.readTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	ids, e := r.Owners.Worklist(ctx, tx, id.TenantID, id.UserID, scope, cursor, limit+1)
	if e != nil {
		return out, e
	}
	if len(ids) > limit {
		ids = ids[:limit]
		next := ids[limit-1]
		out.NextCursor = &next
	}
	list, versions, e := r.readAssets(ctx, tx, id.TenantID, ids)
	if e != nil {
		return out, e
	}
	assignments, e := r.Owners.AssignmentsMany(ctx, tx, id.TenantID, ids)
	if e != nil {
		return out, e
	}
	for _, a := range list {
		item := WorklistItem{Asset: a.UID, DisplayName: a.Business.DisplayName, Hostname: a.Hostname, Version: versions[a.UID], Assignments: assignments[a.UID]}
		if item.Assignments == nil {
			item.Assignments = []responsibility.Assignment{}
		}
		out.Items = append(out.Items, item)
	}
	return out, tx.Commit(ctx)
}

func (r *Registry) ownershipHandlers() map[string]struct {
	permission string
	handler    http.Handler
} {
	type route = struct {
		permission string
		handler    http.Handler
	}
	h := map[string]route{}
	h["GET /api/v1/subjects"] = route{"assets:read", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		q, ok := queryOnly(w, req, "kind", "cursor", "limit", "include_inactive")
		if !ok {
			return
		}
		limit, ok := pageLimit(w, q, 100, 200)
		if !ok {
			return
		}
		kind, cursor := q.Get("kind"), q.Get("cursor")
		if kind != "" && kind != "person" && kind != "team" || cursor != "" && !identifier.Valid(cursor) || q.Has("include_inactive") && q.Get("include_inactive") != "true" && q.Get("include_inactive") != "false" {
			access.APIError(w, 400, "INVALID_QUERY")
			return
		}
		ctx, cancel, id := cmdbContext(req)
		defer cancel()
		out, e := r.Subjects(ctx, id, kind, cursor, q.Get("include_inactive") == "true", limit)
		if e != nil {
			cmdbError(w, req, e)
			return
		}
		registryJSON(w, out)
	})}
	h["POST /api/v1/subjects"] = route{"sources:admin", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body responsibility.SubjectInput
		if !readOperationBody(w, req, &body) {
			return
		}
		ctx, cancel, id := cmdbContext(req)
		defer cancel()
		out, e := r.CreateSubject(ctx, id, body)
		if e != nil {
			cmdbError(w, req, e)
			return
		}
		registryJSONStatus(w, http.StatusCreated, out)
	})}
	h["PATCH /api/v1/subjects/{subject_id}"] = route{"sources:admin", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body SubjectPatch
		if !readOperationBody(w, req, &body) {
			return
		}
		ctx, cancel, id := cmdbContext(req)
		defer cancel()
		out, e := r.PatchSubject(ctx, id, req.PathValue("subject_id"), body)
		if e != nil {
			cmdbError(w, req, e)
			return
		}
		registryJSON(w, out)
	})}
	member := func(add bool) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if _, ok := queryOnly(w, req); !ok {
				return
			}
			ctx, cancel, id := cmdbContext(req)
			defer cancel()
			out, e := r.ChangeMember(ctx, id, req.PathValue("subject_id"), req.PathValue("person_id"), add)
			if e != nil {
				cmdbError(w, req, e)
				return
			}
			registryJSON(w, out)
		})
	}
	h["PUT /api/v1/subjects/{subject_id}/members/{person_id}"] = route{"sources:admin", member(true)}
	h["DELETE /api/v1/subjects/{subject_id}/members/{person_id}"] = route{"sources:admin", member(false)}
	h["GET /api/v1/assets/{asset_uid}/assignments"] = route{"assets:read", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if _, ok := queryOnly(w, req); !ok {
			return
		}
		ctx, cancel, id := cmdbContext(req)
		defer cancel()
		out, e := r.AssetAssignments(ctx, id, req.PathValue("asset_uid"))
		if e != nil {
			cmdbError(w, req, e)
			return
		}
		registryJSON(w, out)
	})}
	h["POST /api/v1/assets/{asset_uid}/assignments"] = route{"assets:write", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body AssignRequest
		if !readOperationBody(w, req, &body) {
			return
		}
		ctx, cancel, id := cmdbContext(req)
		defer cancel()
		out, e := r.Assign(ctx, id, req.PathValue("asset_uid"), body)
		if e != nil {
			cmdbError(w, req, e)
			return
		}
		registryJSON(w, out)
	})}
	h["POST /api/v1/assignments/bulk"] = route{"assets:write", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body BulkAssignRequest
		if !readOperationBody(w, req, &body) {
			return
		}
		ctx, cancel, id := cmdbContext(req)
		defer cancel()
		out, e := r.BulkAssign(ctx, id, body)
		var stale ErrStale
		if errors.As(e, &stale) {
			registryJSONStatus(w, http.StatusPreconditionFailed, out)
			return
		}
		if e != nil {
			cmdbError(w, req, e)
			return
		}
		registryJSON(w, out)
	})}
	h["GET /api/v1/worklist"] = route{"assets:read", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		q, ok := queryOnly(w, req, "scope", "cursor", "limit")
		if !ok {
			return
		}
		limit, ok := pageLimit(w, q, 50, 100)
		if !ok {
			return
		}
		scope, cursor := q.Get("scope"), q.Get("cursor")
		if scope != "mine" && scope != "team" && scope != "unassigned" && scope != "attention" || cursor != "" && !identifier.Valid(cursor) {
			access.APIError(w, 400, "INVALID_QUERY")
			return
		}
		ctx, cancel, id := cmdbContext(req)
		defer cancel()
		out, e := r.Worklist(ctx, id, scope, cursor, limit)
		if e != nil {
			cmdbError(w, req, e)
			return
		}
		registryJSON(w, out)
	})}
	return h
}
