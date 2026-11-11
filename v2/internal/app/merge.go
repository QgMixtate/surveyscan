package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	accessport "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/assets"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
)

// C25.03 — слияние (две карточки одного устройства) и разделение (ошибочное слияние или ошибочная привязка записи).
// Всё в одной транзакции под блокировкой реестра тенанта: перенос записей, идентификаторов и связей наблюдений,
// пересборка проекций из неизменных наблюдений, история, outbox и аудит на каждом затронутом активе.
// Поглощённый UID не удаляется и не переиспользуется: он разрешается в канонический (308 на карточке).

type MergeRequest struct {
	Target          string `json:"target_asset_uid"`
	Absorbed        string `json:"absorbed_asset_uid"`
	TargetVersion   string `json:"target_version,omitempty"`
	AbsorbedVersion string `json:"absorbed_version,omitempty"`
}

type SplitRequest struct {
	Records []string `json:"source_record_keys"`
	Target  string   `json:"target_asset_uid,omitempty"` // пусто — новый актив (новый UID)
	Version string   `json:"version,omitempty"`
}

type AssetOperationResult struct {
	OperationID string `json:"operation_id"`
	Kind        string `json:"kind"`
	FromAsset   string `json:"from_asset_uid"`
	ToAsset     string `json:"to_asset_uid"`
	Created     bool   `json:"created"`
	Records     int    `json:"moved_records"`
	Relinked    int64  `json:"relinked_observations"`
	Rebuilt     int    `json:"rebuilt_observations"`
}

func (r *Registry) assetOperationTx(ctx context.Context, id accessport.Identity) (pgx.Tx, error) {
	tx, e := r.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if e != nil {
		return nil, e
	}
	if _, e = r.Auth.Authorize(ctx, tx, id.CredentialID, id.TenantID, "assets:write"); e != nil {
		tx.Rollback(ctx)
		return nil, e
	}
	if e = lockRegistry(ctx, tx, id.TenantID); e != nil {
		tx.Rollback(ctx)
		return nil, e
	}
	return tx, nil
}

// lockPair блокирует два актива в порядке UID (без взаимоблокировок между встречными операциями).
func (r *Registry) lockPair(ctx context.Context, tx pgx.Tx, tenant, a, b string) (assets.AssetRow, assets.AssetRow, error) {
	first, second := a, b
	if second < first {
		first, second = second, first
	}
	x, e := r.Assets.Lock(ctx, tx, tenant, first)
	if e != nil {
		return x, x, e
	}
	y, e := r.Assets.Lock(ctx, tx, tenant, second)
	if e != nil {
		return x, y, e
	}
	if first != a {
		x, y = y, x
	}
	return x, y, nil
}

func (r *Registry) MergeAssets(ctx context.Context, id accessport.Identity, req MergeRequest) (AssetOperationResult, error) {
	out := AssetOperationResult{Kind: "merge", FromAsset: req.Absorbed, ToAsset: req.Target}
	if !identifier.Valid(req.Target) || !identifier.Valid(req.Absorbed) || req.Target == req.Absorbed {
		return out, domain.Invalid
	}
	tx, e := r.assetOperationTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	tenant, actor := id.TenantID, id.UserID
	target, absorbed, e := r.lockPair(ctx, tx, tenant, req.Target, req.Absorbed)
	if e != nil {
		return out, e
	}
	if target.MergedInto != nil || absorbed.MergedInto != nil {
		return out, domain.Conflict // слитый актив не участвует в операциях: работать с каноническим
	}
	if req.TargetVersion != "" && req.TargetVersion != target.Version || req.AbsorbedVersion != "" && req.AbsorbedVersion != absorbed.Version {
		return out, domain.Revision
	}
	if target.Scope != absorbed.Scope || target.Site != absorbed.Site {
		return out, domain.Conflict // слияние через границу площадки/network scope запрещено
	}
	records, e := r.Assets.RecordKeys(ctx, tx, tenant, absorbed.UID)
	if e != nil {
		return out, e
	}
	if len(records) > 0 {
		if out.Relinked, e = r.Assets.MoveRecords(ctx, tx, tenant, absorbed.UID, target.UID, records, "ASSET_MERGE"); e != nil {
			return out, e
		}
	}
	if e = r.Assets.RetargetConflicts(ctx, tx, tenant, absorbed.UID, target.UID); e != nil {
		return out, e
	}
	if _, e = r.CMDB.RetargetAsset(ctx, tx, tenant, absorbed.UID, target.UID, actor); e != nil {
		return out, e
	}
	// конфликты, возникшие, пока активы были раздельными, закрываются, ожидавшие наблюдения привязываются к целевому
	// активу (проекция пересобирается ниже по всем активным связям)
	settled, e := r.Assets.SettleRecords(ctx, tx, tenant, target.UID)
	if e != nil {
		return out, e
	}
	for _, record := range settled {
		pending, e := r.Inventory.PendingObservations(ctx, tx, tenant, record, 10000)
		if e != nil {
			return out, e
		}
		for _, p := range pending {
			if _, e = r.Assets.LinkReason(ctx, tx, p.Observation, target.UID, "ASSET_MERGE"); e != nil {
				return out, e
			}
			out.Relinked++
		}
	}
	if e = r.Assets.MergeBusiness(ctx, tx, tenant, absorbed.UID, target.UID); e != nil {
		return out, e
	}
	if out.OperationID, e = r.Assets.Operation(ctx, tx, tenant, "merge", absorbed.UID, target.UID, records, actor); e != nil {
		return out, e
	}
	if e = r.Inventory.Clear(ctx, tx, tenant, absorbed.UID); e != nil {
		return out, e
	}
	version, e := r.Assets.MarkMerged(ctx, tx, tenant, absorbed.UID, target.UID)
	if e != nil {
		return out, e
	}
	if e = r.assetEvent(ctx, tx, tenant, absorbed.UID, version, "asset.facts_changed.v1", "Assets", "MERGED_INTO_ASSET", actor, out.OperationID); e != nil {
		return out, e
	}
	if out.Rebuilt, e = r.Inventory.Rebuild(ctx, tx, tenant, target.UID); e != nil {
		return out, e
	}
	subject, e := r.Owners.MergeFrom(ctx, tx, tenant, absorbed.UID, target.UID, actor)
	if e != nil {
		return out, e
	}
	if subject != "" {
		if version, e = r.Assets.Bump(ctx, tx, tenant, target.UID); e != nil {
			return out, e
		}
		if e = r.assetEvent(ctx, tx, tenant, target.UID, version, "responsibility.assigned.v1", "Responsibility", "ASSET_MERGE", actor, out.OperationID, subject); e != nil {
			return out, e
		}
	}
	if version, e = r.Assets.Bump(ctx, tx, tenant, target.UID); e != nil {
		return out, e
	}
	if e = r.assetEvent(ctx, tx, tenant, target.UID, version, "asset.facts_changed.v1", "Assets", "ASSET_MERGE", actor, out.OperationID); e != nil {
		return out, e
	}
	out.Records = len(records)
	return out, tx.Commit(ctx)
}

func (r *Registry) SplitAsset(ctx context.Context, id accessport.Identity, uid string, req SplitRequest) (AssetOperationResult, error) {
	out := AssetOperationResult{Kind: "split", FromAsset: uid}
	if !identifier.Valid(uid) || len(req.Records) == 0 || len(req.Records) > 1000 || req.Target == uid || req.Target != "" && !identifier.Valid(req.Target) {
		return out, domain.Invalid
	}
	records := slices.Clone(req.Records)
	slices.Sort(records)
	if len(slices.Compact(records)) != len(req.Records) {
		return out, domain.Invalid
	}
	for _, k := range records {
		if !identifier.Valid(k) {
			return out, domain.Invalid
		}
	}
	tx, e := r.assetOperationTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	tenant, actor := id.TenantID, id.UserID
	var from, to assets.AssetRow
	if req.Target != "" {
		from, to, e = r.lockPair(ctx, tx, tenant, uid, req.Target)
	} else {
		from, e = r.Assets.Lock(ctx, tx, tenant, uid)
	}
	if e != nil {
		return out, e
	}
	if from.MergedInto != nil || to.MergedInto != nil {
		return out, domain.Conflict
	}
	if req.Version != "" && req.Version != from.Version {
		return out, domain.Revision
	}
	if req.Target != "" && (to.Scope != from.Scope || to.Site != from.Site) {
		return out, domain.Conflict
	}
	all, e := r.Assets.RecordKeys(ctx, tx, tenant, uid)
	if e != nil {
		return out, e
	}
	for _, k := range records {
		if !slices.Contains(all, k) {
			return out, domain.Invalid // запись не сопоставлена с этим активом
		}
	}
	if len(records) == len(all) && req.Target == "" {
		return out, domain.Invalid // выделять все записи в новый актив бессмысленно: UID остался бы пустым
	}
	target := req.Target
	if target == "" {
		if target, e = r.Assets.CreateAsset(ctx, tx, tenant, from.Site, from.Scope); e != nil {
			return out, e
		}
		out.Created = true
	}
	if out.Relinked, e = r.Assets.MoveRecords(ctx, tx, tenant, uid, target, records, "ASSET_SPLIT"); e != nil {
		return out, e
	}
	if out.OperationID, e = r.Assets.Operation(ctx, tx, tenant, "split", uid, target, records, actor); e != nil {
		return out, e
	}
	if out.Created {
		subject, e := r.Owners.Assign(ctx, tx, tenant, target, from.Site)
		if e != nil {
			return out, e
		}
		if e = r.assetEvent(ctx, tx, tenant, target, "1", "asset.created.v1", "Assets", "ASSET_SPLIT", actor, out.OperationID); e != nil {
			return out, e
		}
		version, e := r.Assets.Bump(ctx, tx, tenant, target)
		if e != nil {
			return out, e
		}
		if e = r.assetEvent(ctx, tx, tenant, target, version, "responsibility.assigned.v1", "Responsibility", "SITE_FALLBACK", actor, out.OperationID, subject); e != nil {
			return out, e
		}
	}
	rebuilt, e := r.Inventory.Rebuild(ctx, tx, tenant, uid)
	if e != nil {
		return out, e
	}
	moved, e := r.Inventory.Rebuild(ctx, tx, tenant, target)
	if e != nil {
		return out, e
	}
	out.Rebuilt = rebuilt + moved
	for _, asset := range []string{uid, target} {
		version, e := r.Assets.Bump(ctx, tx, tenant, asset)
		if e != nil {
			return out, e
		}
		if e = r.assetEvent(ctx, tx, tenant, asset, version, "asset.facts_changed.v1", "Assets", "ASSET_SPLIT", actor, out.OperationID); e != nil {
			return out, e
		}
	}
	out.ToAsset, out.Records = target, len(records)
	return out, tx.Commit(ctx)
}

func readOperationBody(w http.ResponseWriter, req *http.Request, into any) bool {
	if req.URL.RawQuery != "" {
		access.APIError(w, 400, "INVALID_QUERY")
		return false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, req.Body, 128<<10))
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err != nil || dec.Decode(into) != nil {
		access.APIError(w, 400, "INVALID_BODY")
		return false
	}
	return true
}

func operationError(w http.ResponseWriter, e error) {
	if errors.Is(e, domain.Invalid) {
		access.APIError(w, 422, "INVALID_OPERATION")
		return
	}
	registryError(w, e)
}

// assetOperationTimeout — срок слияния/разделения: пересборка проекций на живых данных занимает десятки секунд
// (стенд R-027: ~600 наблюдений записи — 23–26 с), это больше общего WriteTimeout сервера (10/15 с).
const assetOperationTimeout = 120 * time.Second

// assetOperationContext продлевает срок записи ответа под операцию: иначе сервер обрывает соединение посреди ответа,
// хотя транзакция завершается (клиент видел ошибку TLS при успешной операции, стенд R-027).
func assetOperationContext(w http.ResponseWriter, req *http.Request) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(assetOperationTimeout)
	_ = http.NewResponseController(w).SetWriteDeadline(deadline.Add(10 * time.Second))
	return context.WithDeadline(context.WithoutCancel(req.Context()), deadline)
}

func (r *Registry) mergeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body MergeRequest
		if !readOperationBody(w, req, &body) {
			return
		}
		ctx, cancel := assetOperationContext(w, req)
		defer cancel()
		id, _ := access.Identity(req.Context())
		out, e := r.MergeAssets(ctx, id, body)
		if e != nil {
			operationError(w, e)
			return
		}
		registryJSON(w, out)
	})
}

func (r *Registry) splitHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body SplitRequest
		if !readOperationBody(w, req, &body) {
			return
		}
		ctx, cancel := assetOperationContext(w, req)
		defer cancel()
		id, _ := access.Identity(req.Context())
		out, e := r.SplitAsset(ctx, id, req.PathValue("asset_uid"), body)
		if e != nil {
			operationError(w, e)
			return
		}
		registryJSON(w, out)
	})
}

type SourceRecordPage struct {
	Tenant  string                `json:"tenant_id"`
	Asset   string                `json:"asset_uid"`
	Version string                `json:"version"`
	Items   []assets.SourceRecord `json:"items"`
}

func (r *Registry) AssetSourceRecords(ctx context.Context, id accessport.Identity, uid string) (SourceRecordPage, error) {
	out := SourceRecordPage{Tenant: id.TenantID, Asset: uid, Items: []assets.SourceRecord{}}
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
	if _, e = r.Assets.Get(ctx, tx, id.TenantID, uid); e != nil {
		return out, e
	}
	if e = tx.QueryRow(ctx, "SELECT aggregate_version::text FROM assets.assets WHERE tenant_id=$1 AND asset_uid=$2", id.TenantID, uid).Scan(&out.Version); e != nil {
		return out, e
	}
	if out.Items, e = r.Assets.SourceRecords(ctx, tx, id.TenantID, uid); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}

func (r *Registry) sourceRecordsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.RawQuery != "" {
			access.APIError(w, 400, "INVALID_QUERY")
			return
		}
		ctx, cancel := context.WithTimeout(req.Context(), 10*time.Second)
		defer cancel()
		id, _ := access.Identity(req.Context())
		out, e := r.AssetSourceRecords(ctx, id, req.PathValue("asset_uid"))
		if e != nil {
			if redirectMerged(w, req, e) {
				return
			}
			registryError(w, e)
			return
		}
		registryJSON(w, out)
	})
}
