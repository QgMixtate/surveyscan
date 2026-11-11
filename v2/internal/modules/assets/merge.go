package assets

import (
	"context"
	"errors"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
)

// C25.03 — слияние и разделение активов. UID не переиспользуется: поглощённый актив остаётся с merged_into,
// разделение всегда переносит записи в новый (новый UID) или в другой существующий актив.

// ErrMerged — актив поглощён другим; Into — канонический UID (с учётом цепочки слияний).
type ErrMerged struct{ Into string }

func (e ErrMerged) Error() string { return "asset merged into " + e.Into }

// AssetRow — состояние актива под блокировкой операции.
type AssetRow struct {
	UID, Site, Scope, Version string
	MergedInto                *string
}

// Lock блокирует актив тенанта для операции слияния/разделения; актив чужого тенанта не находится (NotFound).
func (Store) Lock(ctx context.Context, tx pgx.Tx, tenant, uid string) (AssetRow, error) {
	a := AssetRow{UID: uid}
	e := tx.QueryRow(ctx, "SELECT site_id::text,scope_id::text,aggregate_version::text,merged_into::text FROM assets.assets WHERE tenant_id=$1 AND asset_uid=$2 FOR UPDATE", tenant, uid).Scan(&a.Site, &a.Scope, &a.Version, &a.MergedInto)
	if errors.Is(e, pgx.ErrNoRows) {
		e = domain.NotFound
	}
	return a, e
}

// Canonical возвращает UID, в который (возможно, цепочкой) слит актив; для неслитого — сам UID.
func (Store) Canonical(ctx context.Context, tx pgx.Tx, tenant, uid string) (string, error) {
	current := uid
	for range 32 {
		var next *string
		e := tx.QueryRow(ctx, "SELECT merged_into::text FROM assets.assets WHERE tenant_id=$1 AND asset_uid=$2", tenant, current).Scan(&next)
		if errors.Is(e, pgx.ErrNoRows) {
			return "", domain.NotFound
		}
		if e != nil {
			return "", e
		}
		if next == nil {
			return current, nil
		}
		current = *next
	}
	return "", domain.Conflict
}

// RecordKeys — записи источников, сопоставленные с активом.
func (Store) RecordKeys(ctx context.Context, tx pgx.Tx, tenant, asset string) ([]string, error) {
	rows, e := tx.Query(ctx, "SELECT source_record_key::text FROM assets.source_records WHERE tenant_id=$1 AND asset_uid=$2 ORDER BY source_record_key FOR UPDATE", tenant, asset)
	if e != nil {
		return nil, e
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// MoveRecords переносит записи источников с актива from на to: сопоставление записи, её идентификаторы (старые
// закрываются valid_to, на новом активе открываются копии) и активные связи её наблюдений (старая связь закрывается,
// новая — следующая assignment_revision с причиной reason). Возвращает число перенесённых связей.
func (Store) MoveRecords(ctx context.Context, tx pgx.Tx, tenant, from, to string, records []string, reason string) (int64, error) {
	tag, e := tx.Exec(ctx, "UPDATE assets.source_records SET asset_uid=$3,resolution_state='resolved',revision=revision+1 WHERE tenant_id=$1 AND asset_uid=$2 AND source_record_key=ANY($4::uuid[])", tenant, from, to, records)
	if e != nil {
		return 0, e
	}
	if tag.RowsAffected() != int64(len(records)) {
		return 0, domain.Invalid // запись не принадлежит активу from
	}
	if _, e = tx.Exec(ctx, `INSERT INTO assets.asset_identifiers(tenant_id,identifier_id,asset_uid,kind,namespace,normalized_value,strength,source_record_key)
SELECT tenant_id,gen_random_uuid(),$3,kind,namespace,normalized_value,strength,source_record_key FROM assets.asset_identifiers
WHERE tenant_id=$1 AND asset_uid=$2 AND valid_to IS NULL AND source_record_key=ANY($4::uuid[])`, tenant, from, to, records); e != nil {
		return 0, e
	}
	if _, e = tx.Exec(ctx, "UPDATE assets.asset_identifiers SET valid_to=now() WHERE tenant_id=$1 AND asset_uid=$2 AND valid_to IS NULL AND source_record_key=ANY($3::uuid[])", tenant, from, records); e != nil {
		return 0, e
	}
	// наблюдения записей: закрываем активные связи с from и открываем связи с to (две команды — уникальный
	// индекс «одна активная связь» проверяется построчно)
	rows, e := tx.Query(ctx, `UPDATE assets.observation_links l SET valid_to=now() FROM inventory.observations o
WHERE l.tenant_id=$1 AND l.asset_uid=$2 AND l.valid_to IS NULL AND o.tenant_id=l.tenant_id AND o.observation_id=l.observation_id AND o.source_record_key=ANY($3::uuid[])
RETURNING l.observation_id::text,l.assignment_revision::text`, tenant, from, records)
	if e != nil {
		return 0, e
	}
	var observations, revisions []string
	for rows.Next() {
		var o, r string
		if e = rows.Scan(&o, &r); e != nil {
			rows.Close()
			return 0, e
		}
		observations, revisions = append(observations, o), append(revisions, r)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return 0, e
	}
	tag, e = tx.Exec(ctx, "INSERT INTO assets.observation_links(tenant_id,link_id,observation_id,asset_uid,assignment_revision,reason_code) SELECT $1,gen_random_uuid(),o,$2,r::numeric+1,$3 FROM unnest($4::uuid[],$5::text[]) AS u(o,r)", tenant, to, reason, observations, revisions)
	if e != nil {
		return 0, e
	}
	return tag.RowsAffected(), nil
}

// RetargetConflicts заменяет поглощённый актив целевым в кандидатах открытых конфликтов.
func (Store) RetargetConflicts(ctx context.Context, tx pgx.Tx, tenant, from, to string) error {
	_, e := tx.Exec(ctx, `UPDATE assets.reconciliation_conflicts SET candidate_asset_uids=ARRAY(SELECT DISTINCT x FROM unnest(array_replace(candidate_asset_uids,$2::uuid,$3::uuid)) x ORDER BY x),revision=revision+1
WHERE tenant_id=$1 AND state='open' AND $2::uuid=ANY(candidate_asset_uids)`, tenant, from, to)
	return e
}

// SettleRecords (C25.03, стенд R-027) — после слияния: открытые конфликты записей актива, у которых кроме него не
// осталось кандидатов, закрываются (решение оператора «это один актив»), и возвращаются записи актива без открытых
// конфликтов — их ожидающие наблюдения привязываются к активу вызывающей стороной.
func (Store) SettleRecords(ctx context.Context, tx pgx.Tx, tenant, asset string) ([]string, error) {
	if _, e := tx.Exec(ctx, `UPDATE assets.reconciliation_conflicts c SET state='resolved',revision=c.revision+1 FROM assets.source_records r
WHERE c.tenant_id=$1 AND c.state='open' AND r.tenant_id=c.tenant_id AND r.source_record_key=c.source_record_key AND r.asset_uid=$2
AND c.candidate_asset_uids <@ ARRAY[$2::uuid]`, tenant, asset); e != nil {
		return nil, e
	}
	rows, e := tx.Query(ctx, `SELECT r.source_record_key::text FROM assets.source_records r WHERE r.tenant_id=$1 AND r.asset_uid=$2
AND NOT EXISTS(SELECT 1 FROM assets.reconciliation_conflicts c WHERE c.tenant_id=r.tenant_id AND c.source_record_key=r.source_record_key AND c.state='open')
ORDER BY 1`, tenant, asset)
	if e != nil {
		return nil, e
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// MergeBusiness переносит ручные поля: у целевого актива свои значения сохраняются, пустые заполняются из
// поглощённого, теги объединяются (не более 32), критичность — более высокая из двух.
func (Store) MergeBusiness(ctx context.Context, tx pgx.Tx, tenant, from, to string) error {
	_, e := tx.Exec(ctx, `UPDATE assets.asset_business_fields t SET display_name=COALESCE(t.display_name,f.display_name),purpose=COALESCE(t.purpose,f.purpose),
criticality=CASE WHEN array_position(ARRAY['unknown','low','medium','high','critical'],f.criticality)>array_position(ARRAY['unknown','low','medium','high','critical'],t.criticality) THEN f.criticality ELSE t.criticality END,
tags=(SELECT COALESCE(array_agg(x ORDER BY o),'{}') FROM (SELECT x,min(o) o FROM unnest(t.tags||f.tags) WITH ORDINALITY u(x,o) GROUP BY x ORDER BY min(o) LIMIT 32) s),revision=t.revision+1
FROM assets.asset_business_fields f WHERE t.tenant_id=$1 AND t.asset_uid=$3 AND f.tenant_id=$1 AND f.asset_uid=$2`, tenant, from, to)
	return e
}

// MarkMerged помечает поглощённый актив (необратимо: триггер asset_merge_final).
func (Store) MarkMerged(ctx context.Context, tx pgx.Tx, tenant, from, to string) (string, error) {
	var v string
	e := tx.QueryRow(ctx, "UPDATE assets.assets SET merged_into=$3,merged_at=now(),lifecycle_state='merged',aggregate_version=aggregate_version+1 WHERE tenant_id=$1 AND asset_uid=$2 AND merged_into IS NULL RETURNING aggregate_version::text", tenant, from, to).Scan(&v)
	if errors.Is(e, pgx.ErrNoRows) {
		e = domain.Conflict
	}
	return v, e
}

// Operation записывает операцию слияния/разделения (provenance перепривязки).
func (Store) Operation(ctx context.Context, tx pgx.Tx, tenant, kind, from, to string, records []string, actor string) (string, error) {
	id := identifier.New()
	_, e := tx.Exec(ctx, "INSERT INTO assets.asset_operations(tenant_id,operation_id,kind,from_asset_uid,to_asset_uid,source_record_keys,actor_ref) VALUES($1,$2,$3,$4,$5,$6::uuid[],$7)", tenant, id, kind, from, to, records, actor)
	return id, e
}

// SourceRecord — запись источника, сопоставленная с активом (для разделения и перепривязки, C25.03).
type SourceRecord struct {
	Key          string `json:"source_record_key"`
	SourceID     string `json:"source_id"`
	Namespace    string `json:"namespace"`
	LocalID      string `json:"source_local_id"`
	Observations int    `json:"observations"`
}

func (Store) SourceRecords(ctx context.Context, tx pgx.Tx, tenant, asset string) ([]SourceRecord, error) {
	rows, e := tx.Query(ctx, `SELECT r.source_record_key::text,r.source_id::text,r.namespace,r.source_local_id,
(SELECT count(*) FROM assets.observation_links l JOIN inventory.observations o ON o.tenant_id=l.tenant_id AND o.observation_id=l.observation_id WHERE l.tenant_id=r.tenant_id AND l.asset_uid=r.asset_uid AND l.valid_to IS NULL AND o.source_record_key=r.source_record_key)
FROM assets.source_records r WHERE r.tenant_id=$1 AND r.asset_uid=$2 ORDER BY r.source_id,r.namespace,r.source_local_id LIMIT 1000`, tenant, asset)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []SourceRecord{}
	for rows.Next() {
		var r SourceRecord
		if e = rows.Scan(&r.Key, &r.SourceID, &r.Namespace, &r.LocalID, &r.Observations); e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ManualClass — ручной класс актива и ревизия бизнес-полей (C26.02).
func (Store) ManualClass(ctx context.Context, tx pgx.Tx, tenant, asset string) (*string, string, error) {
	var class *string
	var revision string
	e := tx.QueryRow(ctx, "SELECT asset_class,revision::text FROM assets.asset_business_fields WHERE tenant_id=$1 AND asset_uid=$2", tenant, asset).Scan(&class, &revision)
	if errors.Is(e, pgx.ErrNoRows) {
		e = domain.NotFound
	}
	return class, revision, e
}

// SetClass задаёт или снимает (nil) ручной класс при совпадении ревизии бизнес-полей; сбор это поле не меняет (AM-04).
func (Store) SetClass(ctx context.Context, tx pgx.Tx, tenant, asset, revision string, class *string) error {
	tag, e := tx.Exec(ctx, "UPDATE assets.asset_business_fields SET asset_class=$4,revision=revision+1 WHERE tenant_id=$1 AND asset_uid=$2 AND revision::text=$3", tenant, asset, revision, class)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return domain.Revision
	}
	return nil
}
