package assets

import (
	"context"
	"errors"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
)

// C25.02 — очередь ручного разбора: записи источников, которые не сопоставились с активом автоматически.

// Conflict — конфликт сопоставления записи источника (для очереди разбора).
type Conflict struct {
	ID         string   `json:"conflict_id"`
	Reason     string   `json:"reason_code"`
	State      string   `json:"state"`
	Revision   string   `json:"revision"`
	RecordKey  string   `json:"source_record_key"`
	SourceID   string   `json:"source_id"`
	Namespace  string   `json:"namespace"`
	LocalID    string   `json:"source_local_id"`
	Resolution string   `json:"resolution_state"`
	AssetID    *string  `json:"asset_uid"`
	Candidates []string `json:"candidate_asset_uids"`
}

// Conflicts возвращает страницу конфликтов tenant в состоянии state (open|resolved|dismissed), по conflict_id —
// по одной строке на запись источника (старые базы могли накопить дубли до исправления R-027).
func (Store) Conflicts(ctx context.Context, tx pgx.Tx, tenant, state, after string, limit int) ([]Conflict, error) {
	if state != "open" && state != "resolved" && state != "dismissed" {
		return nil, domain.Invalid
	}
	if after == "" {
		after = "00000000-0000-0000-0000-000000000000"
	}
	if !identifier.Valid(after) && after != "00000000-0000-0000-0000-000000000000" {
		return nil, domain.Invalid
	}
	rows, e := tx.Query(ctx, `SELECT c.conflict_id::text,c.reason_code,c.state,c.revision::text,c.source_record_key::text,r.source_id::text,r.namespace,r.source_local_id,r.resolution_state,r.asset_uid::text,c.candidate_asset_uids::text[]
FROM (SELECT DISTINCT ON (source_record_key) * FROM assets.reconciliation_conflicts WHERE tenant_id=$1 AND state=$2 ORDER BY source_record_key, revision DESC, conflict_id) c
JOIN assets.source_records r USING(tenant_id,source_record_key)
WHERE c.conflict_id>$3::uuid ORDER BY c.conflict_id LIMIT $4`, tenant, state, after, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Conflict{}
	for rows.Next() {
		var c Conflict
		if e = rows.Scan(&c.ID, &c.Reason, &c.State, &c.Revision, &c.RecordKey, &c.SourceID, &c.Namespace, &c.LocalID, &c.Resolution, &c.AssetID, &c.Candidates); e != nil {
			return nil, e
		}
		if c.Candidates == nil {
			c.Candidates = []string{}
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ConflictFor блокирует открытый конфликт и возвращает его вместе с записью источника.
func (Store) ConflictFor(ctx context.Context, tx pgx.Tx, tenant, conflict string) (Conflict, error) {
	var c Conflict
	if !identifier.Valid(conflict) {
		return c, domain.NotFound
	}
	e := tx.QueryRow(ctx, `SELECT c.conflict_id::text,c.reason_code,c.state,c.revision::text,c.source_record_key::text,r.source_id::text,r.namespace,r.source_local_id,r.resolution_state,r.asset_uid::text,c.candidate_asset_uids::text[]
FROM assets.reconciliation_conflicts c JOIN assets.source_records r USING(tenant_id,source_record_key)
WHERE c.tenant_id=$1 AND c.conflict_id=$2 FOR UPDATE OF c, r`, tenant, conflict).Scan(&c.ID, &c.Reason, &c.State, &c.Revision, &c.RecordKey, &c.SourceID, &c.Namespace, &c.LocalID, &c.Resolution, &c.AssetID, &c.Candidates)
	if errors.Is(e, pgx.ErrNoRows) {
		return c, domain.NotFound
	}
	return c, e
}

// AssetScope — площадка и scope актива tenant (NotFound, если актива нет).
func (Store) AssetScope(ctx context.Context, tx pgx.Tx, tenant, asset string) (string, string, error) {
	var site, scope string
	if !identifier.Valid(asset) {
		return "", "", domain.NotFound
	}
	e := tx.QueryRow(ctx, "SELECT site_id::text,scope_id::text FROM assets.assets WHERE tenant_id=$1 AND asset_uid=$2 AND merged_into IS NULL", tenant, asset).Scan(&site, &scope)
	if errors.Is(e, pgx.ErrNoRows) {
		return "", "", domain.NotFound
	}
	return site, scope, e
}

// CreateAsset создаёт новый актив (без бизнес-значений) для записи, разобранной вручную.
func (Store) CreateAsset(ctx context.Context, tx pgx.Tx, tenant, site, scope string) (string, error) {
	asset := identifier.New()
	if _, e := tx.Exec(ctx, "INSERT INTO assets.assets(tenant_id,asset_uid,site_id,scope_id) VALUES($1,$2,$3,$4)", tenant, asset, site, scope); e != nil {
		return "", e
	}
	_, e := tx.Exec(ctx, "INSERT INTO assets.asset_business_fields(tenant_id,asset_uid) VALUES($1,$2)", tenant, asset)
	return asset, e
}

// AttachRecord привязывает запись источника к активу, закрывает её открытые конфликты и сохраняет идентификаторы
// последнего наблюдения записи (история идентификаторов — как при автоматическом сопоставлении).
func (Store) AttachRecord(ctx context.Context, tx pgx.Tx, tenant, record, asset string, candidates []contracts.Candidate) error {
	if _, e := tx.Exec(ctx, "UPDATE assets.source_records SET asset_uid=$3,resolution_state='resolved',revision=revision+1 WHERE tenant_id=$1 AND source_record_key=$2", tenant, record, asset); e != nil {
		return e
	}
	if _, e := tx.Exec(ctx, "UPDATE assets.reconciliation_conflicts SET state='resolved',revision=revision+1 WHERE tenant_id=$1 AND source_record_key=$2 AND state='open'", tenant, record); e != nil {
		return e
	}
	for _, candidate := range candidates {
		c, e := Normalize(candidate)
		if e != nil {
			continue // недопустимый кандидат уже был отвергнут при приёме; в идентификаторы не попадает
		}
		strength := "weak"
		if strongKind(c.Kind) {
			strength = "strong"
		}
		if _, e = tx.Exec(ctx, `INSERT INTO assets.asset_identifiers(tenant_id,identifier_id,asset_uid,kind,namespace,normalized_value,strength,source_record_key) SELECT $1,$2,$3,$4,$5,$6,$7,$8 WHERE NOT EXISTS(SELECT 1 FROM assets.asset_identifiers WHERE tenant_id=$1 AND asset_uid=$3 AND kind=$4 AND namespace=$5 AND normalized_value=$6 AND source_record_key=$8 AND valid_to IS NULL)`, tenant, identifier.New(), asset, c.Kind, c.Namespace, c.Value, strength, record); e != nil {
			return e
		}
	}
	return nil
}

// DismissConflict откладывает конфликт: запись остаётся без актива, её наблюдения — в ожидании.
func (Store) DismissConflict(ctx context.Context, tx pgx.Tx, tenant, conflict string) error {
	_, e := tx.Exec(ctx, "UPDATE assets.reconciliation_conflicts SET state='dismissed',revision=revision+1 WHERE tenant_id=$1 AND conflict_id=$2 AND state='open'", tenant, conflict)
	return e
}
