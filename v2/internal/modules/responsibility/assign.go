package responsibility

import (
	"context"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
)

type Store struct{}

func (Store) Assign(ctx context.Context, tx pgx.Tx, tenant, asset, site string) (string, error) {
	var subject string
	e := tx.QueryRow(ctx, "SELECT fallback_subject_id::text FROM scope.sites WHERE tenant_id=$1 AND site_id=$2 FOR SHARE", tenant, site).Scan(&subject)
	if e != nil {
		return "", e
	}
	_, e = tx.Exec(ctx, "INSERT INTO responsibility.responsibility_assignments(tenant_id,assignment_id,asset_uid,subject_id,role,reason_code,actor_ref) VALUES($1,$2,$3,$4,'accountable','SITE_FALLBACK','system')", tenant, identifier.New(), asset, subject)
	return subject, e
}

func (Store) Accountable(ctx context.Context, tx pgx.Tx, tenant, asset string) (string, error) {
	var id string
	e := tx.QueryRow(ctx, "SELECT subject_id::text FROM responsibility.responsibility_assignments WHERE tenant_id=$1 AND asset_uid=$2 AND role='accountable' AND valid_to IS NULL", tenant, asset).Scan(&id)
	return id, e
}

func (Store) Subject(ctx context.Context, tx pgx.Tx, tenant, id string) (contracts.SubjectSummary, error) {
	var out contracts.SubjectSummary
	e := tx.QueryRow(ctx, "SELECT subject_id::text,kind,name FROM responsibility.subjects WHERE tenant_id=$1 AND subject_id=$2", tenant, id).Scan(&out.ID, &out.Kind, &out.Name)
	return out, e
}

// MergeFrom переносит назначения поглощённого актива на целевой (C25.03): роль, которой у цели нет, копируется;
// назначение цели по умолчанию площадки (SITE_FALLBACK) заменяется явным назначением поглощённого. Назначения
// поглощённого актива остаются как есть (у каждого актива ровно один действующий ответственный). Возвращает
// субъекта ответственного цели, если он сменился.
func (Store) MergeFrom(ctx context.Context, tx pgx.Tx, tenant, from, to, actor string) (string, error) {
	rows, e := tx.Query(ctx, `SELECT f.role,f.subject_id::text FROM responsibility.responsibility_assignments f
LEFT JOIN responsibility.responsibility_assignments t ON t.tenant_id=f.tenant_id AND t.asset_uid=$3 AND t.role=f.role AND t.valid_to IS NULL
WHERE f.tenant_id=$1 AND f.asset_uid=$2 AND f.valid_to IS NULL AND (t.assignment_id IS NULL OR t.reason_code='SITE_FALLBACK' AND f.reason_code<>'SITE_FALLBACK' AND t.subject_id<>f.subject_id)`, tenant, from, to)
	if e != nil {
		return "", e
	}
	type move struct{ role, subject string }
	var moves []move
	for rows.Next() {
		var m move
		if e = rows.Scan(&m.role, &m.subject); e != nil {
			rows.Close()
			return "", e
		}
		moves = append(moves, m)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return "", e
	}
	accountable := ""
	for _, m := range moves {
		if _, e = tx.Exec(ctx, "UPDATE responsibility.responsibility_assignments SET valid_to=now() WHERE tenant_id=$1 AND asset_uid=$2 AND role=$3 AND valid_to IS NULL", tenant, to, m.role); e != nil {
			return "", e
		}
		if _, e = tx.Exec(ctx, "INSERT INTO responsibility.responsibility_assignments(tenant_id,assignment_id,asset_uid,subject_id,role,reason_code,actor_ref) VALUES($1,$2,$3,$4,$5,'ASSET_MERGE',$6)", tenant, identifier.New(), to, m.subject, m.role, actor); e != nil {
			return "", e
		}
		if m.role == "accountable" {
			accountable = m.subject
		}
	}
	return accountable, nil
}
