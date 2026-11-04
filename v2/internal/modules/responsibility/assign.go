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
