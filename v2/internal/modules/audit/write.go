package audit

import (
	"context"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
)

type Store struct{}

func (Store) Record(ctx context.Context, tx pgx.Tx, tenant, actor, action, kind, object string) error {
	_, e := tx.Exec(ctx, "INSERT INTO audit.audit_events(tenant_id,audit_id,actor_ref,action,object_type,object_id) VALUES($1,$2,$3,$4,$5,$6)", tenant, identifier.New(), actor, action, kind, object)
	return e
}
