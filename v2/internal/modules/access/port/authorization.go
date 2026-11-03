// Package port задаёт контракт авторизации API и будущих workers.
package port

import (
	"context"
	"github.com/jackc/pgx/v5"
)

type Identity struct {
	TenantID, UserID, CredentialID, Role, Kind string
	Scopes                                     []string
}
type Authorizer interface {
	// Вызывается повторно внутри транзакции записи; держит locks до commit/rollback.
	Authorize(context.Context, pgx.Tx, string, string, string) (Identity, error)
}
