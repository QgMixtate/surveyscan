package port

import (
	"context"
	"github.com/jackc/pgx/v5"
)

type Writer interface {
	Record(context.Context, pgx.Tx, string, string, string, string, string) error
}
