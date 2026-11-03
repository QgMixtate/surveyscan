package port

import (
	"context"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/jackc/pgx/v5"
)

type Trust struct {
	PublicKey []byte
	Priority  int
}
type Reader interface {
	Trust(context.Context, pgx.Tx, contracts.Observation, string) (Trust, error)
}
