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
	RecordSuccess(context.Context, pgx.Tx, contracts.Observation) error
	Summaries(context.Context, pgx.Tx, string, []string) ([]contracts.SourceSummary, error)
}

type Actor struct {
	Tenant, Source, Generation, Site, Kind, Fingerprint string
	Collector                                           *string
}
type MachineAuthorizer interface {
	PeerFingerprint(context.Context, pgx.Tx, string) (Actor, error)
	AllowOrigin(context.Context, pgx.Tx, string, contracts.Observation) error
}
