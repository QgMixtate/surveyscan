package port

import (
	"context"
	"github.com/QgMixtate/surveyscan/v2/contracts"
)

type Registry interface {
	Apply(context.Context, string, []byte) (contracts.RecordResult, error)
}
