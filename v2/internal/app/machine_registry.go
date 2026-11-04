package app

import (
	"context"
	"encoding/json"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	sourceport "github.com/QgMixtate/surveyscan/v2/internal/modules/sources/port"
	"github.com/jackc/pgx/v5"
)

type MachineRegistry struct {
	Registry *Registry
	Auth     sourceport.MachineAuthorizer
}

func (a MachineRegistry) Apply(ctx context.Context, fingerprint string, raw []byte) (contracts.RecordResult, error) {
	var signed contracts.SignedObservation
	_ = json.Unmarshal(raw, &signed)
	var observation contracts.Observation
	_ = json.Unmarshal(signed.Payload, &observation)
	result, e := a.Registry.IngestAuthorized(ctx, observation.TenantID, observation.Origin.SourceID, raw, func(ctx context.Context, tx pgx.Tx, o contracts.Observation) error {
		return a.Auth.AllowOrigin(ctx, tx, fingerprint, o)
	})
	if e != nil {
		return contracts.RecordResult{}, e
	}
	return contracts.RecordResult{SourceID: observation.Origin.SourceID, ObservationID: observation.ID, Digest: signed.Digest, Disposition: result.Disposition, AssetID: result.AssetID, Reason: result.Reason, SpoolAction: "remove"}, nil
}
