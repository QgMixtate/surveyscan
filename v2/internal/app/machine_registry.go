package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	sourceport "github.com/QgMixtate/surveyscan/v2/internal/modules/sources/port"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/jackc/pgx/v5"
)

type MachineRegistry struct {
	Registry *Registry
	Auth     sourceport.MachineAuthorizer
}

func (a MachineRegistry) Apply(ctx context.Context, fingerprint string, raw []byte) (contracts.RecordResult, error) {
	if result, found, e := a.recorded(ctx, fingerprint, raw); e != nil || found {
		return result, e
	}
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

func (a MachineRegistry) recorded(ctx context.Context, fingerprint string, raw []byte) (contracts.RecordResult, bool, error) {
	var out contracts.RecordResult
	signed, o, canonical, e := a.Registry.observation(raw)
	if e != nil {
		return out, false, e
	}
	sum := sha256.Sum256(canonical)
	if signed.Digest != hex.EncodeToString(sum[:]) {
		return out, false, domain.Invalid
	}
	auth, ok := a.Auth.(interface {
		AllowRecordedOrigin(context.Context, pgx.Tx, string, contracts.Observation) error
	})
	if !ok {
		return out, false, nil
	}
	tx, e := a.Registry.Pool.Begin(ctx)
	if e != nil {
		return out, false, e
	}
	defer tx.Rollback(ctx)
	if e = auth.AllowRecordedOrigin(ctx, tx, fingerprint, o); e != nil {
		return out, false, e
	}
	signature, e := base64.RawURLEncoding.Strict().DecodeString(signed.Signature)
	if e != nil {
		return out, false, domain.Invalid
	}
	result, found, e := a.Registry.Inventory.RecordedExact(ctx, tx, o, signed.Digest, signed.KeyID, signature)
	if e != nil || !found {
		return out, false, e
	}
	out = contracts.RecordResult{SourceID: o.Origin.SourceID, ObservationID: o.ID, Digest: signed.Digest, Disposition: result.Disposition, AssetID: result.AssetID, Reason: result.Reason, SpoolAction: "remove"}
	return out, true, tx.Commit(ctx)
}
