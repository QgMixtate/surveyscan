package imports

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/imports/port"
	sourceport "github.com/QgMixtate/surveyscan/v2/internal/modules/sources/port"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

type ResultSigner interface {
	Sign(context.Context, []byte) ([]byte, error)
}
type UploadService struct {
	Signer   ResultSigner
	Limits   Limits
	Pool     *pgxpool.Pool
	Auth     sourceport.MachineAuthorizer
	Registry port.Registry
	Wire     *wire.Validator
	Protocol *wire.InventoryDecoder
	KeyID    string
	Key      ed25519.PrivateKey
}

func (s *UploadService) Stage(ctx context.Context, fingerprint string, raw []byte) (contracts.TransportReceipt, error) {
	var result contracts.TransportReceipt
	decoder := s.Protocol
	if decoder == nil {
		var err error
		decoder, err = wire.NewInventoryDecoder(s.Wire, false)
		if err != nil {
			return result, err
		}
	}
	decoded, e := decoder.Batch(raw)
	if e != nil {
		return result, e
	}
	batch, canonical, observations := decoded.Batch, decoded.Canonical, decoded.Observations
	if batch.Version.Minor == 2 && !s.Inventory12Enabled() {
		return result, domain.Invalid
	}
	sum := sha256.Sum256(canonical)
	digest := hex.EncodeToString(sum[:])
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return result, e
	}
	defer tx.Rollback(ctx)
	actor, e := s.Auth.PeerFingerprint(ctx, tx, fingerprint)
	if e != nil {
		return result, e
	}
	if actor.Tenant != batch.TenantID || actor.Kind != "collector" || actor.Collector == nil {
		return result, domain.Unauthorized
	}
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "delivery:"+batch.TenantID+":"+batch.DeliveryID); e != nil {
		return result, e
	}
	var oldDigest, owner, generation string
	e = tx.QueryRow(ctx, "SELECT digest,principal_source::text,principal_generation::text FROM imports.delivery_payloads WHERE tenant_id=$1 AND delivery_id=$2", batch.TenantID, batch.DeliveryID).Scan(&oldDigest, &owner, &generation)
	if e == nil {
		if oldDigest != digest || owner != actor.Source || generation != actor.Generation {
			return result, domain.Conflict
		}
	} else if e == pgx.ErrNoRows {
		// Exact prior delivery belongs to this active courier and is recovery, not new ingress.
		for _, o := range observations {
			if e = s.Auth.AllowOrigin(ctx, tx, fingerprint, o); e != nil {
				return result, e
			}
		}
		if e = s.admit(ctx, tx, batch.TenantID, actor.Source, int64(len(canonical))); e != nil {
			return result, e
		}
		if _, e = tx.Exec(ctx, "INSERT INTO imports.deliveries(tenant_id,delivery_id,collector_id,digest,state) VALUES($1,$2,$3,$4,'processing')", batch.TenantID, batch.DeliveryID, actor.Collector, digest); e != nil {
			return result, e
		}
		if _, e = tx.Exec(ctx, "INSERT INTO imports.delivery_payloads(tenant_id,delivery_id,principal_source,principal_generation,payload,digest) VALUES($1,$2,$3,$4,$5,$6)", batch.TenantID, batch.DeliveryID, actor.Source, actor.Generation, canonical, digest); e != nil {
			return result, e
		}
	} else {
		return result, e
	}
	result = contracts.TransportReceipt{Type: "transport", TenantID: batch.TenantID, DeliveryID: batch.DeliveryID, Digest: digest, Stage: "center_received", SpoolAction: "retain", RequestID: identifier.New()}
	return result, tx.Commit(ctx)
}

type loadedDelivery struct {
	Batch   contracts.Batch
	Digest  string
	Receipt []byte
}

func (s *UploadService) load(ctx context.Context, tx pgx.Tx, fingerprint, id string, lock bool) (loadedDelivery, error) {
	var d loadedDelivery
	actor, e := s.Auth.PeerFingerprint(ctx, tx, fingerprint)
	if e != nil {
		return d, e
	}
	var raw []byte
	var owner, generation string
	q := "SELECT payload,digest,receipt,principal_source::text,principal_generation::text FROM imports.delivery_payloads WHERE tenant_id=$1 AND delivery_id=$2"
	if lock {
		q += " FOR UPDATE"
	}
	e = tx.QueryRow(ctx, q, actor.Tenant, id).Scan(&raw, &d.Digest, &d.Receipt, &owner, &generation)
	if e == pgx.ErrNoRows {
		return d, domain.NotFound
	}
	if e != nil {
		return d, e
	}
	if owner != actor.Source || generation != actor.Generation {
		return d, domain.NotFound
	}
	if len(raw) == 0 && len(d.Receipt) > 0 {
		d.Batch.TenantID = actor.Tenant
		d.Batch.DeliveryID = id
		return d, nil
	}
	if e = json.Unmarshal(raw, &d.Batch); e != nil {
		return d, e
	}
	if d.Batch.Version.Major == 1 && d.Batch.Version.Minor == 2 && len(d.Receipt) == 0 && !s.Inventory12Enabled() {
		return d, wire.ErrInventory12Unavailable
	}
	return d, nil
}
func (s *UploadService) Status(ctx context.Context, fingerprint, id string) ([]byte, error) {
	if !identifier.Valid(id) {
		return nil, domain.NotFound
	}
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx)
	d, e := s.load(ctx, tx, fingerprint, id, false)
	if e != nil {
		return nil, e
	}
	if len(d.Receipt) > 0 {
		return d.Receipt, nil
	}
	return json.Marshal(contracts.TransportReceipt{Type: "transport", TenantID: d.Batch.TenantID, DeliveryID: d.Batch.DeliveryID, Digest: d.Digest, Stage: "processing", SpoolAction: "retain", RequestID: identifier.New()})
}
func (s *UploadService) Process(ctx context.Context, fingerprint, id string) (response []byte, failure error) {
	if (s.Signer == nil && len(s.Key) != ed25519.PrivateKeySize) || !identifier.Valid(s.KeyID) || !identifier.Valid(id) {
		return nil, domain.Invalid
	}
	var d loadedDelivery
	var owner string
	for {
		tx, e := s.Pool.Begin(ctx)
		if e != nil {
			return nil, e
		}
		d, e = s.load(ctx, tx, fingerprint, id, false)
		tx.Rollback(ctx)
		if e != nil {
			return nil, e
		}
		if len(d.Receipt) > 0 {
			return d.Receipt, nil
		}
		var claimed bool
		owner, claimed, e = s.claim(ctx, d.Batch.TenantID, id)
		if e != nil {
			return nil, e
		}
		if claimed {
			break
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	defer func() {
		if failure != nil {
			s.failClaim(d.Batch.TenantID, id, owner, failure)
		}
	}()
	return s.process(ctx, fingerprint, id, owner, d)
}
func (s *UploadService) process(ctx context.Context, fingerprint, id, owner string, d loadedDelivery) ([]byte, error) {
	var e error
	for _, raw := range d.Batch.Records {
		var signed contracts.SignedObservation
		var o contracts.Observation
		_ = json.Unmarshal(raw, &signed)
		_ = json.Unmarshal(signed.Payload, &o)
		var saved []byte
		e = s.Pool.QueryRow(ctx, "SELECT result FROM imports.import_checkpoints WHERE tenant_id=$1 AND delivery_id=$2 AND record_key=$3", d.Batch.TenantID, id, o.ID).Scan(&saved)
		if e != nil && e != pgx.ErrNoRows {
			return nil, e
		}
		if len(saved) > 0 {
			continue
		}
		if e = s.renew(ctx, d.Batch.TenantID, id, owner); e != nil {
			return nil, e
		}
		result, e := s.Registry.Apply(ctx, fingerprint, raw)
		if e != nil {
			if !errors.Is(e, domain.Invalid) && !errors.Is(e, domain.Conflict) && !errors.Is(e, domain.Unauthorized) {
				return nil, e
			}
			reason := "SCHEMA_INVALID"
			if errors.Is(e, domain.Conflict) {
				reason = "SEQUENCE_CONFLICT"
			}
			if errors.Is(e, domain.Unauthorized) {
				reason = "SOURCE_NOT_AUTHORIZED"
			}
			result = contracts.RecordResult{SourceID: o.Origin.SourceID, ObservationID: o.ID, Digest: signed.Digest, Disposition: "rejected", Reason: reason, SpoolAction: "retain"}
		}
		if result.SourceID != o.Origin.SourceID || result.ObservationID != o.ID || result.Digest != signed.Digest {
			return nil, domain.Conflict
		}
		body, _ := json.Marshal(result)
		if e = s.Wire.Validate("RecordResult", body); e != nil {
			return nil, e
		}
		var accepted *string
		if result.Disposition != "rejected" {
			accepted = &o.ID
		}
		checkpoint, e := s.Pool.Begin(ctx)
		if e != nil {
			return nil, e
		}
		if e = s.fence(ctx, checkpoint, d.Batch.TenantID, id, owner, true); e != nil {
			checkpoint.Rollback(ctx)
			return nil, e
		}
		_, e = checkpoint.Exec(ctx, `INSERT INTO imports.import_checkpoints(tenant_id,delivery_id,record_key,state,observation_id,reason_code,result) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(tenant_id,delivery_id,record_key) DO NOTHING`, d.Batch.TenantID, id, o.ID, result.Disposition, accepted, result.Reason, body)
		if e != nil {
			checkpoint.Rollback(ctx)
			return nil, e
		}
		if e = checkpoint.Commit(ctx); e != nil {
			return nil, e
		}
	}
	final, e := s.Pool.Begin(ctx)
	if e != nil {
		return nil, e
	}
	defer final.Rollback(ctx)
	d, e = s.load(ctx, final, fingerprint, id, true)
	if e != nil {
		return nil, e
	}
	if len(d.Receipt) > 0 {
		return d.Receipt, nil
	}
	if e = s.fence(ctx, final, d.Batch.TenantID, id, owner, false); e != nil {
		return nil, e
	}
	var now time.Time
	if e = final.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); e != nil {
		return nil, e
	}
	payload := contracts.CenterResult{Version: contracts.Version{Major: 1}, ReceiptID: identifier.New(), TenantID: d.Batch.TenantID, DeliveryID: d.Batch.DeliveryID, BatchDigest: d.Digest, CommittedAt: now.UTC(), Revision: "1", Status: "completed", Results: []contracts.RecordResult{}}
	for _, raw := range d.Batch.Records {
		var signed contracts.SignedObservation
		var o contracts.Observation
		_ = json.Unmarshal(raw, &signed)
		_ = json.Unmarshal(signed.Payload, &o)
		var body []byte
		if e = final.QueryRow(ctx, "SELECT result FROM imports.import_checkpoints WHERE tenant_id=$1 AND delivery_id=$2 AND record_key=$3", d.Batch.TenantID, id, o.ID).Scan(&body); e != nil {
			return nil, e
		}
		var result contracts.RecordResult
		if e = json.Unmarshal(body, &result); e != nil {
			return nil, e
		}
		payload.Results = append(payload.Results, result)
		if result.Disposition != "applied" {
			payload.Status = "completed_with_errors"
		}
	}
	raw, e := json.Marshal(payload)
	if e != nil {
		return nil, e
	}
	canonical, e := wire.Canonical(raw)
	if e != nil {
		return nil, e
	}
	hash := sha256.Sum256(canonical)
	var signature []byte
	message := append([]byte("SURVEYSCAN-CENTER-RESULT-V1\n"), canonical...)
	if s.Signer != nil {
		signature, e = s.Signer.Sign(ctx, message)
		if e != nil {
			return nil, e
		}
	} else {
		signature = ed25519.Sign(s.Key, message)
	}
	receipt := contracts.SignedCenterResult{Payload: payload, Digest: hex.EncodeToString(hash[:]), KeyID: s.KeyID, Signature: base64.RawURLEncoding.EncodeToString(signature)}
	response, e := json.Marshal(receipt)
	if e != nil {
		return nil, e
	}
	if e = s.Wire.Validate("SignedCenterResult", response); e != nil {
		return nil, e
	}
	if _, e = final.Exec(ctx, "UPDATE imports.delivery_payloads SET receipt=$3,payload=NULL WHERE tenant_id=$1 AND delivery_id=$2", d.Batch.TenantID, id, response); e != nil {
		return nil, e
	}
	if _, e = final.Exec(ctx, "UPDATE imports.deliveries SET state=$3,revision=revision+1 WHERE tenant_id=$1 AND delivery_id=$2", d.Batch.TenantID, id, payload.Status); e != nil {
		return nil, e
	}
	if _, e = final.Exec(ctx, "UPDATE imports.processing_claims SET state='completed',owner=NULL,lease_until=NULL,retry_at=NULL,failures=0 WHERE tenant_id=$1 AND delivery_id=$2 AND owner=$3", d.Batch.TenantID, id, owner); e != nil {
		return nil, e
	}
	if e = final.Commit(ctx); e != nil {
		return nil, e
	}
	return response, nil
}
