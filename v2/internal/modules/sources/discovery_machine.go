package sources

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
	"github.com/jackc/pgx/v5"
)

// Машинный канал C51 (контракт contracts/c51-discovery.schema.json; C03 не меняется): collector по mTLS забирает
// задание и сдаёт результат, подписанный своим ключом подписи (как пульс C10), с префиксом домена подписи.
const DiscoverySignaturePrefix = "SURVEYSCAN-DISCOVERY-V1\n"

type DiscoveryResult struct {
	Major      int         `json:"major"`
	ResultID   string      `json:"result_id"`
	Tenant     string      `json:"tenant_id"`
	Source     string      `json:"source_id"`
	Generation string      `json:"generation_id"`
	Run        string      `json:"run_id"`
	StartedAt  time.Time   `json:"started_at"`
	FinishedAt time.Time   `json:"finished_at"`
	Addresses  int         `json:"addresses"`
	Hosts      []FoundHost `json:"hosts"`
	Errors     []string    `json:"errors"`
}

type SignedDiscoveryResult struct {
	Payload   json.RawMessage `json:"payload"`
	Digest    string          `json:"payload_sha256"`
	KeyID     string          `json:"key_id"`
	Signature string          `json:"signature"`
}

// Strict — строгий разбор JSON машинного канала C51 (неизвестные поля — отказ).
func Strict(raw []byte, into any) error { return strict(raw, into) }

func strict(raw []byte, into any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(into); e != nil {
		return domain.Invalid
	}
	if d.More() {
		return domain.Invalid
	}
	return nil
}

func (s *MachineService) collectorActor(ctx context.Context, tx pgx.Tx, fp string) (MachineActor, error) {
	actor, e := s.PeerFingerprint(ctx, tx, fp)
	if e != nil {
		return actor, e
	}
	if actor.Kind != "collector" {
		return actor, domain.Unauthorized
	}
	return actor, nil
}

// DiscoveryJob выдаёт collector следующее обследование его подсетей (nil — заданий нет).
func (s *MachineService) DiscoveryJob(ctx context.Context, fp string) (*DiscoveryJob, error) {
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx)
	actor, e := s.collectorActor(ctx, tx, fp)
	if e != nil {
		return nil, e
	}
	job, e := Store{}.ClaimDiscovery(ctx, tx, actor.Tenant, actor.Source)
	if e != nil {
		return nil, e
	}
	return job, tx.Commit(ctx)
}

// SubmitDiscovery проверяет подпись результата ключом collector и принимает его.
func (s *MachineService) SubmitDiscovery(ctx context.Context, fp string, raw []byte) (DiscoveryOutcome, error) {
	var out DiscoveryOutcome
	var signed SignedDiscoveryResult
	if e := strict(raw, &signed); e != nil {
		return out, e
	}
	var r DiscoveryResult
	if e := strict(signed.Payload, &r); e != nil || r.Major != 1 || !identifier.Valid(r.ResultID) || !identifier.Valid(r.Run) || r.FinishedAt.Before(r.StartedAt) {
		return out, domain.Invalid
	}
	canonical, e := wire.Canonical(signed.Payload)
	if e != nil {
		return out, domain.Invalid
	}
	sum := sha256.Sum256(canonical)
	if signed.Digest != hex.EncodeToString(sum[:]) {
		return out, domain.Invalid
	}
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	actor, e := s.collectorActor(ctx, tx, fp)
	if e != nil {
		return out, e
	}
	if actor.Tenant != r.Tenant || actor.Source != r.Source || actor.Generation != r.Generation {
		return out, domain.Unauthorized
	}
	var public []byte
	e = tx.QueryRow(ctx, `SELECT public_key FROM sources.ingest_bindings WHERE tenant_id=$1 AND source_id=$2 AND generation_id=$3 AND key_id=$4 AND active LIMIT 1 FOR SHARE`, r.Tenant, r.Source, r.Generation, signed.KeyID).Scan(&public)
	if errors.Is(e, pgx.ErrNoRows) {
		return out, domain.Unauthorized
	}
	if e != nil {
		return out, e
	}
	signature, e := base64.RawURLEncoding.Strict().DecodeString(signed.Signature)
	if e != nil || len(public) != ed25519.PublicKeySize || !ed25519.Verify(public, append([]byte(DiscoverySignaturePrefix), canonical...), signature) {
		return out, domain.Invalid
	}
	if out, e = (Store{}).CompleteDiscovery(ctx, tx, r.Tenant, r.Source, r.Run, r.Addresses, r.Hosts, r.Errors); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}
