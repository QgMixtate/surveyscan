//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/imports"
	importport "github.com/QgMixtate/surveyscan/v2/internal/modules/imports/port"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/pki"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
	"strings"
	"sync"
	"testing"
)

type uploadFixture struct {
	f                               *registryFixture
	service                         *imports.UploadService
	sources                         *sources.MachineService
	source, generation, fingerprint string
	key                             ed25519.PrivateKey
	certificate                     *x509.Certificate
}

func uploadSetup(t *testing.T) *uploadFixture {
	t.Helper()
	f := registrySetup(t)
	sources, _ := machineService(t, f)
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	sources.CenterPublicKey = base64.RawURLEncoding.EncodeToString(pub)
	csr, hash, _, _ := csrTLSMaterial(t)
	source := identifier.New()
	grant, e := sources.Grant(f.ctx, f.identity, contracts.EnrollmentGrantRequest{TenantID: tenant, SourceID: source, Kind: "collector", SiteID: siteID, TTL: 900, CSRHash: hash, PublicKey: base64.RawURLEncoding.EncodeToString(f.key.Public().(ed25519.PublicKey))})
	if e != nil {
		t.Fatal(e)
	}
	result, e := sources.Enroll(f.ctx, grant.Token, contracts.EnrollmentRequest{GrantID: grant.ID, SourceID: source, CSR: csr, PublicKey: base64.RawURLEncoding.EncodeToString(f.key.Public().(ed25519.PublicKey))})
	if e != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode([]byte(result.Chain))
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	f.keyID = result.KeyID
	service := &imports.UploadService{Pool: f.pool, Auth: sources, Registry: app.MachineRegistry{Registry: f.registry, Auth: sources}, Wire: f.registry.Wire, KeyID: sources.CenterKeyID, Key: key}
	return &uploadFixture{f, service, sources, source, result.GenerationID, pki.Fingerprint(cert), key, cert}
}
func (u *uploadFixture) observation(sequence string) contracts.Observation {
	o := u.f.observation(sequence)
	o.Origin = contracts.Origin{SourceID: u.source, SourceKind: "collector", GenerationID: u.generation}
	return o
}
func (u *uploadFixture) batch(t *testing.T, observations ...contracts.Observation) (contracts.Batch, []byte) {
	t.Helper()
	batch := contracts.Batch{Version: contracts.Version{Major: 1}, TenantID: tenant, DeliveryID: identifier.New(), Records: []json.RawMessage{}}
	for _, o := range observations {
		batch.Records = append(batch.Records, u.f.signed(t, o))
	}
	raw, e := json.Marshal(batch)
	if e != nil {
		t.Fatal(e)
	}
	return batch, raw
}
func (u *uploadFixture) verifyReceipt(t *testing.T, raw []byte, batch contracts.Batch) contracts.SignedCenterResult {
	t.Helper()
	if e := u.service.Wire.Validate("SignedCenterResult", raw); e != nil {
		t.Fatal(e)
	}
	var result contracts.SignedCenterResult
	if e := json.Unmarshal(raw, &result); e != nil {
		t.Fatal(e)
	}
	body, _ := json.Marshal(result.Payload)
	canonical, e := wire.Canonical(body)
	if e != nil {
		t.Fatal(e)
	}
	digest := sha256.Sum256(canonical)
	signature, e := base64.RawURLEncoding.DecodeString(result.Signature)
	if e != nil {
		t.Fatal(e)
	}
	if result.Digest != hex.EncodeToString(digest[:]) || !ed25519.Verify(u.key.Public().(ed25519.PublicKey), append([]byte("SURVEYSCAN-CENTER-RESULT-V1\n"), canonical...), signature) {
		t.Fatal("unverifiable center result")
	}
	batchRaw, _ := json.Marshal(batch)
	batchCanonical, _ := wire.Canonical(batchRaw)
	sum := sha256.Sum256(batchCanonical)
	if result.Payload.BatchDigest != hex.EncodeToString(sum[:]) || result.Payload.DeliveryID != batch.DeliveryID || result.Payload.TenantID != tenant || len(result.Payload.Results) != len(batch.Records) {
		t.Fatal("receipt not bound to batch")
	}
	return result
}
func TestC07DurableUploadSignedReceiptAndReplay(t *testing.T) {
	u := uploadSetup(t)
	first, second := u.observation("1"), u.observation("2")
	batch, raw := u.batch(t, first, second)
	transport, e := u.service.Stage(u.f.ctx, u.fingerprint, raw)
	if e != nil || transport.SpoolAction != "retain" {
		t.Fatal(transport, e)
	}
	status, e := u.service.Status(u.f.ctx, u.fingerprint, batch.DeliveryID)
	if e != nil || u.service.Wire.Validate("TransportReceipt", status) != nil {
		t.Fatal("non-durable transport status", e)
	}
	receipt, e := u.service.Process(u.f.ctx, u.fingerprint, batch.DeliveryID)
	if e != nil {
		t.Fatal(e)
	}
	result := u.verifyReceipt(t, receipt, batch)
	if result.Payload.Status != "completed" {
		t.Fatal("valid batch not completed")
	}
	for _, r := range result.Payload.Results {
		if r.Disposition != "applied" || r.AssetID == nil || r.SpoolAction != "remove" {
			t.Fatal("invalid disposition")
		}
	}
	count(t, u.f, "assets.assets", 1)
	count(t, u.f, "inventory.observations", 2)
	count(t, u.f, "imports.import_checkpoints", 2)
	if _, e = u.service.Stage(u.f.ctx, u.fingerprint, raw); e != nil {
		t.Fatal(e)
	}
	replayed, e := u.service.Process(u.f.ctx, u.fingerprint, batch.DeliveryID)
	if e != nil {
		t.Fatal(e)
	}
	same := u.verifyReceipt(t, replayed, batch)
	if same.Signature != result.Signature || same.Payload.ReceiptID != result.Payload.ReceiptID {
		t.Fatal("receipt identity changed on replay")
	}
	count(t, u.f, "inventory.observations", 2)
	changed := batch
	changed.Records = []json.RawMessage{changed.Records[0]}
	bad, _ := json.Marshal(changed)
	if _, e = u.service.Stage(u.f.ctx, u.fingerprint, bad); !errors.Is(e, domain.Conflict) {
		t.Fatal("delivery ID reused with new digest", e)
	}
}

type crashAfterApply struct {
	delegate importport.Registry
	once     bool
}

func (c *crashAfterApply) Apply(ctx context.Context, fingerprint string, raw []byte) (contracts.RecordResult, error) {
	result, e := c.delegate.Apply(ctx, fingerprint, raw)
	if e != nil {
		return result, e
	}
	if !c.once {
		c.once = true
		return result, errors.New("synthetic crash after registry commit")
	}
	return result, nil
}
func TestC07RecoveryAfterRegistryCommitBeforeCheckpoint(t *testing.T) {
	u := uploadSetup(t)
	u.service.Registry = &crashAfterApply{delegate: u.service.Registry}
	batch, raw := u.batch(t, u.observation("1"))
	if _, e := u.service.Stage(u.f.ctx, u.fingerprint, raw); e != nil {
		t.Fatal(e)
	}
	if _, e := u.service.Process(u.f.ctx, u.fingerprint, batch.DeliveryID); e == nil {
		t.Fatal("crash injection ignored")
	}
	count(t, u.f, "inventory.observations", 1)
	count(t, u.f, "imports.import_checkpoints", 0)
	receipt, e := u.service.Process(u.f.ctx, u.fingerprint, batch.DeliveryID)
	if e != nil {
		t.Fatal(e)
	}
	u.verifyReceipt(t, receipt, batch)
	count(t, u.f, "assets.assets", 1)
	count(t, u.f, "inventory.observations", 1)
	count(t, u.f, "messaging.outbox_events", 4)
	count(t, u.f, "imports.import_checkpoints", 1)
}
func TestC07RejectedSignatureRetainsSpoolAndPendingConflictCanTrim(t *testing.T) {
	u := uploadSetup(t)
	first := u.observation("1")
	pending := u.observation("2")
	pending.Record.LocalID = "another-record"
	bad := u.observation("3")
	batch, raw := u.batch(t, first, pending, bad)
	var signed contracts.SignedObservation
	_ = json.Unmarshal(batch.Records[2], &signed)
	signed.Signature = strings.Repeat("A", 86)
	batch.Records[2], _ = json.Marshal(signed)
	raw, _ = json.Marshal(batch)
	if _, e := u.service.Stage(u.f.ctx, u.fingerprint, raw); e != nil {
		t.Fatal(e)
	}
	receipt, e := u.service.Process(u.f.ctx, u.fingerprint, batch.DeliveryID)
	if e != nil {
		t.Fatal(e)
	}
	result := u.verifyReceipt(t, receipt, batch)
	if result.Payload.Status != "completed_with_errors" || result.Payload.Results[1].Disposition != "recorded_pending_resolution" || result.Payload.Results[1].SpoolAction != "remove" || result.Payload.Results[2].Disposition != "rejected" || result.Payload.Results[2].SpoolAction != "retain" {
		t.Fatal("unsafe spool disposition")
	}
	count(t, u.f, "assets.assets", 1)
	count(t, u.f, "inventory.observations", 2)
}
func TestC07BatchTenantDigestAndUnknownPeerRejectedBeforeApply(t *testing.T) {
	u := uploadSetup(t)
	_, raw := u.batch(t, u.observation("1"))
	if _, e := u.service.Stage(u.f.ctx, strings.Repeat("0", 64), raw); !errors.Is(e, domain.Unauthorized) {
		t.Fatal("unknown peer accepted", e)
	}
	var batch contracts.Batch
	_ = json.Unmarshal(raw, &batch)
	batch.TenantID = otherTenant
	bad, _ := json.Marshal(batch)
	if _, e := u.service.Stage(u.f.ctx, u.fingerprint, bad); !errors.Is(e, domain.Invalid) {
		t.Fatal("mixed tenant accepted", e)
	}
	_ = json.Unmarshal(raw, &batch)
	var signed contracts.SignedObservation
	_ = json.Unmarshal(batch.Records[0], &signed)
	signed.Digest = strings.Repeat("0", 64)
	batch.Records[0], _ = json.Marshal(signed)
	bad, _ = json.Marshal(batch)
	if _, e := u.service.Stage(u.f.ctx, u.fingerprint, bad); !errors.Is(e, domain.Invalid) {
		t.Fatal("bad digest staged", e)
	}
	count(t, u.f, "imports.deliveries", 0)
	count(t, u.f, "inventory.observations", 0)
}
func TestC07ConcurrentProcessingConvergesToOneReceipt(t *testing.T) {
	u := uploadSetup(t)
	batch, raw := u.batch(t, u.observation("1"))
	if _, e := u.service.Stage(u.f.ctx, u.fingerprint, raw); e != nil {
		t.Fatal(e)
	}
	var receipts [2][]byte
	var errs [2]error
	var wg sync.WaitGroup
	for i := range 2 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			receipts[i], errs[i] = u.service.Process(u.f.ctx, u.fingerprint, batch.DeliveryID)
		}(i)
	}
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	a := u.verifyReceipt(t, receipts[0], batch)
	b := u.verifyReceipt(t, receipts[1], batch)
	if a.Signature != b.Signature {
		t.Fatal("parallel finalizers created different receipts")
	}
	count(t, u.f, "inventory.observations", 1)
	count(t, u.f, "imports.import_checkpoints", 1)
}
