//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/imports"
	importport "github.com/QgMixtate/surveyscan/v2/internal/modules/imports/port"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/pki"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

func TestC10ConcurrentStagingAdmissionAndReceiptPayloadGC(t *testing.T) {
	u := uploadSetup(t)
	u.service.Limits = imports.Limits{SourceDeliveries: 4, TenantDeliveries: 6}
	raws := [][]byte{}
	batches := []contracts.Batch{}
	for i := 1; i <= 24; i++ {
		batch, raw := u.batch(t, u.observation(stringInt(i)))
		raws = append(raws, raw)
		batches = append(batches, batch)
	}
	var wg sync.WaitGroup
	accepted := make(chan int, 24)
	errs := make(chan error, 24)
	for i := range raws {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, e := u.service.Stage(u.f.ctx, u.fingerprint, raws[i])
			if e == nil {
				accepted <- i
			} else if !errors.Is(e, imports.ErrQuota) {
				errs <- e
			}
		}(i)
	}
	wg.Wait()
	close(accepted)
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	indices := []int{}
	for i := range accepted {
		indices = append(indices, i)
	}
	if len(indices) != 4 {
		t.Fatal("non-atomic admission", len(indices))
	}
	count(t, u.f, "imports.deliveries", 4)
	first := indices[0]
	if _, e := u.service.Stage(u.f.ctx, u.fingerprint, raws[first]); e != nil {
		t.Fatal("exact replay rejected at capacity", e)
	}
	receipt, e := u.service.Process(u.f.ctx, u.fingerprint, batches[first].DeliveryID)
	if e != nil {
		t.Fatal(e)
	}
	u.verifyReceipt(t, receipt, batches[first])
	var gone bool
	if e = u.f.pool.QueryRow(u.f.ctx, "SELECT payload IS NULL AND receipt IS NOT NULL FROM imports.delivery_payloads WHERE delivery_id=$1", batches[first].DeliveryID).Scan(&gone); e != nil || !gone {
		t.Fatal("staging not freed safely", e)
	}
	replay, e := u.service.Status(u.f.ctx, u.fingerprint, batches[first].DeliveryID)
	a, _ := wire.Canonical(replay)
	b, _ := wire.Canonical(receipt)
	if e != nil || string(a) != string(b) {
		t.Fatal("GC broke cached receipt", e)
	}
	_, newRaw := u.batch(t, u.observation("100"))
	if _, e = u.service.Stage(u.f.ctx, u.fingerprint, newRaw); e != nil {
		t.Fatal("completed staging still consumes admission count", e)
	}
	u.service.Limits = imports.Limits{TenantBytes: 1}
	_, other := u.batch(t, u.observation("101"))
	if _, e = u.service.Stage(u.f.ctx, u.fingerprint, other); !errors.Is(e, imports.ErrQuota) {
		t.Fatal("tenant bytes bypass", e)
	}
}
func stringInt(n int) string { return strconv.Itoa(n) }

type blockedCommit struct {
	delegate         importport.Registry
	entered, release chan struct{}
	once             atomic.Bool
}

func (b *blockedCommit) Apply(ctx context.Context, fp string, raw []byte) (contracts.RecordResult, error) {
	v, e := b.delegate.Apply(ctx, fp, raw)
	if e == nil && b.once.CompareAndSwap(false, true) {
		close(b.entered)
		select {
		case <-b.release:
		case <-ctx.Done():
			return v, ctx.Err()
		}
	}
	return v, e
}
func TestC10ExpiredLeaseFencesOldWorkerAfterRegistryCommit(t *testing.T) {
	u := uploadSetup(t)
	batch, raw := u.batch(t, u.observation("1"))
	if _, e := u.service.Stage(u.f.ctx, u.fingerprint, raw); e != nil {
		t.Fatal(e)
	}
	blocked := &blockedCommit{delegate: u.service.Registry, entered: make(chan struct{}), release: make(chan struct{})}
	u.service.Registry = blocked
	done := make(chan error, 1)
	go func() { _, e := u.service.Process(u.f.ctx, u.fingerprint, batch.DeliveryID); done <- e }()
	select {
	case <-blocked.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("worker never committed")
	}
	if _, e := u.f.pool.Exec(u.f.ctx, "UPDATE imports.processing_claims SET lease_until=clock_timestamp()-interval '1 second' WHERE delivery_id=$1", batch.DeliveryID); e != nil {
		t.Fatal(e)
	}
	receipt, e := u.service.Process(u.f.ctx, u.fingerprint, batch.DeliveryID)
	close(blocked.release)
	if e != nil {
		t.Fatal(e)
	}
	u.verifyReceipt(t, receipt, batch)
	if e = <-done; !errors.Is(e, imports.ErrLeaseLost) {
		t.Fatal("stale worker was not fenced", e)
	}
	count(t, u.f, "inventory.observations", 1)
	count(t, u.f, "imports.import_checkpoints", 1)
	count(t, u.f, "messaging.outbox_events", 4)
	var attempts int
	var state string
	if e = u.f.pool.QueryRow(u.f.ctx, "SELECT attempts,state FROM imports.processing_claims").Scan(&attempts, &state); e != nil || attempts != 2 || state != "completed" {
		t.Fatal("claim takeover state", attempts, state, e)
	}
}

type unavailableRegistry struct{}

func (unavailableRegistry) Apply(context.Context, string, []byte) (contracts.RecordResult, error) {
	return contracts.RecordResult{}, errors.New("synthetic-private-error-marker")
}
func TestC10TransientRetriesDeadLetterAndRawGuard(t *testing.T) {
	u := uploadSetup(t)
	u.service.Registry = unavailableRegistry{}
	batch, raw := u.batch(t, u.observation("1"))
	if _, e := u.service.Stage(u.f.ctx, u.fingerprint, raw); e != nil {
		t.Fatal(e)
	}
	for range 5 {
		if _, e := u.f.pool.Exec(u.f.ctx, "UPDATE imports.processing_claims SET retry_at=NULL"); e != nil {
			t.Fatal(e)
		}
		if _, e := u.service.Process(u.f.ctx, u.fingerprint, batch.DeliveryID); e == nil {
			t.Fatal("transient error acknowledged")
		}
	}
	if _, e := u.service.Process(u.f.ctx, u.fingerprint, batch.DeliveryID); !errors.Is(e, imports.ErrDeadLetter) {
		t.Fatal("retry bound bypassed", e)
	}
	var state, code string
	var failures int
	if e := u.f.pool.QueryRow(u.f.ctx, "SELECT state,failure_code,failures FROM imports.processing_claims").Scan(&state, &code, &failures); e != nil || state != "dead_letter" || failures != 5 || strings.Contains(code, "private") {
		t.Fatal("deadletter or sanitized failure invalid", e)
	}
	if _, e := u.f.pool.Exec(u.f.ctx, "UPDATE imports.delivery_payloads SET payload=NULL WHERE delivery_id=$1", batch.DeliveryID); e == nil {
		t.Fatal("payload discarded without receipt")
	}
	count(t, u.f, "inventory.observations", 0)
}
func TestC10ConcurrentProcessingBurstReturnsOneDurableReceipt(t *testing.T) {
	u := uploadSetup(t)
	batch, raw := u.batch(t, u.observation("1"))
	if _, e := u.service.Stage(u.f.ctx, u.fingerprint, raw); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(u.f.ctx, 15*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	results := make(chan []byte, 24)
	errs := make(chan error, 24)
	for range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, e := u.service.Process(ctx, u.fingerprint, batch.DeliveryID)
			if e != nil {
				errs <- e
			} else {
				results <- v
			}
		}()
	}
	wg.Wait()
	close(errs)
	close(results)
	for e := range errs {
		t.Fatal(e)
	}
	var first []byte
	for v := range results {
		if first == nil {
			first = v
		} else if a, _ := wire.Canonical(v); string(a) != canonicalText(first) {
			t.Fatal("burst minted multiple receipts")
		}
	}
	u.verifyReceipt(t, first, batch)
	count(t, u.f, "inventory.observations", 1)
	count(t, u.f, "imports.import_checkpoints", 1)
}
func TestC10CommittedOriginRevocationDoesNotCorruptOriginalResult(t *testing.T) {
	u := uploadSetup(t)
	claims, e := pki.ClaimsFromCertificate(u.certificate)
	if e != nil {
		t.Fatal(e)
	}
	agent := identifier.New()
	csr, hash, _, _ := csrTLSMaterial(t)
	pub := base64.RawURLEncoding.EncodeToString(u.f.key.Public().(ed25519.PublicKey))
	grant, e := u.sources.Grant(u.f.ctx, u.f.identity, contracts.EnrollmentGrantRequest{TenantID: tenant, SourceID: agent, Kind: "agent", SiteID: siteID, CollectorID: &claims.Collector, TTL: 900, CSRHash: hash, PublicKey: pub})
	if e != nil {
		t.Fatal(e)
	}
	enrolled, e := u.sources.Enroll(u.f.ctx, grant.Token, contracts.EnrollmentRequest{GrantID: grant.ID, SourceID: agent, CSR: csr, PublicKey: pub})
	if e != nil {
		t.Fatal(e)
	}
	u.f.keyID = enrolled.KeyID
	o := u.f.observation("1")
	o.Origin = contracts.Origin{SourceID: agent, SourceKind: "agent", GenerationID: enrolled.GenerationID}
	batch, raw := u.batch(t, o)
	delegate := u.service.Registry
	u.service.Registry = &crashAfterApply{delegate: delegate}
	if _, e = u.service.Stage(u.f.ctx, u.fingerprint, raw); e != nil {
		t.Fatal(e)
	}
	if _, e = u.service.Process(u.f.ctx, u.fingerprint, batch.DeliveryID); e == nil {
		t.Fatal("crash not injected")
	}
	if e = u.sources.Revoke(u.f.ctx, u.f.identity, agent); e != nil {
		t.Fatal(e)
	}
	u.service.Registry = delegate
	if _, e = u.service.Stage(u.f.ctx, u.fingerprint, raw); e != nil {
		t.Fatal("owned exact delivery could not resume after origin revoke", e)
	}
	receipt, e := u.service.Process(u.f.ctx, u.fingerprint, batch.DeliveryID)
	if e != nil {
		t.Fatal(e)
	}
	result := u.verifyReceipt(t, receipt, batch)
	if result.Payload.Results[0].Disposition != "applied" {
		t.Fatal("committed truth changed after revoke")
	}
	fresh := o
	fresh.ID = identifier.New()
	fresh.Sequence = "2"
	_, newRaw := u.batch(t, fresh)
	if _, e = u.service.Stage(u.f.ctx, u.fingerprint, newRaw); !errors.Is(e, domain.Unauthorized) {
		t.Fatal("revoked source ingested new data", e)
	}
	var frame contracts.SignedObservation
	_ = json.Unmarshal(batch.Records[0], &frame)
	frame.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	bad, _ := json.Marshal(frame)
	if _, e = (app.MachineRegistry{Registry: u.f.registry, Auth: u.sources}).Apply(u.f.ctx, u.fingerprint, bad); e == nil {
		t.Fatal("recorded path accepted forged signature")
	}
	count(t, u.f, "inventory.observations", 1)
}

func canonicalText(raw []byte) string { v, _ := wire.Canonical(raw); return string(v) }
