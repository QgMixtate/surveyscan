//go:build linux

package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/pki"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

func TestFlushProgress12CachedAckRemovesOnlyAfterVerifiedCommit(t *testing.T) {
	dir := t.TempDir()
	spool := filepath.Join(dir, "spool")
	if e := os.Mkdir(spool, 0700); e != nil {
		t.Fatal(e)
	}
	centerPublic, center, _ := ed25519.GenerateKey(rand.Reader)
	_, origin, _ := ed25519.GenerateKey(rand.Reader)
	legacy, e := wire.New()
	if e != nil {
		t.Fatal(e)
	}
	decoder, e := wire.NewInventoryDecoder(legacy, true)
	if e != nil {
		t.Fatal(e)
	}
	claims := pki.Claims{Tenant: identifier.New(), Source: identifier.New(), Generation: identifier.New(), KeyID: identifier.New(), CenterKeyID: identifier.New(), CenterPublic: centerPublic}
	c := &Client{cfg: Config{State: dir, Limit: 524288, CollectorURL: "https://offline.invalid"}, claims: claims, key: origin, wire: legacy, http: &http.Client{Transport: responseTransport{fail: true}}}

	fixture := allSectionsFixture(t)
	transport, e := wire.NewInventoryTransport12(wire.InventoryMaximum12())
	if e != nil {
		t.Fatal(e)
	}
	id := batchIdentity12{Tenant: claims.Tenant, Origin: contracts.Origin{SourceID: claims.Source, SourceKind: "agent", GenerationID: claims.Generation}, Site: fixture.Scope.SiteID, Scope: fixture.Scope.ScopeID, KeyID: claims.KeyID, Key: origin}
	delivery, raw, e := buildBatch12(id, transport, "1", fixture.Candidates, fixture.Sections, fixture.CollectedAt)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(spool, delivery+".pending")
	if e = writeAtomic(path, raw); e != nil {
		t.Fatal(e)
	}
	batch, _, e := transport.Batch(raw)
	if e != nil {
		t.Fatal(e)
	}
	signed, observed, _, e := transport.Observation(batch.Records[0])
	if e != nil {
		t.Fatal(e)
	}
	canonical, _ := wire.Canonical(raw)
	batchHash := sha256.Sum256(canonical)
	result := contracts.CenterResult{Version: contracts.Version{Major: 1}, ReceiptID: identifier.New(), TenantID: claims.Tenant, DeliveryID: delivery, BatchDigest: hex.EncodeToString(batchHash[:]), CommittedAt: time.Now().UTC(), Revision: "1", Status: "completed_with_errors",
		Results: []contracts.RecordResult{{SourceID: claims.Source, ObservationID: observed.ID, Digest: signed.Digest, Disposition: "rejected", Reason: "SOURCE_NOT_AUTHORIZED", SpoolAction: "retain"}}}
	save := func() {
		t.Helper()
		body, _ := json.Marshal(result)
		canon, _ := wire.Canonical(body)
		sum := sha256.Sum256(canon)
		ack := contracts.SignedCenterResult{Payload: result, KeyID: claims.CenterKeyID, Digest: hex.EncodeToString(sum[:]), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(center, append([]byte("SURVEYSCAN-CENTER-RESULT-V1\n"), canon...)))}
		out, _ := json.Marshal(ack)
		if e := writeAtomic(filepath.Join(spool, delivery+".receipt"), out); e != nil {
			t.Fatal(e)
		}
	}

	// Без подтверждения и без сети пакет остаётся.
	if progress, e := c.flushProgress12(context.Background(), decoder); e == nil || progress {
		t.Fatal("offline flush without a receipt claimed progress", e)
	}
	if _, e = os.Stat(path); e != nil {
		t.Fatal("offline flush removed the packet", e)
	}
	// Отвергнутый результат хранит пакет (карантин) и не требует сети.
	save()
	if progress, e := c.flushProgress12(context.Background(), decoder); e != nil || progress {
		t.Fatal("quarantine must retain without progress", progress, e)
	}
	if _, e = os.Stat(path); e != nil {
		t.Fatal("quarantine removed the packet", e)
	}
	// Старый путь C03 не должен молча принимать батч 1.2: поэтому нужна отдельная копия.
	if _, e = c.flushProgress(context.Background()); e == nil {
		t.Fatal("C03 delivery accepted an unnegotiated 1.2 batch")
	}
	if _, e = os.Stat(path); e != nil {
		t.Fatal("C03 delivery removed a 1.2 packet", e)
	}
	// Проверенный commit разрешает удаление и считается прогрессом.
	uid := identifier.New()
	result.Status, result.Results[0].AssetID = "completed", &uid
	result.Results[0].Disposition, result.Results[0].Reason, result.Results[0].SpoolAction = "applied", "SOURCE_MAPPING", "remove"
	save()
	progress, e := c.flushProgress12(context.Background(), decoder)
	if e != nil || !progress {
		t.Fatal("verified commit made no progress", progress, e)
	}
	if _, e = os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("packet survived a verified remove receipt")
	}
}
