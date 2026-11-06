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
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/pki"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

type responseTransport struct {
	status    int
	getStatus int
	body      string
	fail      bool
}

func (r responseTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if r.fail {
		return nil, errors.New("offline")
	}
	status := r.status
	if req.Method == "GET" && r.getStatus != 0 {
		status = r.getStatus
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(r.body)), Header: make(http.Header)}, nil
}
func TestAgentOfflineAndUntrustedAckNeverTrim(t *testing.T) {
	dir := t.TempDir()
	spool := filepath.Join(dir, "spool")
	if e := os.Mkdir(spool, 0700); e != nil {
		t.Fatal(e)
	}
	id := identifier.New()
	tenant := identifier.New()
	raw, _ := json.Marshal(contracts.Batch{Version: contracts.Version{Major: 1}, TenantID: tenant, DeliveryID: id, Records: []json.RawMessage{}})
	path := filepath.Join(spool, id+".pending")
	if e := writeAtomic(path, raw); e != nil {
		t.Fatal(e)
	}
	v, e := wire.New()
	if e != nil {
		t.Fatal(e)
	}
	pub, _, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	for _, transport := range []responseTransport{{fail: true}, {status: 202, body: `{"spool_action":"remove"}`}, {status: 202, body: `{}`}} {
		c := &Client{cfg: Config{State: dir, CollectorURL: "https://collector.invalid"}, claims: pki.Claims{Tenant: tenant, CenterKeyID: identifier.New(), CenterPublic: pub}, wire: v, http: &http.Client{Transport: transport}}
		_ = c.Flush(context.Background())
		if _, e := os.Stat(path); e != nil {
			t.Fatal("offline or forged receipt removed sender packet", e)
		}
	}
}
func TestAgentPrepareStableLockAndPrivateConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{State: dir}
	first, e := Prepare(cfg)
	if e != nil {
		t.Fatal(e)
	}
	again, e := Prepare(cfg)
	if e != nil || again != first {
		t.Fatal("prepare replaced identity", e)
	}
	a, e := readKey(filepath.Join(dir, "tls.key"))
	if e != nil {
		t.Fatal(e)
	}
	b, e := readKey(filepath.Join(dir, "signing.key"))
	if e != nil {
		t.Fatal(e)
	}
	if string(a) == string(b) {
		t.Fatal("TLS and observation keys reused")
	}
	unlock, e := lockState(dir)
	if e != nil {
		t.Fatal(e)
	}
	if other, e := lockState(dir); e == nil {
		other()
		t.Fatal("second process acquired state")
	}
	unlock()
	config := filepath.Join(dir, "config.json")
	raw, _ := json.Marshal(Config{Tenant: identifier.New(), Site: identifier.New(), Scope: identifier.New(), CollectorSource: identifier.New(), CollectorURL: "http://collector.invalid", State: dir, CA: "ca.pem"})
	if e = writeAtomic(config, raw); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadConfig(config); e == nil {
		t.Fatal("cleartext collector allowed")
	}
	if e = os.Chmod(config, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadConfig(config); e == nil {
		t.Fatal("public config allowed")
	}
}

func TestSourceCachedAckRecoveryAndQuarantineWithoutNetwork(t *testing.T) {
	dir := t.TempDir()
	spool := filepath.Join(dir, "spool")
	if e := os.Mkdir(spool, 0700); e != nil {
		t.Fatal(e)
	}
	pub, center, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	_, origin, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	v, e := wire.New()
	if e != nil {
		t.Fatal(e)
	}
	claims := pki.Claims{Tenant: identifier.New(), Source: identifier.New(), Generation: identifier.New(), KeyID: identifier.New(), CenterKeyID: identifier.New(), CenterPublic: pub}
	c := &Client{cfg: Config{State: dir, Limit: 524288, CollectorURL: "https://offline.invalid"}, claims: claims, key: origin, wire: v, http: &http.Client{Transport: responseTransport{fail: true}}}
	now := time.Now().UTC()
	o := contracts.Observation{Version: contracts.Version{Major: 1}, ID: identifier.New(), TenantID: claims.Tenant, Origin: contracts.Origin{SourceID: claims.Source, GenerationID: claims.Generation, SourceKind: "agent"}, Record: contracts.SourceRecord{Namespace: "host", LocalID: "host"}, Scope: contracts.Scope{SiteID: identifier.New(), ScopeID: identifier.New()}, Sequence: "1", CollectedAt: now, Clock: "trusted", Candidates: []contracts.Candidate{}, Sections: []contracts.Section{{Name: "identity", CollectedAt: now, Status: "ok", Complete: true, Reason: "COLLECTED", Count: 1, Records: []map[string]any{{"hostname": "synthetic"}}}}}
	record, e := c.signed(o, "SURVEYSCAN-OBSERVATION-V1\n")
	if e != nil {
		t.Fatal(e)
	}
	var signed contracts.SignedObservation
	_ = json.Unmarshal(record, &signed)
	batch := contracts.Batch{Version: contracts.Version{Major: 1}, TenantID: claims.Tenant, DeliveryID: identifier.New(), Records: []json.RawMessage{record}}
	raw, _ := json.Marshal(batch)
	canonical, _ := wire.Canonical(raw)
	batchHash := sha256.Sum256(canonical)
	path := filepath.Join(spool, batch.DeliveryID+".pending")
	if e = writeAtomic(path, raw); e != nil {
		t.Fatal(e)
	}
	result := contracts.CenterResult{Version: contracts.Version{Major: 1}, ReceiptID: identifier.New(), TenantID: claims.Tenant, DeliveryID: batch.DeliveryID, BatchDigest: hex.EncodeToString(batchHash[:]), CommittedAt: now, Revision: "1", Status: "completed_with_errors", Results: []contracts.RecordResult{{SourceID: claims.Source, ObservationID: o.ID, Digest: signed.Digest, Disposition: "rejected", Reason: "SOURCE_NOT_AUTHORIZED", SpoolAction: "retain"}}}
	save := func() {
		t.Helper()
		body, _ := json.Marshal(result)
		canonical, _ := wire.Canonical(body)
		sum := sha256.Sum256(canonical)
		ack := contracts.SignedCenterResult{Payload: result, KeyID: claims.CenterKeyID, Digest: hex.EncodeToString(sum[:]), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(center, append([]byte("SURVEYSCAN-CENTER-RESULT-V1\n"), canonical...)))}
		raw, _ := json.Marshal(ack)
		if e := writeAtomic(filepath.Join(spool, batch.DeliveryID+".receipt"), raw); e != nil {
			t.Fatal(e)
		}
	}
	save()
	if e = c.Flush(context.Background()); e != nil {
		t.Fatal("quarantine attempted network instead of retaining", e)
	}
	if _, e = os.Stat(path); e != nil {
		t.Fatal("quarantine removed", e)
	}
	uid := identifier.New()
	result.Status = "completed"
	result.Results[0].AssetID = &uid
	result.Results[0].Disposition = "applied"
	result.Results[0].Reason = "SOURCE_MAPPING"
	result.Results[0].SpoolAction = "remove"
	save()
	if e = c.Flush(context.Background()); e != nil {
		t.Fatal("durable cached commit could not finish while offline", e)
	}
	if _, e = os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("cached verified ACK failed pending-unlink recovery")
	}
	// Mix an old verified cached ACK with a newly staged transport-only packet.
	// Arrival of new work must not erase successful durable delivery progress.
	if e = writeAtomic(path, raw); e != nil {
		t.Fatal(e)
	}
	fresh := batch
	fresh.DeliveryID = identifier.New()
	freshRaw, _ := json.Marshal(fresh)
	freshCanonical, _ := wire.Canonical(freshRaw)
	freshSum := sha256.Sum256(freshCanonical)
	freshPath := filepath.Join(spool, fresh.DeliveryID+".pending")
	if e = writeAtomic(freshPath, freshRaw); e != nil {
		t.Fatal(e)
	}
	transport, _ := json.Marshal(contracts.TransportReceipt{Type: "transport", TenantID: claims.Tenant, DeliveryID: fresh.DeliveryID, Digest: hex.EncodeToString(freshSum[:]), Stage: "processing", SpoolAction: "retain", RequestID: identifier.New()})
	if e = v.Validate("TransportReceipt", transport); e != nil {
		t.Fatal("invalid synthetic transport receipt", e)
	}
	c.http.Transport = responseTransport{status: 202, getStatus: 200, body: string(transport)}
	progress, err := c.flushProgress(context.Background())
	if !progress || err == nil {
		t.Fatal("verified removal hidden by new pending work", progress, err)
	}
	if _, e = os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("old acknowledged packet remains")
	}
	preserved, e := os.ReadFile(freshPath)
	if e != nil || string(preserved) != string(freshRaw) {
		t.Fatal("transport-only packet altered/removed", e)
	}
	if progress, err = c.flushProgress(context.Background()); progress || err == nil {
		t.Fatal("transport receipt falsely reported progress", progress, err)
	}
}
