package collector

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/pki"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

// Actual mTLS, Ed25519/C03 admission and disk replay with synthetic inventory.
// There is no center/PG delivery and no1.2upload in this test.
func TestCollectorLargeSignedC03BatchSurvivesSpoolEncoding(t *testing.T) {
	f := credentialSetup(t)
	c, err := New(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.client.CloseIdleConnections()
	public, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claims := pki.Claims{Tenant: f.claims.Tenant, Source: identifier.New(), Generation: identifier.New(), Kind: "agent", Collector: f.claims.Collector, KeyID: identifier.New(), SigningPublic: public, CenterKeyID: f.claims.CenterKeyID, CenterPublic: f.claims.CenterPublic}
	_, tlsKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, tlsKey)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := f.issuer.Issue(context.Background(), csr, claims)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(tlsKey)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair([]byte(issued.PEM), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(c.Handler())
	server.TLS = c.TLS.Clone()
	server.StartTLS()
	defer server.Close()
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: c.roots, ServerName: c.Claims.Source + ".collector.invalid", Certificates: []tls.Certificate{pair}}}}
	defer client.CloseIdleConnections()
	now := time.Now().UTC().Truncate(time.Microsecond)
	batch := contracts.Batch{Version: contracts.Version{Major: 1}, TenantID: claims.Tenant, DeliveryID: identifier.New()}
	for index := 1; index <= 10; index++ {
		network := []map[string]any{}
		for row := 0; row < 300; row++ {
			network = append(network, map[string]any{"name": fmt.Sprintf("%03d", row) + strings.Repeat("<>&", 41) + "xx", "addresses": []any{}})
		}
		o := contracts.Observation{Version: contracts.Version{Major: 1}, ID: identifier.New(), TenantID: claims.Tenant, Origin: contracts.Origin{SourceID: claims.Source, SourceKind: "agent", GenerationID: claims.Generation}, Record: contracts.SourceRecord{Namespace: "host", LocalID: "host"}, Scope: contracts.Scope{SiteID: identifier.New(), ScopeID: identifier.New()}, Sequence: strconv.Itoa(index), CollectedAt: now, Clock: "trusted", Candidates: []contracts.Candidate{{Kind: "hostname", Namespace: "dns", Value: "synthetic"}}, Sections: []contracts.Section{
			{Name: "identity", CollectedAt: now, Status: "ok", Complete: true, Reason: "COLLECTED", Count: 1, Records: []map[string]any{{"hostname": "synthetic"}}},
			{Name: "os", CollectedAt: now, Status: "ok", Complete: true, Reason: "COLLECTED", Count: 1, Records: []map[string]any{{"name": "Linux", "version": "6", "architecture": "amd64"}}},
			{Name: "network", CollectedAt: now, Status: "ok", Complete: true, Reason: "COLLECTED", Count: len(network), Records: network},
		}}
		payload, err := wire.RecordJSON(o)
		if err != nil {
			t.Fatal(err)
		}
		payload, err = wire.Canonical(payload)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(payload)
		signed, err := wire.RecordJSON(contracts.SignedObservation{Payload: payload, Digest: hex.EncodeToString(sum[:]), KeyID: claims.KeyID, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(signing, append([]byte("SURVEYSCAN-OBSERVATION-V1\n"), payload...)))})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err = c.wire.Observation(signed); err != nil {
			t.Fatal("synthetic C03 record invalid", err)
		}
		batch.Records = append(batch.Records, signed)
	}
	raw, err := wire.RecordJSON(batch)
	if err != nil || len(raw) > 1048576 {
		t.Fatal("synthetic batch exceeds existing admission", err)
	}
	if err = c.wire.Validate("Batch", raw); err != nil {
		t.Fatal(err)
	}
	post := func() {
		t.Helper()
		response, err := client.Post(server.URL+"/api/v1/machine/observations", "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		_, readErr := io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if readErr != nil || response.StatusCode != 202 {
			t.Fatal("durable admission failed", response.StatusCode, readErr)
		}
	}
	post()
	p, err := readPacket(c.path(batch.DeliveryID, ".pending"))
	if err != nil {
		t.Fatal("accepted packet unreadable", err)
	}
	canonical, err := wire.Canonical(raw)
	if err != nil || !bytes.Equal(p.Batch, canonical) {
		t.Fatal("canonical signed data changed on disk", err)
	}
	legacy, _ := json.Marshal(p)
	stored, _ := marshalPacket(p)
	t.Logf("synthetic C03: records=10 NICrows/observation=300 batch=%d old_packet=%d bounded_packet=%d reader_limit=%d", len(raw), len(legacy), len(stored), maxPacketBytes)
	if len(legacy) <= maxPacketBytes {
		t.Fatal("fixture does not reproduce old codec overflow")
	}
	// Same authenticated request is idempotently acknowledged from the readable
	// durable packet; it must not fail after a simulated sender ACK loss.
	post()
}
