//go:build linux

package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/collector"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/pki"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

// Actual in-process mutual TLS on both hops and production agent/collector
// methods. The center signing handler is a test double, not OpenBao/PG proof.
func TestAgentNegotiatesThroughRealMTLSCollector(t *testing.T) {
	caPub, caKey, _ := ed25519.GenerateKey(rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "capability test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, caPub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	authority := pki.Authority{Certificate: ca, Chain: chain, Key: caKey}
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	centerPub, centerKey, _ := ed25519.GenerateKey(rand.Reader)
	relayPub, relayKey, _ := ed25519.GenerateKey(rand.Reader)
	agentPub, agentKey, _ := ed25519.GenerateKey(rand.Reader)
	claims := pki.Claims{Tenant: identifier.New(), Source: identifier.New(), Generation: identifier.New(), Kind: "collector", Collector: identifier.New(), KeyID: identifier.New(), SigningPublic: relayPub, CenterKeyID: identifier.New(), CenterPublic: centerPub}
	issue := func(claims pki.Claims) (tls.Certificate, []byte, []byte) {
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
		if err != nil {
			t.Fatal(err)
		}
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil {
			t.Fatal(err)
		}
		issued, err := authority.Issue(context.Background(), csr, claims)
		if err != nil {
			t.Fatal(err)
		}
		private, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		private = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
		pair, err := tls.X509KeyPair([]byte(issued.PEM), private)
		if err != nil {
			t.Fatal(err)
		}
		return pair, []byte(issued.PEM), private
	}
	_, relayCert, relayTLSKey := issue(claims)
	agentClaims := claims
	agentClaims.Kind = "agent"
	agentClaims.Source = identifier.New()
	agentClaims.Generation = identifier.New()
	agentClaims.KeyID = identifier.New()
	agentClaims.SigningPublic = agentPub
	agentPair, _, _ := issue(agentClaims)
	// The center uses a separate server leaf with loopback SAN and requires the
	// collector client certificate issued above.
	serverPub, serverKey, _ := ed25519.GenerateKey(rand.Reader)
	serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "center test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, ca, serverPub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	private, _ := x509.MarshalPKCS8PrivateKey(serverKey)
	serverPair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
	if err != nil {
		t.Fatal(err)
	}
	var mode atomic.Int32
	var calls atomic.Int32
	center := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			t.Error("center did not verify TLS")
			w.WriteHeader(401)
			return
		}
		peer, err := pki.ClaimsFromCertificate(r.TLS.PeerCertificates[0])
		if err != nil || peer.Source != claims.Source {
			t.Error("wrong center caller")
			w.WriteHeader(401)
			return
		}

		if r.URL.Path == "/api/v1/machine/inventory-profile" {
			if mode.Load() != 0 {
				w.WriteHeader(503)
				return
			}
			var frame contracts.ProfileFrame
			if json.NewDecoder(r.Body).Decode(&frame) != nil {
				w.WriteHeader(400)
				return
			}
			if wire.VerifyProfileFrame12(frame, wire.InventoryProfileRequestDomain12, agentClaims.KeyID, agentPub) != nil {
				t.Error("agent profile proof missing")
				w.WriteHeader(401)
				return
			}
			var request contracts.InventoryProfileRequest12
			_ = json.Unmarshal(frame.Payload, &request)
			if request.Applied != nil {
				t.Error("read-only fetch claimed applied")
			}
			common := contracts.MachineConfig{SourceID: agentClaims.Source, CollectorID: &claims.Collector, Revision: "1", Heartbeat: 30, Inventory: 60, SpoolBytes: 1048576}
			config, err := wire.InventoryConfigFromCommon12(common)
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			now := time.Now().UTC()
			value := contracts.InventoryProfile12{Version: contracts.Version{Major: 1, Minor: 2}, Tenant: claims.Tenant, Origin: request.Origin, Nonce: request.Nonce, Issued: now, Expires: now.Add(time.Minute), Config: config}
			raw, err := wire.SignInventoryProfile12(value, wire.InventoryProfileResponseDomain12, claims.CenterKeyID, centerKey)
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			_, _ = w.Write(raw)
			return
		}
		if mode.Load() == 1 {
			w.WriteHeader(503)
			return
		}
		var req struct {
			Nonce string `json:"nonce"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			w.WriteHeader(400)
			return
		}
		now := time.Now().UTC()
		p := contracts.InventoryCapabilities{Version: contracts.Version{Major: 1}, Issuer: "center", Tenant: claims.Tenant, Audience: contracts.Origin{SourceID: claims.Source, SourceKind: "collector", GenerationID: claims.Generation}, Nonce: req.Nonce, Issued: now, Expires: now.Add(time.Minute), Observations: []contracts.Version{{Major: 1}}, Batches: []contracts.Version{{Major: 1}}, SnapshotModes: []string{}}
		if mode.Load() != 2 {
			p.Observations = append(p.Observations, contracts.Version{Major: 1, Minor: 2})
			p.Batches = append(p.Batches, contracts.Version{Major: 1, Minor: 2})
			p.Limits12 = &contracts.InventoryLimits12{CanonicalBytes: 100000, SignedBytes: 200000, BatchBytes: 300000, Records: 9}
			p.SnapshotModes = []string{"partial"}
		}
		raw, _ := wire.RecordJSON(p)
		message, digest, err := wire.InventoryCapabilityMessage(raw)
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		signature := ed25519.Sign(centerKey, message)
		if mode.Load() == 3 {
			signature[0] ^= 1
		}
		_ = json.NewEncoder(w).Encode(contracts.SignedInventoryCapabilities{Payload: p, Digest: digest, KeyID: claims.CenterKeyID, Signature: base64.RawURLEncoding.EncodeToString(signature)})
	}))
	center.TLS = &tls.Config{Certificates: []tls.Certificate{serverPair}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12}
	center.StartTLS()
	defer center.Close()
	signingDER, _ := x509.MarshalPKCS8PrivateKey(relayKey)
	cfg := collector.Config{Inventory12: true, Listen: "127.0.0.1:0", CenterURL: center.URL, SourceID: claims.Source, CredentialState: filepath.Join(dir, "credentials"), SigningKey: write("signing.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: signingDER})), Certificate: write("relay.pem", relayCert), PrivateKey: write("tls.pem", relayTLSKey), CA: write("ca.pem", chain), Spool: filepath.Join(dir, "spool"), Limit: 524288}
	relay, err := collector.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(relay.Handler())
	server.TLS = relay.TLS.Clone()
	server.StartTLS()
	defer server.Close()
	agentCfg := Config{Tenant: claims.Tenant, CollectorSource: claims.Source, CollectorURL: server.URL}
	httpClient, err := newHTTP(agentCfg, roots, &agentPair, claims.Collector)
	if err != nil {
		t.Fatal(err)
	}
	defer httpClient.CloseIdleConnections()
	client := &Client{cfg: agentCfg, claims: agentClaims, key: agentKey, http: httpClient}
	own := wire.InventoryMaximum12()
	own.Records = 3
	result, err := client.NegotiateInventory12(context.Background(), own)
	if err != nil || result.Limits.CanonicalBytes != 100000 || result.Limits.BatchBytes != 300000 || result.Limits.Records != 3 || !result.Expires.After(time.Now()) {
		t.Fatalf("negotiation: %+v %v", result, err)
	}
	if calls.Load() != 1 {
		t.Fatal("negotiation retried")
	}
	profile, err := client.FetchInventoryProfile12(context.Background(), result)
	if err != nil || profile.Profile.Config.CollectionSeconds != 420 || profile.Limits != result.Limits {
		t.Fatal("fresh negotiated profile", err)
	}
	if client.profile != nil || client.cfg.InventorySeconds != 0 {
		t.Fatal("read-only fetch applied runtime config")
	}
	forged := result
	forged.Limits.BatchBytes++
	if _, err = client.FetchInventoryProfile12(context.Background(), forged); err == nil {
		t.Fatal("mutated negotiation accepted")
	}
	if _, err = client.FetchInventoryProfile12(context.Background(), InventoryNegotiation12{}); err == nil {
		t.Fatal("profile fetched without negotiation proof")
	}

	for _, failure := range []int32{1, 2, 3} {
		mode.Store(failure)
		if _, err := client.NegotiateInventory12(context.Background(), own); err == nil {
			t.Fatal("unavailable/legacy/forged center enabled1.2", failure)
		}
	}
	// A valid chain still cannot widen the local agent offer.
	mode.Store(0)
	own.Observation12 = false
	if _, err := client.NegotiateInventory12(context.Background(), own); err == nil {
		t.Fatal("local unsupported version enabled")
	}
}
