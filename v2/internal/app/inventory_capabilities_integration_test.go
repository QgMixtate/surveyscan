//go:build integration

package app_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/imports"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/health"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

type capabilityTestSigner struct {
	key   ed25519.PrivateKey
	fail  atomic.Bool
	calls atomic.Int32
}

func (s *capabilityTestSigner) Sign(_ context.Context, message []byte) ([]byte, error) {
	s.calls.Add(1)
	if s.fail.Load() {
		return nil, errors.New("synthetic unavailable signer")
	}
	return ed25519.Sign(s.key, message), nil
}

// Real TLS/PG/enrollment with a test signer implementation. This test does not
// claim an actual OpenBao Transit call or full three-hop negotiation.
func TestC15CenterCapabilitiesMTLSBindingRevocationAndSignerFailure(t *testing.T) {
	f := registrySetup(t)
	machine, authority := machineService(t, f)
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	machine.CenterPublicKey = base64.RawURLEncoding.EncodeToString(public)
	signer := &capabilityTestSigner{key: key}
	// Deliberately supply a local key too: failed Signer must never fall back.
	uploads := &imports.UploadService{Pool: f.pool, Auth: machine, Wire: f.registry.Wire, Signer: signer, KeyID: machine.CenterKeyID, Key: key}
	protocol, err := f.registry.ConfigureInventoryProtocol12(true)
	if err != nil {
		t.Fatal(err)
	}
	uploads.Registry = app.MachineRegistry{Registry: f.registry, Auth: machine}
	f.registry.Machine = &app.MachineAPI{Sources: machine, Uploads: uploads}
	auth, err := access.NewHTTP(f.users, "https://ui.example", false)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := app.NewHTTP(auth, health.Handler(func(context.Context) error { return nil }), f.registry)
	if err != nil {
		t.Fatal(err)
	}
	serverPublic, serverKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "C15 capability fixture"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	serverDER, err := x509.CreateCertificate(rand.Reader, template, authority.Certificate, serverPublic, authority.Key)
	if err != nil {
		t.Fatal(err)
	}
	serverPair := tlsPair(t, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})), serverKey)
	roots := x509.NewCertPool()
	roots.AddCert(authority.Certificate)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverPair}, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: roots}
	server.StartTLS()
	defer server.Close()
	clientFor := func(pair *tls.Certificate) *http.Client {
		cfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
		if pair != nil {
			cfg.Certificates = []tls.Certificate{*pair}
		}
		return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
	}
	post := func(client *http.Client, body []byte) (int, []byte) {
		t.Helper()
		res, err := client.Post(server.URL+"/api/v1/machine/inventory-capabilities", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		return res.StatusCode, raw
	}
	nonce, err := wire.NewInventoryNonce()
	if err != nil {
		t.Fatal(err)
	}
	request, _ := wire.RecordJSON(map[string]string{"nonce": nonce})
	anonymous := clientFor(nil)
	defer anonymous.CloseIdleConnections()
	code, _ := post(anonymous, request)
	expect(t, 401, code)
	csr, hash, signingPublic, tlsKey := csrTLSMaterial(t)
	source := identifier.New()
	grant, err := machine.Grant(f.ctx, f.identity, contracts.EnrollmentGrantRequest{TenantID: tenant, SourceID: source, Kind: "collector", SiteID: siteID, TTL: 900, CSRHash: hash, PublicKey: signingPublic})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := machine.Enroll(f.ctx, grant.Token, contracts.EnrollmentRequest{GrantID: grant.ID, SourceID: source, CSR: csr, PublicKey: signingPublic})
	if err != nil {
		t.Fatal(err)
	}
	pair := tlsPair(t, identity.Chain, tlsKey)
	client := clientFor(&pair)
	defer client.CloseIdleConnections()
	code, raw := post(client, request)
	expect(t, 200, code)
	audience := contracts.Origin{SourceID: source, SourceKind: "collector", GenerationID: identity.GenerationID}
	payload, err := wire.VerifyInventoryCapabilities(raw, tenant, audience, nonce, machine.CenterKeyID, public)
	if err != nil {
		t.Fatal(err)
	}
	if offer, err := wire.CapabilityOffer(payload); err != nil || offer.Observation12 || offer.Batch12 {
		t.Fatal("draft advertised before handlers", err)
	}
	code, _ = post(client, []byte(`{"nonce":"bad"}`))
	expect(t, 400, code)
	if signer.calls.Load() != 1 {
		t.Fatal("invalid request reached signer", signer.calls.Load())
	}
	signer.fail.Store(true)
	code, _ = post(client, request)
	expect(t, 503, code)
	signer.fail.Store(false)

	// Same real TLS/PG fixture, separately signed profile request for an assigned agent.
	var collectorID string
	if err = f.pool.QueryRow(f.ctx, "SELECT collector_id::text FROM sources.collectors WHERE tenant_id=$1 AND source_id=$2", tenant, source).Scan(&collectorID); err != nil {
		t.Fatal(err)
	}
	agentPublic, agentKey, _ := ed25519.GenerateKey(rand.Reader)
	agentCSR, agentHash, _, _ := csrTLSMaterial(t)
	agentSource := identifier.New()
	agentSigning := base64.RawURLEncoding.EncodeToString(agentPublic)
	agentGrant, err := machine.Grant(f.ctx, f.identity, contracts.EnrollmentGrantRequest{TenantID: tenant, SourceID: agentSource, Kind: "agent", SiteID: siteID, CollectorID: &collectorID, TTL: 900, CSRHash: agentHash, PublicKey: agentSigning})
	if err != nil {
		t.Fatal(err)
	}
	agentIdentity, err := machine.Enroll(f.ctx, agentGrant.Token, contracts.EnrollmentRequest{GrantID: agentGrant.ID, SourceID: agentSource, CSR: agentCSR, PublicKey: agentSigning})
	if err != nil {
		t.Fatal(err)
	}
	agentOrigin := contracts.Origin{SourceID: agentSource, SourceKind: "agent", GenerationID: agentIdentity.GenerationID}
	profileNonce, _ := wire.NewInventoryNonce()
	profileRequest := contracts.InventoryProfileRequest12{Version: contracts.Version{Major: 1, Minor: 2}, Tenant: tenant, Origin: agentOrigin, Nonce: profileNonce, Sent: time.Now().UTC(), Platform: contracts.InventoryPlatform12}
	profileRaw, _ := wire.SignInventoryProfile12(profileRequest, wire.InventoryProfileRequestDomain12, agentIdentity.KeyID, agentKey)
	postProfile := func(raw []byte) (int, []byte) {
		t.Helper()
		res, err := client.Post(server.URL+"/api/v1/machine/inventory-profile", "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, b
	}
	code, _ = postProfile(profileRaw)
	expect(t, 503, code)
	uploads.Protocol = protocol
	code, profileResponse := postProfile(profileRaw)
	expect(t, 200, code)
	if _, err = wire.VerifyInventoryProfile12(profileResponse, tenant, agentOrigin, collectorID, profileNonce, machine.CenterKeyID, public); err != nil {
		t.Fatal(err)
	}
	signer.fail.Store(true)
	code, _ = postProfile(profileRaw)
	expect(t, 503, code)
	signer.fail.Store(false)
	forgedProfile, _ := wire.SignInventoryProfile12(profileRequest, wire.InventoryProfileRequestDomain12, agentIdentity.KeyID, key)
	code, _ = postProfile(forgedProfile)
	expect(t, 401, code)
	if err = machine.Revoke(f.ctx, f.identity, source); err != nil {
		t.Fatal(err)
	}
	calls := signer.calls.Load()
	code, _ = post(client, request)
	expect(t, 401, code)
	if signer.calls.Load() != calls {
		t.Fatal("revoked source obtained a fresh signed capability")
	}
}
