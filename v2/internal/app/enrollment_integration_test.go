//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/audit"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/health"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/pki"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func machineService(t *testing.T, f *registryFixture) (*sources.MachineService, *pki.Authority) {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "C07 synthetic test authority"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour)}
	der, e := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	ca, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	authority := &pki.Authority{Certificate: ca, Key: key, Chain: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
	centerPub, _, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return &sources.MachineService{Pool: f.pool, Auth: f.users, Audit: audit.Store{}, Issuer: authority, Wire: f.registry.Wire, CenterKeyID: identifier.New(), CenterPublicKey: base64.RawURLEncoding.EncodeToString(centerPub)}, authority
}
func csrTLSMaterial(t *testing.T) (string, string, string, ed25519.PrivateKey) {
	t.Helper()
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	der, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "attacker-chosen-subject"}, DNSNames: []string{"untrusted.example"}}, key)
	if e != nil {
		t.Fatal(e)
	}
	digest := sha256.Sum256(der)
	signPub, _, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), hex.EncodeToString(digest[:]), base64.RawURLEncoding.EncodeToString(signPub), key
}
func issueCollector(t *testing.T, f *registryFixture, s *sources.MachineService) (contracts.EnrollmentResult, *x509.Certificate) {
	t.Helper()
	csr, hash, pub := csrMaterial(t)
	source := identifier.New()
	grant, e := s.Grant(f.ctx, f.identity, contracts.EnrollmentGrantRequest{TenantID: tenant, SourceID: source, Kind: "collector", SiteID: siteID, TTL: 900, CSRHash: hash, PublicKey: pub})
	if e != nil {
		t.Fatal(e)
	}
	result, e := s.Enroll(f.ctx, grant.Token, contracts.EnrollmentRequest{GrantID: grant.ID, SourceID: source, CSR: csr, PublicKey: pub})
	if e != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode([]byte(result.Chain))
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	return result, cert
}
func TestC07ConcurrentPreboundEnrollmentAndCertificateIdentity(t *testing.T) {
	f := registrySetup(t)
	s, authority := machineService(t, f)
	csr, hash, pub := csrMaterial(t)
	source := identifier.New()
	grant, e := s.Grant(f.ctx, f.identity, contracts.EnrollmentGrantRequest{TenantID: tenant, SourceID: source, Kind: "collector", SiteID: siteID, TTL: 900, CSRHash: hash, PublicKey: pub})
	if e != nil {
		t.Fatal(e)
	}
	req := contracts.EnrollmentRequest{GrantID: grant.ID, SourceID: source, CSR: csr, PublicKey: pub}
	var results [2]contracts.EnrollmentResult
	var errs [2]error
	var wg sync.WaitGroup
	for i := range 2 {
		wg.Add(1)
		go func(i int) { defer wg.Done(); results[i], errs[i] = s.Enroll(f.ctx, grant.Token, req) }(i)
	}
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	if results[0].Chain != results[1].Chain || results[0].GenerationID != results[1].GenerationID {
		t.Fatal("concurrent enrollment did not return original identity")
	}
	count(t, f, "sources.machine_identities", 1)
	block, _ := pem.Decode([]byte(results[0].Chain))
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(authority.Certificate)
	if _, e = cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
		t.Fatal(e)
	}
	claims, e := pki.ClaimsFromCertificate(cert)
	if e != nil || claims.Source != source || claims.Tenant != tenant || claims.Kind != "collector" || claims.Collector == "" || claims.Collector == source || cert.Subject.CommonName == "attacker-chosen-subject" {
		t.Fatal("CSR selected identity/collector", e)
	}
	for _, name := range cert.DNSNames {
		if name == "untrusted.example" {
			t.Fatal("CSR SAN copied")
		}
	}
	tx, e := f.pool.Begin(f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	actor, e := s.Peer(f.ctx, tx, cert)
	tx.Rollback(f.ctx)
	if e != nil || actor.Source != source {
		t.Fatal("registered peer rejected", e)
	}
	body, _ := json.Marshal(results[0])
	if e = s.Wire.Validate("EnrollmentResult", body); e != nil {
		t.Fatal(e)
	}
}
func TestC07GrantCSRSubstitutionExpiryAndRevocation(t *testing.T) {
	f := registrySetup(t)
	s, _ := machineService(t, f)
	csr, hash, pub := csrMaterial(t)
	source := identifier.New()
	grant, e := s.Grant(f.ctx, f.identity, contracts.EnrollmentGrantRequest{TenantID: tenant, SourceID: source, Kind: "collector", SiteID: siteID, TTL: 900, CSRHash: hash, PublicKey: pub})
	if e != nil {
		t.Fatal(e)
	}
	otherCSR, _, otherPub := csrMaterial(t)
	for _, req := range []contracts.EnrollmentRequest{{GrantID: grant.ID, SourceID: source, CSR: otherCSR, PublicKey: pub}, {GrantID: grant.ID, SourceID: source, CSR: csr, PublicKey: otherPub}} {
		if _, e = s.Enroll(f.ctx, grant.Token, req); !errors.Is(e, domain.Unauthorized) {
			t.Fatal("substitution accepted", e)
		}
	}
	req := contracts.EnrollmentRequest{GrantID: grant.ID, SourceID: source, CSR: csr, PublicKey: pub}
	if _, e = f.pool.Exec(f.ctx, "UPDATE sources.enrollment_grants SET expires_at=clock_timestamp()-interval '1 second' WHERE grant_id=$1", grant.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Enroll(f.ctx, grant.Token, req); !errors.Is(e, domain.Unauthorized) {
		t.Fatal("expired grant accepted", e)
	}
	result, cert := issueCollector(t, f, s)
	if e = s.Revoke(f.ctx, f.identity, result.SourceID); e != nil {
		t.Fatal(e)
	}
	tx, e := f.pool.Begin(f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.Peer(f.ctx, tx, cert)
	tx.Rollback(f.ctx)
	if !errors.Is(e, domain.Unauthorized) {
		t.Fatal("revoked peer accepted", e)
	}
	if e = s.Revoke(f.ctx, f.identity, identifier.New()); !errors.Is(e, domain.NotFound) {
		t.Fatal("unknown resource leaked", e)
	}
}
func TestC07AgentCollectorTenantBindingAndIssuerRollback(t *testing.T) {
	f := registrySetup(t)
	s, _ := machineService(t, f)
	_, cert := issueCollector(t, f, s)
	tx, e := f.pool.Begin(f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	actor, e := s.Peer(f.ctx, tx, cert)
	tx.Rollback(f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	csr, hash, pub := csrMaterial(t)
	agent := identifier.New()
	grant, e := s.Grant(f.ctx, f.identity, contracts.EnrollmentGrantRequest{TenantID: tenant, SourceID: agent, Kind: "agent", SiteID: siteID, CollectorID: actor.Collector, TTL: 900, CSRHash: hash, PublicKey: pub})
	if e != nil {
		t.Fatal(e)
	}
	result, e := s.Enroll(f.ctx, grant.Token, contracts.EnrollmentRequest{GrantID: grant.ID, SourceID: agent, CSR: csr, PublicKey: pub})
	if e != nil {
		t.Fatal(e)
	}
	o := f.observation("1")
	o.Origin = contracts.Origin{SourceID: agent, SourceKind: "agent", GenerationID: result.GenerationID}
	tx, e = f.pool.Begin(f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	e = s.AllowOrigin(f.ctx, tx, actor.Fingerprint, o)
	tx.Rollback(f.ctx)
	if e != nil {
		t.Fatal("collector binding rejected", e)
	}
	_, otherCert := issueCollector(t, f, s)
	tx, e = f.pool.Begin(f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	e = s.AllowOrigin(f.ctx, tx, pki.Fingerprint(otherCert), o)
	tx.Rollback(f.ctx)
	if !errors.Is(e, domain.Unauthorized) {
		t.Fatal("other collector substituted origin", e)
	}
	bad := contracts.EnrollmentGrantRequest{TenantID: otherTenant, SourceID: identifier.New(), Kind: "collector", SiteID: siteID, TTL: 900, CSRHash: hash, PublicKey: pub}
	if _, e = s.Grant(f.ctx, f.identity, bad); !errors.Is(e, domain.Unauthorized) {
		t.Fatal("cross-tenant grant accepted", e)
	}
}

func csrMaterial(t *testing.T) (string, string, string) {
	csr, hash, pub, _ := csrTLSMaterial(t)
	return csr, hash, pub
}

type failingIssuer struct{}

func (failingIssuer) Issue(context.Context, *x509.CertificateRequest, pki.Claims) (pki.Issued, error) {
	return pki.Issued{}, errors.New("synthetic issuer failure")
}
func TestC07IssuerFailureLeavesPendingRegistration(t *testing.T) {
	f := registrySetup(t)
	s, _ := machineService(t, f)
	csr, hash, pub := csrMaterial(t)
	source := identifier.New()
	grant, e := s.Grant(f.ctx, f.identity, contracts.EnrollmentGrantRequest{TenantID: tenant, SourceID: source, Kind: "collector", SiteID: siteID, TTL: 900, CSRHash: hash, PublicKey: pub})
	if e != nil {
		t.Fatal(e)
	}
	s.Issuer = failingIssuer{}
	if _, e = s.Enroll(f.ctx, grant.Token, contracts.EnrollmentRequest{GrantID: grant.ID, SourceID: source, CSR: csr, PublicKey: pub}); e == nil {
		t.Fatal("issuer failure ignored")
	}
	var pending bool
	if e = f.pool.QueryRow(f.ctx, "SELECT s.state='pending' AND g.result IS NULL FROM sources.sources s JOIN sources.enrollment_grants g USING(tenant_id,source_id) WHERE s.source_id=$1", source).Scan(&pending); e != nil || !pending {
		t.Fatal("partial activation committed", e)
	}
	count(t, f, "sources.machine_identities", 0)
}
func TestC07HTTPSGrantEnrollmentAndMTLSRevocation(t *testing.T) {
	f := registrySetup(t)
	s, authority := machineService(t, f)
	f.registry.Machine = &app.MachineAPI{Sources: s}
	auth, e := access.NewHTTP(f.users, "https://ui.example", false)
	if e != nil {
		t.Fatal(e)
	}
	handler, e := app.NewHTTP(auth, health.Handler(func(context.Context) error { return nil }), f.registry)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(authority.Certificate)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: roots}
	server.StartTLS()
	t.Cleanup(server.Close)
	admin := newBrowser(t, server)
	session := admin.login(t, "admin")
	csr, hash, pub, tlsKey := csrTLSMaterial(t)
	source := identifier.New()
	req := contracts.EnrollmentGrantRequest{TenantID: tenant, SourceID: source, Kind: "collector", SiteID: siteID, TTL: 900, CSRHash: hash, PublicKey: pub}
	body, _ := json.Marshal(req)
	code, data, _ := admin.request(t, "POST", "/api/v1/enrollments", string(body), session.CSRFToken, "https://ui.example", nil)
	expect(t, 201, code)
	var grant contracts.EnrollmentGrant
	if e = json.Unmarshal(data, &grant); e != nil {
		t.Fatal(e)
	}
	enrollment := contracts.EnrollmentRequest{GrantID: grant.ID, SourceID: source, CSR: csr, PublicKey: pub}
	body, _ = json.Marshal(enrollment)
	anonymous := newBrowser(t, server)
	code, data, _ = anonymous.request(t, "POST", "/api/v1/machine/enroll", string(body), "", "", map[string]string{"Authorization": "Bearer " + grant.Token})
	expect(t, 201, code)
	var result contracts.EnrollmentResult
	if e = json.Unmarshal(data, &result); e != nil {
		t.Fatal(e)
	}
	if e = s.Wire.Validate("EnrollmentResult", data); e != nil {
		t.Fatal(e)
	}
	privateDER, e := x509.MarshalPKCS8PrivateKey(tlsKey)
	if e != nil {
		t.Fatal(e)
	}
	pair, e := tls.X509KeyPair([]byte(result.Chain), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}))
	if e != nil {
		t.Fatal(e)
	}
	config := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	config.Certificates = []tls.Certificate{pair}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: config}, Timeout: 5 * time.Second}
	t.Cleanup(client.CloseIdleConnections)
	machine := browser{client, server.URL}
	code, _, _ = admin.request(t, "GET", "/api/v1/machine/config", "", "", "", map[string]string{"X-Source-ID": source})
	expect(t, 401, code)
	code, data, _ = machine.request(t, "GET", "/api/v1/machine/config", "", "", "", map[string]string{"X-Source-ID": identifier.New()})
	expect(t, 200, code)
	if e = s.Wire.Validate("MachineConfig", data); e != nil {
		t.Fatal(e)
	}
	var profile contracts.MachineConfig
	_ = json.Unmarshal(data, &profile)
	if profile.SourceID != source || profile.CollectorID == nil {
		t.Fatal("header selected machine identity")
	}
	code, _, _ = admin.request(t, "POST", "/api/v1/sources/"+source+"/revocations", `{"reason_code":"OPERATOR_REQUEST"}`, session.CSRFToken, "https://ui.example", nil)
	expect(t, 200, code)
	code, _, _ = machine.request(t, "GET", "/api/v1/machine/config", "", "", "", nil)
	expect(t, 401, code)
}
