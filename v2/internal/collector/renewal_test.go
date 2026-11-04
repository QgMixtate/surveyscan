package collector

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
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/machinecred"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/pki"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type credentialFixture struct {
	cfg      Config
	issuer   pki.Authority
	claims   pki.Claims
	identity machinecred.Identity
	tlsKey   ed25519.PrivateKey
}

func privateWrite(t *testing.T, path string, raw []byte) {
	t.Helper()
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
}
func credentialSetup(t *testing.T) *credentialFixture {
	t.Helper()
	dir := t.TempDir()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "unit CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	ca, e = x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	signingPublic, signing, _ := ed25519.GenerateKey(rand.Reader)
	center, _, _ := ed25519.GenerateKey(rand.Reader)
	f := &credentialFixture{issuer: pki.Authority{Certificate: ca, Chain: chain, Key: key}, claims: pki.Claims{Tenant: identifier.New(), Source: identifier.New(), Generation: identifier.New(), Kind: "collector", Collector: identifier.New(), KeyID: identifier.New(), SigningPublic: signingPublic, CenterKeyID: identifier.New(), CenterPublic: center}}
	f.cfg = Config{Listen: "127.0.0.1:0", CenterURL: "https://center.invalid", SourceID: f.claims.Source, Certificate: filepath.Join(dir, "cert.pem"), PrivateKey: filepath.Join(dir, "tls.key"), CA: filepath.Join(dir, "ca.pem"), Spool: filepath.Join(dir, "spool"), CredentialState: filepath.Join(dir, "credentials"), SigningKey: filepath.Join(dir, "signing.key")}
	raw, _ := x509.MarshalPKCS8PrivateKey(signing)
	privateWrite(t, f.cfg.SigningKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}))
	privateWrite(t, f.cfg.CA, chain)
	f.identity, f.tlsKey = f.issue(t)
	privateWrite(t, f.cfg.Certificate, []byte(f.identity.Result.Chain))
	privateWrite(t, f.cfg.PrivateKey, []byte(f.identity.Private))
	return f
}
func (f *credentialFixture) issue(t *testing.T) (machinecred.Identity, ed25519.PrivateKey) {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	der, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if e != nil {
		t.Fatal(e)
	}
	csr, e := x509.ParseCertificateRequest(der)
	if e != nil {
		t.Fatal(e)
	}
	issued, e := f.issuer.Issue(context.Background(), csr, f.claims)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := x509.MarshalPKCS8PrivateKey(key)
	return machinecred.Identity{Result: contracts.EnrollmentResult{SourceID: f.claims.Source, GenerationID: f.claims.Generation, Chain: issued.PEM, Expires: issued.Leaf.NotAfter.UTC(), KeyID: f.claims.KeyID, CenterKeyID: f.claims.CenterKeyID, CenterPublicKey: base64.RawURLEncoding.EncodeToString(f.claims.CenterPublic)}, Private: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}))}, key
}
func TestCollectorCredentialConfigAndCorruptionFailClosed(t *testing.T) {
	f := credentialSetup(t)
	c, e := New(f.cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer c.client.CloseIdleConnections()
	for _, change := range []func(*Config){func(c *Config) { c.SigningKey = "" }, func(c *Config) { c.CredentialState = c.Spool }, func(c *Config) { c.CredentialState = filepath.Join(c.Spool, "credentials") }, func(c *Config) { c.SourceID = identifier.New() }} {
		cfg := f.cfg
		change(&cfg)
		if _, e = New(cfg); e == nil {
			t.Fatal("invalid credential config accepted")
		}
	}
	privateWrite(t, filepath.Join(f.cfg.CredentialState, "tls-identity.json"), []byte(`{}`))
	if _, e = New(f.cfg); e == nil {
		t.Fatal("damaged rotation bundle silently fell back to original certificate")
	}
	if e = os.Remove(filepath.Join(f.cfg.CredentialState, "tls-identity.json")); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(f.cfg.Certificate, filepath.Join(f.cfg.CredentialState, "tls-identity.json")); e != nil {
		t.Fatal(e)
	}
	if _, e = New(f.cfg); e == nil {
		t.Fatal("symlinked credential bundle accepted")
	}
}
func TestCollectorAtomicBothDirectionsAndColdLockRefresh(t *testing.T) {
	f := credentialSetup(t)
	c, e := New(f.cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer c.client.CloseIdleConnections()
	before, _ := c.TLS.GetCertificate(&tls.ClientHelloInfo{})
	transport := c.client.Transport.(*http.Transport)
	outbound, _ := transport.TLSClientConfig.GetClientCertificate(&tls.CertificateRequestInfo{})
	if before != outbound {
		t.Fatal("TLS directions use different providers")
	}
	renewed, _ := f.issue(t)
	raw, _ := json.Marshal(renewed)
	privateWrite(t, filepath.Join(f.cfg.CredentialState, "tls-identity.json"), raw)
	unlock, e := c.lockCredentials()
	if e != nil {
		t.Fatal(e)
	}
	defer unlock()
	after, _ := c.TLS.GetCertificate(&tls.ClientHelloInfo{})
	outbound, _ = transport.TLSClientConfig.GetClientCertificate(&tls.CertificateRequestInfo{})
	if after == before || after != outbound || string(after.Certificate[0]) == string(before.Certificate[0]) {
		t.Fatal("cold lock refresh did not atomically activate current bundle")
	}
	second, e := New(f.cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer second.client.CloseIdleConnections()
	if release, e := second.lockCredentials(); e == nil {
		release()
		t.Fatal("shared credential writer lock not exclusive")
	}
	renewed.Result.GenerationID = identifier.New()
	if e = c.activate(renewed); e == nil {
		t.Fatal("changed generation activated")
	}
	current, _ := c.TLS.GetCertificate(&tls.ClientHelloInfo{})
	if current != after {
		t.Fatal("failed activation changed TLS provider")
	}
}
func TestCollectorRejectsExpiredTLSWithoutFallback(t *testing.T) {
	f := credentialSetup(t)
	block, _ := pem.Decode([]byte(f.identity.Result.Chain))
	leaf, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	leaf.NotBefore = time.Now().Add(-2 * time.Hour)
	leaf.NotAfter = time.Now().Add(-time.Hour)
	der, e := x509.CreateCertificate(rand.Reader, leaf, f.issuer.Certificate, f.tlsKey.Public(), f.issuer.Key)
	if e != nil {
		t.Fatal(e)
	}
	f.identity.Result.Chain = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + string(f.issuer.Chain)
	f.identity.Result.Expires = leaf.NotAfter
	if e = os.MkdirAll(f.cfg.CredentialState, 0700); e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(f.identity)
	privateWrite(t, filepath.Join(f.cfg.CredentialState, "tls-identity.json"), raw)
	if _, e = New(f.cfg); e == nil {
		t.Fatal("expired rotated identity fell back to still-valid original certificate")
	}
}
