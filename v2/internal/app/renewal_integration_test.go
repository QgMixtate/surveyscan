//go:build integration

package app_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/pki"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
	"sync"
	"testing"
	"time"
)

func renewalChallenge(t *testing.T, u *uploadFixture) contracts.Challenge {
	t.Helper()
	out, e := u.sources.Challenges(u.f.ctx, u.fingerprint, contracts.ChallengeRequest{Sources: []string{u.source}, Purpose: "cert_renew"})
	if e != nil {
		t.Fatal(e)
	}
	return out.Challenges[0]
}
func renewalPayload(t *testing.T, u *uploadFixture, c contracts.Challenge) contracts.Renewal {
	t.Helper()
	csr, _, _, _ := csrTLSMaterial(t)
	return contracts.Renewal{Version: contracts.Version{Major: 1}, ID: identifier.New(), Tenant: tenant, Origin: u.observation("1").Origin, Challenge: c.ID, Nonce: c.Nonce, CSR: csr, Sent: time.Now().UTC()}
}
func signedRenewal(t *testing.T, u *uploadFixture, p contracts.Renewal, domain string) []byte {
	t.Helper()
	raw, _ := json.Marshal(p)
	canonical, e := wire.Canonical(raw)
	if e != nil {
		t.Fatal(e)
	}
	digest := sha256.Sum256(canonical)
	req := contracts.RenewRequest{Payload: raw, Digest: hex.EncodeToString(digest[:]), KeyID: u.f.keyID, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(u.f.key, append([]byte(domain), canonical...)))}
	raw, _ = json.Marshal(req)
	return raw
}
func TestC11RenewalConcurrentReplayAndPreservedOrigin(t *testing.T) {
	u := uploadSetup(t)
	c := renewalChallenge(t, u)
	p := renewalPayload(t, u, c)
	raw := signedRenewal(t, u, p, "SURVEYSCAN-RENEWAL-V1\n")
	var wg sync.WaitGroup
	results := make(chan contracts.EnrollmentResult, 12)
	errs := make(chan error, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, e := u.sources.Renew(u.f.ctx, u.fingerprint, raw)
			if e != nil {
				errs <- e
			} else {
				results <- result
			}
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	chain := ""
	for result := range results {
		if chain != "" && chain != result.Chain {
			t.Fatal("replay minted new certificate")
		}
		chain = result.Chain
		if result.SourceID != u.source || result.GenerationID != u.generation || result.KeyID != u.f.keyID {
			t.Fatal("origin changed")
		}
	}
	block, _ := pem.Decode([]byte(chain))
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	claims, e := pki.ClaimsFromCertificate(cert)
	if e != nil || claims.Source != u.source || claims.Generation != u.generation || !ed25519.PublicKey(claims.SigningPublic).Equal(u.f.key.Public()) {
		t.Fatal("attestation changed", e)
	}
	csr, _, e := pki.ParseCSR(p.CSR)
	if e != nil {
		t.Fatal(e)
	}
	actual, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
	expected, _ := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if string(actual) != string(expected) {
		t.Fatal("CSR key not bound")
	}
	if _, e = u.sources.Config(u.f.ctx, pki.Fingerprint(cert)); e != nil {
		t.Fatal("renewed credential unusable", e)
	}
	count(t, u.f, "sources.renewal_receipts", 1)
	count(t, u.f, "sources.machine_identities", 2)
	count(t, u.f, "sources.ingest_bindings", 2)
	p.CSR, _, _, _ = csrTLSMaterial(t)
	if _, e = u.sources.Renew(u.f.ctx, u.fingerprint, signedRenewal(t, u, p, "SURVEYSCAN-RENEWAL-V1\n")); !errors.Is(e, domain.Conflict) {
		t.Fatal("ID changed digest allowed", e)
	}
	p.ID = identifier.New()
	if _, e = u.sources.Renew(u.f.ctx, u.fingerprint, signedRenewal(t, u, p, "SURVEYSCAN-RENEWAL-V1\n")); !errors.Is(e, domain.Conflict) {
		t.Fatal("consumed challenge reused", e)
	}
}
func TestC11RenewalPurposeProofExpiryAndRevoke(t *testing.T) {
	u := uploadSetup(t)
	heartbeat := heartbeatChallenge(t, u)
	p := renewalPayload(t, u, heartbeat)
	if _, e := u.sources.Renew(u.f.ctx, u.fingerprint, signedRenewal(t, u, p, "SURVEYSCAN-RENEWAL-V1\n")); !errors.Is(e, domain.Conflict) {
		t.Fatal("heartbeat challenge renewed certificate", e)
	}
	c := renewalChallenge(t, u)
	p = renewalPayload(t, u, c)
	if _, e := u.sources.Renew(u.f.ctx, u.fingerprint, signedRenewal(t, u, p, "SURVEYSCAN-HEARTBEAT-V1\n")); !errors.Is(e, domain.Invalid) {
		t.Fatal("wrong signature domain allowed", e)
	}
	raw := signedRenewal(t, u, p, "SURVEYSCAN-RENEWAL-V1\n")
	var req contracts.RenewRequest
	_ = json.Unmarshal(raw, &req)
	p.CSR, _, _, _ = csrTLSMaterial(t)
	req.Payload, _ = json.Marshal(p)
	forged, _ := json.Marshal(req)
	if _, e := u.sources.Renew(u.f.ctx, u.fingerprint, forged); !errors.Is(e, domain.Invalid) {
		t.Fatal("relay substituted CSR", e)
	}
	if _, e := u.f.pool.Exec(u.f.ctx, "UPDATE sources.renewal_challenges SET issued_at=clock_timestamp()-interval '3 minutes',expires_at=clock_timestamp()-interval '1 minute'"); e != nil {
		t.Fatal(e)
	}
	if _, e := u.sources.Renew(u.f.ctx, u.fingerprint, raw); !errors.Is(e, domain.Conflict) {
		t.Fatal("expired challenge allowed", e)
	}
	c = renewalChallenge(t, u)
	p = renewalPayload(t, u, c)
	raw = signedRenewal(t, u, p, "SURVEYSCAN-RENEWAL-V1\n")
	result, e := u.sources.Renew(u.f.ctx, u.fingerprint, raw)
	if e != nil {
		t.Fatal(e)
	}
	if e = u.sources.Revoke(u.f.ctx, u.f.identity, u.source); e != nil {
		t.Fatal(e)
	}
	if _, e = u.sources.Renew(u.f.ctx, u.fingerprint, raw); !errors.Is(e, domain.Unauthorized) {
		t.Fatal("revoked identity replay accepted", e)
	}
	block, _ := pem.Decode([]byte(result.Chain))
	cert, _ := x509.ParseCertificate(block.Bytes)
	if _, e = u.sources.Config(u.f.ctx, pki.Fingerprint(cert)); !errors.Is(e, domain.Unauthorized) {
		t.Fatal("renewed credential survived source revoke", e)
	}
	count(t, u.f, "sources.renewal_receipts", 1)
}
func TestC11RenewalExpiredPeerAndTenantIsolation(t *testing.T) {
	u := uploadSetup(t)
	c := renewalChallenge(t, u)
	p := renewalPayload(t, u, c)
	p.Tenant = identifier.New()
	if _, e := u.sources.Renew(u.f.ctx, u.fingerprint, signedRenewal(t, u, p, "SURVEYSCAN-RENEWAL-V1\n")); !errors.Is(e, domain.Unauthorized) {
		t.Fatal("tenant substitution accepted", e)
	}
	p.Tenant = tenant
	if _, e := u.f.pool.Exec(u.f.ctx, "UPDATE sources.machine_identities SET expires_at=clock_timestamp()-interval '1 minute' WHERE fingerprint=$1", u.fingerprint); e != nil {
		t.Fatal(e)
	}
	if _, e := u.sources.Renew(u.f.ctx, u.fingerprint, signedRenewal(t, u, p, "SURVEYSCAN-RENEWAL-V1\n")); !errors.Is(e, domain.Unauthorized) {
		t.Fatal("expired peer renewed", e)
	}
	count(t, u.f, "sources.renewal_receipts", 0)
}
