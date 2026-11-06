package wire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
)

func capabilityFixture() contracts.InventoryCapabilities {
	uuid := "00000000-0000-4000-8000-000000000001"
	nonce := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	now := time.Now().UTC().Truncate(time.Microsecond)
	return contracts.InventoryCapabilities{Version: contracts.Version{Major: 1}, Issuer: "center", Tenant: uuid, Audience: contracts.Origin{SourceID: uuid, SourceKind: "collector", GenerationID: uuid}, Nonce: nonce, Issued: now, Expires: now.Add(InventoryCapabilitiesLifetime), Observations: []contracts.Version{{Major: 1}}, Batches: []contracts.Version{{Major: 1}}, SnapshotModes: []string{}}
}

// Sign even invalid counterexamples so validation cannot be bypassed merely by
// presenting a frame signed by a trusted but incorrectly configured issuer.
func signCapabilityFixture(t *testing.T, p contracts.InventoryCapabilities, key ed25519.PrivateKey, keyID, domain string) []byte {
	t.Helper()
	payload, err := RecordJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := Canonical(payload)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonical)
	frame := contracts.SignedInventoryCapabilities{Payload: p, Digest: hex.EncodeToString(sum[:]), KeyID: keyID, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, append([]byte(domain), canonical...)))}
	b, err := RecordJSON(frame)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestInventoryCapabilitiesNonceAudienceKeyAndLifetime(t *testing.T) {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := capabilityFixture()
	keyID := p.Tenant
	raw := signCapabilityFixture(t, p, key, keyID, InventoryCapabilitiesDomain)
	parsed, err := VerifyInventoryCapabilities(raw, p.Tenant, p.Audience, p.Nonce, keyID, public)
	if err != nil {
		t.Fatal(err)
	}
	offer, err := CapabilityOffer(parsed)
	if err != nil || offer.Observation12 || offer.Batch12 {
		t.Fatal("legacy handlers advertised1.2", err)
	}
	wrong := p.Audience
	wrong.GenerationID = "00000000-0000-4000-8000-000000000099"
	if _, err = VerifyInventoryCapabilities(raw, p.Tenant, wrong, p.Nonce, keyID, public); err == nil {
		t.Fatal("cross-generation capability replay accepted")
	}
	nonce, err := NewInventoryNonce()
	if err != nil || nonce == p.Nonce {
		t.Fatal("fresh nonce unavailable", err)
	}
	if _, err = VerifyInventoryCapabilities(raw, p.Tenant, p.Audience, nonce, keyID, public); err == nil {
		t.Fatal("old request nonce replay accepted")
	}
	if _, err = VerifyInventoryCapabilities(raw, "00000000-0000-4000-8000-000000000099", p.Audience, p.Nonce, keyID, public); err == nil {
		t.Fatal("cross-tenant capabilities accepted")
	}
	if _, err = VerifyInventoryCapabilities(raw, p.Tenant, p.Audience, p.Nonce, "00000000-0000-4000-8000-000000000099", public); err == nil {
		t.Fatal("untrusted key ID accepted")
	}
	if _, err = VerifyInventoryCapabilities(raw, p.Tenant, p.Audience, p.Nonce, keyID, make(ed25519.PublicKey, 32)); err == nil {
		t.Fatal("wrong public key accepted")
	}
	wrongDomain := signCapabilityFixture(t, p, key, keyID, "SURVEYSCAN-CENTER-RESULT-V1\n")
	if _, err = VerifyInventoryCapabilities(wrongDomain, p.Tenant, p.Audience, p.Nonce, keyID, public); err == nil {
		t.Fatal("receipt domain reused as capabilities")
	}
	for name, mutate := range map[string]func(*contracts.InventoryCapabilities){
		"expired": func(p *contracts.InventoryCapabilities) {
			p.Issued = p.Issued.Add(-time.Hour)
			p.Expires = p.Expires.Add(-time.Hour)
		},
		"long-ttl": func(p *contracts.InventoryCapabilities) { p.Expires = p.Expires.Add(time.Minute) },
		"future": func(p *contracts.InventoryCapabilities) {
			p.Issued = p.Issued.Add(time.Hour)
			p.Expires = p.Expires.Add(time.Hour)
		},
		"partial-advertisement": func(p *contracts.InventoryCapabilities) {
			p.Observations = append(p.Observations, contracts.Version{Major: 1, Minor: 2})
		},
		"limits-without-support": func(p *contracts.InventoryCapabilities) {
			p.Limits12 = &contracts.InventoryLimits12{CanonicalBytes: 1, SignedBytes: 2, BatchBytes: 3, Records: 1}
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := capabilityFixture()
			mutate(&bad)
			raw := signCapabilityFixture(t, bad, key, keyID, InventoryCapabilitiesDomain)
			if _, err := VerifyInventoryCapabilities(raw, bad.Tenant, bad.Audience, bad.Nonce, keyID, public); err == nil {
				t.Fatal("invalid signed capability accepted")
			}
		})
	}
}

func TestInventoryCapabilitiesOptInOfferAndRequestBounds(t *testing.T) {
	p := capabilityFixture()
	p.Observations = append(p.Observations, contracts.Version{Major: 1, Minor: 2})
	p.Batches = append(p.Batches, contracts.Version{Major: 1, Minor: 2})
	limits := InventoryMaximum12()
	p.Limits12 = &contracts.InventoryLimits12{CanonicalBytes: limits.CanonicalBytes, SignedBytes: limits.SignedBytes, BatchBytes: limits.BatchBytes, Records: limits.Records}
	p.SnapshotModes = []string{"partial"}
	raw, err := RecordJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = InventoryCapabilityMessage(raw); err != nil {
		t.Fatal(err)
	}
	if offer, err := CapabilityOffer(p); err != nil || offer != limits {
		t.Fatal("advertised limits lost", err)
	}
	request, _ := RecordJSON(map[string]string{"nonce": p.Nonce})
	if nonce, err := InventoryCapabilityRequest(request); err != nil || nonce != p.Nonce {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{[]byte(`{"nonce":"bad"}`), []byte(`{"nonce":"` + p.Nonce + `","tenant_id":"injected"}`), []byte(`{"nonce":"` + p.Nonce + `","nonce":"` + p.Nonce + `"}`), bytes.Repeat([]byte(" "), 4097)} {
		if _, err := InventoryCapabilityRequest(raw); err == nil {
			t.Fatal("malformed/unbounded capability request accepted")
		}
	}
	a, err := contracts.InventoryCapabilityFiles.ReadFile("c15-capabilities.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../../../../docs/plans/surveyscan-v2/contracts/C15/capabilities.schema.json")
	if err != nil || !bytes.Equal(a, b) {
		t.Fatal("embedded/draft capability schema diverged", err)
	}
}
