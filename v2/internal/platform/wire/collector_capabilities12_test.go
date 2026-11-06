package wire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
)

func signCollectorFixture(t *testing.T, p contracts.CollectorInventoryCapabilities, key ed25519.PrivateKey, keyID, domain string) []byte {
	t.Helper()
	body, _ := RecordJSON(p)
	canonical, err := Canonical(body)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonical)
	raw, err := RecordJSON(contracts.SignedCollectorInventoryCapabilities{Payload: p, Digest: hex.EncodeToString(sum[:]), KeyID: keyID, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, append([]byte(domain), canonical...)))})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCollectorCapabilitiesAuthenticateBothRolesAndBindings(t *testing.T) {
	centerPub, centerKey, _ := ed25519.GenerateKey(rand.Reader)
	relayPub, relayKey, _ := ed25519.GenerateKey(rand.Reader)
	center := capabilityFixture()
	center.Observations = append(center.Observations, contracts.Version{Major: 1, Minor: 2})
	center.Batches = append(center.Batches, contracts.Version{Major: 1, Minor: 2})
	center.SnapshotModes = []string{"partial"}
	max := InventoryMaximum12()
	center.Limits12 = &contracts.InventoryLimits12{CanonicalBytes: max.CanonicalBytes, SignedBytes: max.SignedBytes, BatchBytes: max.BatchBytes, Records: max.Records}
	audience := contracts.Origin{SourceID: "00000000-0000-4000-8000-000000000002", SourceKind: "agent", GenerationID: "00000000-0000-4000-8000-000000000003"}
	keyID := center.Tenant
	inner := signCapabilityFixture(t, center, centerKey, keyID, InventoryCapabilitiesDomain)
	base := contracts.CollectorInventoryCapabilities{Version: center.Version, Issuer: center.Audience, Tenant: center.Tenant, Audience: audience, Nonce: center.Nonce, Issued: center.Issued, Expires: center.Expires, Observations: center.Observations, Batches: center.Batches, Limits12: center.Limits12, SnapshotModes: center.SnapshotModes, Center: inner}
	verify := func(raw []byte, issuer, audience contracts.Origin, nonce string, relayPub, centerPub ed25519.PublicKey) error {
		_, _, err := VerifyCollectorInventoryCapabilities(raw, center.Tenant, issuer, audience, nonce, keyID, relayPub, keyID, centerPub)
		return err
	}
	raw := signCollectorFixture(t, base, relayKey, keyID, CollectorInventoryCapabilitiesDomain)
	api, err := contracts.C15API12Files.ReadFile("c15.openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(api))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	id := "urn:surveyscan:c15:capability-api-test"
	if err = compiler.AddResource(id, doc); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(id + "#/components/schemas/SignedCollectorInventoryCapabilities")
	if err != nil {
		t.Fatal(err)
	}
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err = schema.Validate(value); err != nil {
		t.Fatal("published collector capability schema rejects runtime frame", err)
	}

	if err := verify(raw, base.Issuer, audience, base.Nonce, relayPub, centerPub); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*contracts.CollectorInventoryCapabilities){
		"overextended-expiry":     func(p *contracts.CollectorInventoryCapabilities) { p.Expires = p.Expires.Add(time.Second) },
		"outer-predates-center":   func(p *contracts.CollectorInventoryCapabilities) { p.Issued = p.Issued.Add(-time.Second) },
		"wrong-tenant":            func(p *contracts.CollectorInventoryCapabilities) { p.Tenant = audience.SourceID },
		"wrong-issuer-generation": func(p *contracts.CollectorInventoryCapabilities) { p.Issuer.GenerationID = audience.GenerationID },
		"wrong-agent-generation":  func(p *contracts.CollectorInventoryCapabilities) { p.Audience.GenerationID = base.Issuer.GenerationID },
		"wrong-role":              func(p *contracts.CollectorInventoryCapabilities) { p.Audience.SourceKind = "collector" },
		"expired": func(p *contracts.CollectorInventoryCapabilities) {
			p.Issued = p.Issued.Add(-time.Hour)
			p.Expires = p.Expires.Add(-time.Hour)
		},
		"forged-center-under-valid-outer": func(p *contracts.CollectorInventoryCapabilities) {
			bad := center
			bad.Limits12 = &contracts.InventoryLimits12{CanonicalBytes: 1, SignedBytes: 2, BatchBytes: 3, Records: 1}
			p.Center = signCapabilityFixture(t, bad, relayKey, keyID, InventoryCapabilitiesDomain)
		},
		"old-center-nonce": func(p *contracts.CollectorInventoryCapabilities) {
			bad := center
			bad.Nonce, _ = NewInventoryNonce()
			p.Center = signCapabilityFixture(t, bad, centerKey, keyID, InventoryCapabilitiesDomain)
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := base
			mutate(&bad)
			raw := signCollectorFixture(t, bad, relayKey, keyID, CollectorInventoryCapabilitiesDomain)
			if verify(raw, base.Issuer, audience, base.Nonce, relayPub, centerPub) == nil {
				t.Fatal("invalid chain accepted")
			}
		})
	}
	nonce, _ := NewInventoryNonce()
	if verify(raw, base.Issuer, audience, nonce, relayPub, centerPub) == nil {
		t.Fatal("nonce replay")
	}
	if verify(raw, base.Issuer, audience, base.Nonce, centerPub, centerPub) == nil {
		t.Fatal("wrong collector key")
	}
	if verify(raw, base.Issuer, audience, base.Nonce, relayPub, relayPub) == nil {
		t.Fatal("wrong center key")
	}
	wrong := signCollectorFixture(t, base, relayKey, keyID, InventoryCapabilitiesDomain)
	if verify(wrong, base.Issuer, audience, base.Nonce, relayPub, centerPub) == nil {
		t.Fatal("role domain reused")
	}
	// Both valid legacy offers authenticate, but cannot select1.2.
	legacy := capabilityFixture()
	legacy.Issued = center.Issued
	legacy.Expires = center.Expires
	base.Center = signCapabilityFixture(t, legacy, centerKey, keyID, InventoryCapabilitiesDomain)
	raw = signCollectorFixture(t, base, relayKey, keyID, CollectorInventoryCapabilitiesDomain)
	relay, parsed, err := VerifyCollectorInventoryCapabilities(raw, center.Tenant, base.Issuer, audience, base.Nonce, keyID, relayPub, keyID, centerPub)
	if err != nil {
		t.Fatal(err)
	}
	co, _ := CollectorCapabilityOffer(relay)
	ce, _ := CapabilityOffer(parsed)
	if _, err = NegotiateInventory12(max, co, ce); err == nil {
		t.Fatal("old center enabled1.2")
	}
}
