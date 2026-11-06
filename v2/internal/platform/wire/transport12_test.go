package wire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/contracts"
)

func signedFixture12(t *testing.T) (contracts.Observation, ed25519.PrivateKey, InventoryTrust12) {
	t.Helper()
	var o contracts.Observation
	for _, f := range inventory12Fixtures(t) {
		if f.ID == "all-sections" {
			if err := json.Unmarshal(f.Payload, &o); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(o.Sections) != 12 {
		t.Fatal("missing fixture")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust := InventoryTrust12{Tenant: o.TenantID, Origin: o.Origin, KeyID: "00000000-0000-4000-8000-000000000055", PublicKey: public}
	return o, private, trust
}

func signFixture12(t *testing.T, o contracts.Observation, key ed25519.PrivateKey, keyID string) ([]byte, []byte) {
	t.Helper()
	payload, err := RecordJSON(o)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := Canonical(payload)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonical)
	signature := ed25519.Sign(key, append([]byte("SURVEYSCAN-OBSERVATION-V1\n"), canonical...))
	b, err := RecordJSON(contracts.SignedObservation{Payload: canonical, Digest: hex.EncodeToString(sum[:]), KeyID: keyID, Signature: base64.RawURLEncoding.EncodeToString(signature)})
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSpace(b), canonical
}

func TestInventory12SignedTransportTrustAndLegacyRejection(t *testing.T) {
	v, err := NewInventoryTransport12(InventoryMaximum12())
	if err != nil {
		t.Fatal(err)
	}
	o, key, trust := signedFixture12(t)
	raw, canonical := signFixture12(t, o, key, trust.KeyID)
	parsed, err := v.Verify(raw, trust)
	if err != nil || parsed.ID != o.ID {
		t.Fatal("valid signature/binding rejected", err)
	}
	_, _, got, err := v.Observation(raw)
	if err != nil || !bytes.Equal(got, canonical) {
		t.Fatal("canonical origin bytes changed", err)
	}
	for name, change := range map[string]func(*InventoryTrust12){
		"tenant":     func(t *InventoryTrust12) { t.Tenant = "00000000-0000-4000-8000-000000000099" },
		"source":     func(t *InventoryTrust12) { t.Origin.SourceID = "00000000-0000-4000-8000-000000000099" },
		"generation": func(t *InventoryTrust12) { t.Origin.GenerationID = "00000000-0000-4000-8000-000000000099" },
		"kind":       func(t *InventoryTrust12) { t.Origin.SourceKind = "collector" },
		"key-id":     func(t *InventoryTrust12) { t.KeyID = "00000000-0000-4000-8000-000000000099" },
		"public-key": func(t *InventoryTrust12) { t.PublicKey = make(ed25519.PublicKey, ed25519.PublicKeySize) },
	} {
		t.Run(name, func(t *testing.T) {
			wrong := trust
			change(&wrong)
			if _, err := v.Verify(raw, wrong); err == nil {
				t.Fatal("wrong authoritative binding accepted")
			}
		})
	}
	var envelope contracts.SignedObservation
	if err = json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	forged, _ := RecordJSON(envelope)
	if _, _, _, err = v.Observation(forged); err != nil {
		t.Fatal("parse-only operation unexpectedly authorizes signature", err)
	}
	if _, err = v.Verify(forged, trust); err == nil {
		t.Fatal("forged signature verified")
	}
	envelope.Digest = strings.Repeat("0", 64)
	forged, _ = RecordJSON(envelope)
	if _, _, _, err = v.Observation(forged); err == nil {
		t.Fatal("tampered digest accepted")
	}
	legacy, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = legacy.Observation(raw); err == nil {
		t.Fatal("old peer accepted unnegotiated1.2")
	}
	draft, err := os.ReadFile("../../../../docs/plans/surveyscan-v2/contracts/C15/transport.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	embedded, err := contracts.Transport12Files.ReadFile("c15-transport.schema.json")
	if err != nil || !bytes.Equal(draft, embedded) {
		t.Fatal("transport schema diverged", err)
	}
}

func TestInventory12TransportBatchAndExactByteBounds(t *testing.T) {
	o, key, trust := signedFixture12(t)
	signed, canonical := signFixture12(t, o, key, trust.KeyID)
	batch := contracts.Batch{Version: contracts.Version{Major: 1, Minor: 2}, TenantID: o.TenantID, DeliveryID: "00000000-0000-4000-8000-000000000066", Records: []json.RawMessage{signed}}
	raw, err := RecordJSON(batch)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise all three inclusive byte boundaries with a genuine signature.
	limits := InventoryMaximum12()
	limits.CanonicalBytes = len(canonical)
	limits.SignedBytes = len(signed)
	limits.BatchBytes = len(raw)
	v, err := NewInventoryTransport12(limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = v.Batch(raw); err != nil {
		t.Fatal("exact boundaries rejected", err)
	}
	for _, field := range []string{"canonical", "signed", "batch"} {
		l := limits
		switch field {
		case "canonical":
			l.CanonicalBytes--
		case "signed":
			l.SignedBytes--
		case "batch":
			l.BatchBytes--
		}
		bounded, err := NewInventoryTransport12(l)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err = bounded.Batch(raw); err == nil {
			t.Fatal("one byte beyond negotiated limit accepted", field)
		}
	}
	v, err = NewInventoryTransport12(InventoryMaximum12())
	if err != nil {
		t.Fatal(err)
	}
	batch.Records = append(batch.Records, signed)
	raw, _ = RecordJSON(batch)
	if _, _, err = v.Batch(raw); err == nil {
		t.Fatal("duplicate observation ID accepted")
	}
	o.TenantID = "00000000-0000-4000-8000-000000000099"
	other, _ := signFixture12(t, o, key, trust.KeyID)
	batch.Records = []json.RawMessage{other}
	raw, _ = RecordJSON(batch)
	if _, _, err = v.Batch(raw); err == nil {
		t.Fatal("foreign tenant record accepted")
	}
	batch.Records = []json.RawMessage{signed}
	batch.Version.Minor = 0
	raw, _ = RecordJSON(batch)
	if _, _, err = v.Batch(raw); err == nil {
		t.Fatal("mixed legacy/new batch accepted")
	}
}

func TestInventory12NegotiationRequiresEveryHop(t *testing.T) {
	agent := InventoryMaximum12()
	collector := agent
	center := agent
	collector.CanonicalBytes = 64 << 10
	collector.SignedBytes = 128 << 10
	collector.BatchBytes = 256 << 10
	collector.Records = 2
	selected, err := NegotiateInventory12(agent, collector, center)
	if err != nil || selected != collector {
		t.Fatal("intersection not the smallest hop", err)
	}
	for hop := 0; hop < 3; hop++ {
		offers := []InventoryOffer12{agent, collector, center}
		offers[hop].Batch12 = false
		if _, err = NegotiateInventory12(offers[0], offers[1], offers[2]); err == nil {
			t.Fatal("observation support alone does not negotiate batch1.2", hop)
		}
		offers[hop].Batch12 = true
		offers[hop].Observation12 = false
		if _, err = NegotiateInventory12(offers[0], offers[1], offers[2]); err == nil {
			t.Fatal("old peer silently downgraded1.2", hop)
		}
	}
	larger := agent
	larger.CanonicalBytes *= 2
	larger.SignedBytes *= 2
	larger.BatchBytes *= 2
	larger.Records *= 2
	if effective, err := NegotiateInventory12(larger, larger, larger); err != nil || effective != agent {
		t.Fatal("higher peer ceilings should intersect local maxima", err)
	}
	bad := agent
	bad.CanonicalBytes = 0
	if _, err = NegotiateInventory12(bad, collector, center); err == nil {
		t.Fatal("zero treated as unbounded")
	}
}
