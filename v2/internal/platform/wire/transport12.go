package wire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

// Leave room for signatures, batch metadata and durable spool packet wrappers
// under the existing 1MiB HTTP admission and 1MiB agent spool read limits.
const Inventory12CanonicalBytes = 512 << 10
const Inventory12SignedBytes = 576 << 10
const Inventory12BatchBytes = 768 << 10
const Inventory12BatchRecords = 100

// InventoryOffer12 is supplied only after the caller authenticates the peer and
// binds its capabilities to the intended tenant/source/generation. This library
// neither discovers peers nor turns an unsigned offer into a trust assertion.
type InventoryOffer12 struct {
	Observation12  bool
	Batch12        bool
	CanonicalBytes int
	SignedBytes    int
	BatchBytes     int
	Records        int
}

func InventoryMaximum12() InventoryOffer12 {
	return InventoryOffer12{true, true, Inventory12CanonicalBytes, Inventory12SignedBytes, Inventory12BatchBytes, Inventory12BatchRecords}
}

// NegotiateInventory12 requires support on all three hops. A missing/old peer
// fails closed; it never converts/re-signs pending Windows data into C03/1.0.
func NegotiateInventory12(agent, collector, center InventoryOffer12) (InventoryOffer12, error) {
	out := InventoryMaximum12()
	for _, offer := range []InventoryOffer12{agent, collector, center} {
		if !offer.Observation12 || !offer.Batch12 || offer.CanonicalBytes < 1 || offer.SignedBytes < 1 || offer.BatchBytes < 1 || offer.Records < 1 || offer.CanonicalBytes >= offer.SignedBytes || offer.SignedBytes >= offer.BatchBytes {
			return InventoryOffer12{}, domain.Invalid
		}
		out.CanonicalBytes = min(out.CanonicalBytes, offer.CanonicalBytes)
		out.SignedBytes = min(out.SignedBytes, offer.SignedBytes)
		out.BatchBytes = min(out.BatchBytes, offer.BatchBytes)
		out.Records = min(out.Records, offer.Records)
	}
	return out, nil
}

type InventoryTransport12 struct {
	inventory     *Inventory12Validator
	signed, batch *jsonschema.Schema
	limits        InventoryOffer12
}

func NewInventoryTransport12(limits InventoryOffer12) (*InventoryTransport12, error) {
	selected, err := NegotiateInventory12(limits, limits, limits)
	if err != nil {
		return nil, err
	}
	validator, err := NewInventory12()
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	for _, resource := range []struct {
		file, id string
		files    bool
	}{{"c15.schema.json", "urn:surveyscan:c15:observation:1:2", false}, {"c15-transport.schema.json", "urn:surveyscan:c15:transport:1:2", true}} {
		var b []byte
		if resource.files {
			b, err = contracts.Transport12Files.ReadFile(resource.file)
		} else {
			b, err = contracts.C15Files.ReadFile(resource.file)
		}
		if err != nil {
			return nil, err
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		if err = c.AddResource(resource.id, doc); err != nil {
			return nil, err
		}
	}
	signed, err := c.Compile("urn:surveyscan:c15:transport:1:2#/$defs/SignedObservation")
	if err != nil {
		return nil, err
	}
	batch, err := c.Compile("urn:surveyscan:c15:transport:1:2#/$defs/Batch")
	if err != nil {
		return nil, err
	}
	return &InventoryTransport12{validator, signed, batch, selected}, nil
}

func validateTransport12(schema *jsonschema.Schema, b []byte, maxBytes int) error {
	if len(b) == 0 || len(b) > maxBytes {
		return domain.Invalid
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil || !bounded(doc, 0) || schema.Validate(doc) != nil {
		return domain.Invalid
	}
	if _, err = Canonical(b); err != nil {
		return domain.Invalid
	}
	return nil
}

// Observation validates the envelope/payload/digest, not key ownership or source
// authorization. Verify must receive an authoritative binding before admission.
func (v *InventoryTransport12) Observation(b []byte) (contracts.SignedObservation, contracts.Observation, []byte, error) {
	var signed contracts.SignedObservation
	var o contracts.Observation
	if err := validateTransport12(v.signed, b, v.limits.SignedBytes); err != nil {
		return signed, o, nil, err
	}
	if json.Unmarshal(b, &signed) != nil {
		return signed, o, nil, domain.Invalid
	}
	canonical, err := v.inventory.Payload(signed.Payload)
	if err != nil || len(canonical) > v.limits.CanonicalBytes {
		return signed, o, nil, domain.Invalid
	}
	sum := sha256.Sum256(canonical)
	signature, err := base64.RawURLEncoding.Strict().DecodeString(signed.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || signed.Digest != hex.EncodeToString(sum[:]) || json.Unmarshal(signed.Payload, &o) != nil {
		return signed, o, nil, domain.Invalid
	}
	return signed, o, canonical, nil
}

type InventoryTrust12 struct {
	Tenant    string
	Origin    contracts.Origin
	KeyID     string
	PublicKey ed25519.PublicKey
}

func (v *InventoryTransport12) Verify(b []byte, trust InventoryTrust12) (contracts.Observation, error) {
	signed, o, canonical, err := v.Observation(b)
	if err != nil {
		return contracts.Observation{}, err
	}
	if o.TenantID != trust.Tenant || o.Origin != trust.Origin || signed.KeyID != trust.KeyID || len(trust.PublicKey) != ed25519.PublicKeySize {
		return contracts.Observation{}, domain.Invalid
	}
	signature, _ := base64.RawURLEncoding.Strict().DecodeString(signed.Signature)
	// Minor version is inside the signed canonical payload. Preserve the V1
	// domain separation; no re-signing or mutation is performed by a relay.
	if !ed25519.Verify(trust.PublicKey, append([]byte("SURVEYSCAN-OBSERVATION-V1\n"), canonical...), signature) {
		return contracts.Observation{}, domain.Invalid
	}
	return o, nil
}

func (v *InventoryTransport12) Batch(b []byte) (contracts.Batch, []byte, error) {
	var batch contracts.Batch
	if err := validateTransport12(v.batch, b, v.limits.BatchBytes); err != nil {
		return batch, nil, err
	}
	if json.Unmarshal(b, &batch) != nil || len(batch.Records) > v.limits.Records {
		return batch, nil, domain.Invalid
	}
	seen := map[string]bool{}
	for _, record := range batch.Records {
		_, o, _, err := v.Observation(record)
		if err != nil || o.TenantID != batch.TenantID || seen[o.ID] {
			return batch, nil, domain.Invalid
		}
		seen[o.ID] = true
	}
	canonical, err := Canonical(b)
	if err != nil || len(canonical) > v.limits.BatchBytes {
		return batch, nil, domain.Invalid
	}
	return batch, canonical, nil
}
