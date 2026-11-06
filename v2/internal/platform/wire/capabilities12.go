package wire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

const InventoryCapabilitiesDomain = "SURVEYSCAN-INVENTORY-CAPABILITIES-V1\n"
const InventoryCapabilitiesMaxBytes = 65536
const InventoryCapabilitiesLifetime = 5 * time.Minute

var capabilityOnce sync.Once
var capabilitySchemas map[string]*jsonschema.Schema
var capabilitySchemaError error

func capabilitySchema(name string) (*jsonschema.Schema, error) {
	capabilityOnce.Do(func() { capabilitySchemas, capabilitySchemaError = compileCapabilities() })
	if capabilitySchemaError != nil {
		return nil, capabilitySchemaError
	}
	v, ok := capabilitySchemas[name]
	if !ok {
		return nil, domain.Invalid
	}
	return v, nil
}

func compileCapabilities() (map[string]*jsonschema.Schema, error) {
	b, err := contracts.InventoryCapabilityFiles.ReadFile("c15-capabilities.schema.json")
	if err != nil {
		return nil, err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	id := "urn:surveyscan:c15:capabilities:1:0"
	if err = c.AddResource(id, doc); err != nil {
		return nil, err
	}
	out := map[string]*jsonschema.Schema{}
	for _, name := range []string{"Request", "Capabilities", "SignedCapabilities"} {
		out[name], err = c.Compile(id + "#/$defs/" + name)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func validInventoryNonce(nonce string) bool {
	b, err := base64.RawURLEncoding.Strict().DecodeString(nonce)
	return err == nil && len(b) == 32 && len(nonce) == 43
}

func NewInventoryNonce() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func InventoryCapabilityRequest(b []byte) (string, error) {
	v, err := capabilitySchema("Request")
	if err != nil {
		return "", err
	}
	if err = validateTransport12(v, b, 4096); err != nil {
		return "", err
	}
	var out struct {
		Nonce string `json:"nonce"`
	}
	if json.Unmarshal(b, &out) != nil || !validInventoryNonce(out.Nonce) {
		return "", domain.Invalid
	}
	return out.Nonce, nil
}

// CapabilityOffer checks shape/semantics only. Authenticate the signed frame
// with the pretrusted center key before treating this as an authoritative offer.
func CapabilityOffer(p contracts.InventoryCapabilities) (InventoryOffer12, error) {
	zero := InventoryOffer12{}
	if (len(p.Observations) != 1 && len(p.Observations) != 2) || len(p.Observations) != len(p.Batches) || p.Observations[0] != (contracts.Version{Major: 1}) || p.Batches[0] != (contracts.Version{Major: 1}) {
		return zero, domain.Invalid
	}
	obs12 := len(p.Observations) == 2 && p.Observations[1] == (contracts.Version{Major: 1, Minor: 2})
	batch12 := len(p.Batches) == 2 && p.Batches[1] == (contracts.Version{Major: 1, Minor: 2})
	if len(p.Observations) == 2 && (!obs12 || !batch12) || obs12 != batch12 || (p.Limits12 != nil) != obs12 {
		return zero, domain.Invalid
	}
	if !obs12 {
		if len(p.SnapshotModes) != 0 {
			return zero, domain.Invalid
		}
		return zero, nil
	}
	if len(p.SnapshotModes) != 1 || p.SnapshotModes[0] != "partial" {
		return zero, domain.Invalid
	}
	l := p.Limits12
	offer := InventoryOffer12{Observation12: true, Batch12: true, CanonicalBytes: l.CanonicalBytes, SignedBytes: l.SignedBytes, BatchBytes: l.BatchBytes, Records: l.Records}
	if _, err := NegotiateInventory12(offer, offer, offer); err != nil {
		return zero, err
	}
	return offer, nil
}

func capabilityPayload(b []byte) (contracts.InventoryCapabilities, error) {
	var out contracts.InventoryCapabilities
	v, err := capabilitySchema("Capabilities")
	if err != nil {
		return out, err
	}
	if err = validateTransport12(v, b, InventoryCapabilitiesMaxBytes); err != nil {
		return out, err
	}
	if json.Unmarshal(b, &out) != nil || !validInventoryNonce(out.Nonce) {
		return out, domain.Invalid
	}
	now := time.Now()
	if out.Issued.After(now.Add(30*time.Second)) || !out.Expires.After(now) || !out.Expires.After(out.Issued) || out.Expires.Sub(out.Issued) > InventoryCapabilitiesLifetime {
		return out, domain.Invalid
	}
	if _, err = CapabilityOffer(out); err != nil {
		return out, err
	}
	return out, nil
}

func InventoryCapabilityMessage(payload []byte) ([]byte, string, error) {
	if _, err := capabilityPayload(payload); err != nil {
		return nil, "", err
	}
	canonical, err := Canonical(payload)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(canonical)
	return append([]byte(InventoryCapabilitiesDomain), canonical...), hex.EncodeToString(sum[:]), nil
}

// VerifyInventoryCapabilities never derives trust from key material in the frame.
// Audience, nonce and issuer key must come from the authenticated request/session.
func VerifyInventoryCapabilities(raw []byte, tenant string, audience contracts.Origin, nonce, keyID string, public ed25519.PublicKey) (contracts.InventoryCapabilities, error) {
	var empty contracts.InventoryCapabilities
	if len(public) != ed25519.PublicKeySize || !validInventoryNonce(nonce) {
		return empty, domain.Invalid
	}
	v, err := capabilitySchema("SignedCapabilities")
	if err != nil {
		return empty, err
	}
	if err = validateTransport12(v, raw, InventoryCapabilitiesMaxBytes); err != nil {
		return empty, err
	}
	var frame struct {
		Payload   json.RawMessage `json:"payload"`
		Digest    string          `json:"digest"`
		KeyID     string          `json:"key_id"`
		Signature string          `json:"signature"`
	}
	if json.Unmarshal(raw, &frame) != nil {
		return empty, domain.Invalid
	}
	payload, err := capabilityPayload(frame.Payload)
	if err != nil {
		return empty, err
	}
	message, digest, err := InventoryCapabilityMessage(frame.Payload)
	signature, decode := base64.RawURLEncoding.Strict().DecodeString(frame.Signature)
	if err != nil || decode != nil || frame.KeyID != keyID || frame.Digest != digest || payload.Tenant != tenant || payload.Audience != audience || payload.Nonce != nonce || !ed25519.Verify(public, message, signature) {
		return empty, domain.Invalid
	}
	return payload, nil
}
