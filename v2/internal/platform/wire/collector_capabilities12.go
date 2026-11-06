package wire

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
)

const CollectorInventoryCapabilitiesDomain = "SURVEYSCAN-COLLECTOR-INVENTORY-CAPABILITIES-V1\n"

func CollectorCapabilityOffer(p contracts.CollectorInventoryCapabilities) (InventoryOffer12, error) {
	return CapabilityOffer(contracts.InventoryCapabilities{Observations: p.Observations, Batches: p.Batches, Limits12: p.Limits12, SnapshotModes: p.SnapshotModes})
}

func collectorCapabilityPayload(raw []byte) (contracts.CollectorInventoryCapabilities, error) {
	var p contracts.CollectorInventoryCapabilities
	schema, err := capabilitySchema("CollectorCapabilities")
	if err != nil {
		return p, err
	}
	if err = validateTransport12(schema, raw, InventoryCapabilitiesMaxBytes); err != nil {
		return p, err
	}
	if json.Unmarshal(raw, &p) != nil || !validInventoryNonce(p.Nonce) {
		return p, domain.Invalid
	}
	now := time.Now()
	if p.Issued.After(now.Add(30*time.Second)) || !p.Expires.After(now) || !p.Expires.After(p.Issued) || p.Expires.Sub(p.Issued) > InventoryCapabilitiesLifetime {
		return p, domain.Invalid
	}
	// The inner signature is authenticated separately with the pinned center key.
	inner, err := capabilitySchema("SignedCapabilities")
	if err != nil {
		return p, err
	}
	if err = validateTransport12(inner, p.Center, InventoryCapabilitiesMaxBytes); err != nil {
		return p, err
	}
	var frame contracts.SignedInventoryCapabilities
	if json.Unmarshal(p.Center, &frame) != nil {
		return p, domain.Invalid
	}
	center := frame.Payload
	if center.Tenant != p.Tenant || center.Nonce != p.Nonce || center.Audience != p.Issuer || p.Expires.After(center.Expires) || p.Issued.Before(center.Issued) {
		return p, domain.Invalid
	}
	if _, err = CollectorCapabilityOffer(p); err != nil {
		return p, err
	}
	return p, nil
}

func CollectorInventoryCapabilityMessage(payload []byte) ([]byte, string, error) {
	if _, err := collectorCapabilityPayload(payload); err != nil {
		return nil, "", err
	}
	canonical, err := Canonical(payload)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(canonical)
	return append([]byte(CollectorInventoryCapabilitiesDomain), canonical...), hex.EncodeToString(sum[:]), nil
}

// VerifyCollectorInventoryCapabilities authenticates both roles independently.
// All expected identities and keys come from verified TLS/enrollment, never body.
func VerifyCollectorInventoryCapabilities(raw []byte, tenant string, issuer, audience contracts.Origin, nonce, collectorKeyID string, collectorPublic ed25519.PublicKey, centerKeyID string, centerPublic ed25519.PublicKey) (contracts.CollectorInventoryCapabilities, contracts.InventoryCapabilities, error) {
	var empty contracts.CollectorInventoryCapabilities
	var center contracts.InventoryCapabilities
	if len(collectorPublic) != ed25519.PublicKeySize || !validInventoryNonce(nonce) {
		return empty, center, domain.Invalid
	}
	schema, err := capabilitySchema("SignedCollectorCapabilities")
	if err != nil {
		return empty, center, err
	}
	if err = validateTransport12(schema, raw, InventoryCapabilitiesMaxBytes); err != nil {
		return empty, center, err
	}
	var frame struct {
		Payload   json.RawMessage `json:"payload"`
		Digest    string          `json:"digest"`
		KeyID     string          `json:"key_id"`
		Signature string          `json:"signature"`
	}
	if json.Unmarshal(raw, &frame) != nil {
		return empty, center, domain.Invalid
	}
	p, err := collectorCapabilityPayload(frame.Payload)
	if err != nil {
		return empty, center, err
	}
	message, digest, err := CollectorInventoryCapabilityMessage(frame.Payload)
	signature, decode := base64.RawURLEncoding.Strict().DecodeString(frame.Signature)
	if err != nil || decode != nil || frame.KeyID != collectorKeyID || frame.Digest != digest || p.Tenant != tenant || p.Issuer != issuer || p.Audience != audience || p.Nonce != nonce || !ed25519.Verify(collectorPublic, message, signature) {
		return empty, center, domain.Invalid
	}
	center, err = VerifyInventoryCapabilities(p.Center, tenant, issuer, nonce, centerKeyID, centerPublic)
	if err != nil {
		return empty, contracts.InventoryCapabilities{}, err
	}
	return p, center, nil
}
