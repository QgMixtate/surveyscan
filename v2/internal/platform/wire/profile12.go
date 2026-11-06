package wire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"sync"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

const InventoryProfileRequestDomain12 = "SURVEYSCAN-INVENTORY-PROFILE-REQUEST-V1-2\n"
const InventoryProfileResponseDomain12 = "SURVEYSCAN-INVENTORY-PROFILE-RESPONSE-V1-2\n"
const InventoryProfileMaxBytes12 = 65536

var profileOnce12 sync.Once
var profileSchemas12 map[string]*jsonschema.Schema
var profileError12 error

func profileSchema12(name string) (*jsonschema.Schema, error) {
	profileOnce12.Do(func() {
		profileSchemas12 = map[string]*jsonschema.Schema{}
		raw, err := contracts.InventoryProfile12Files.ReadFile("c15-profile.schema.json")
		if err != nil {
			profileError12 = err
			return
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			profileError12 = err
			return
		}
		c := jsonschema.NewCompiler()
		c.AssertFormat()
		id := "urn:surveyscan:c15:inventory-profile:1:2"
		if err = c.AddResource(id, doc); err != nil {
			profileError12 = err
			return
		}
		for _, name := range []string{"Config", "Request", "Response", "SignedRequest", "SignedResponse"} {
			schema, err := c.Compile(id + "#/$defs/" + name)
			if err != nil {
				profileError12 = err
				return
			}
			profileSchemas12[name] = schema
		}
	})
	if profileError12 != nil {
		return nil, profileError12
	}
	s, ok := profileSchemas12[name]
	if !ok {
		return nil, domain.Invalid
	}
	return s, nil
}
func ValidateInventoryProfile12(name string, raw []byte) error {
	s, err := profileSchema12(name)
	if err != nil {
		return err
	}
	return validateTransport12(s, raw, InventoryProfileMaxBytes12)
}
func ProfileRevision12(s string) (uint64, error) {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != s {
		return 0, domain.Invalid
	}
	return n, nil
}

// A single packet leaves room for the ACK reserve and its bounded wrapper.
func InventorySpoolOffer12(limit int64) (InventoryOffer12, error) {
	if limit < 524288 || limit > 1073741824 {
		return InventoryOffer12{}, domain.Invalid
	}
	max := InventoryMaximum12()
	batch := min(max.BatchBytes, int(limit-65536-4096))
	signed := min(max.SignedBytes, batch-(64<<10))
	canonical := min(max.CanonicalBytes, signed-(64<<10))
	return NegotiateInventory12(InventoryOffer12{true, true, canonical, signed, batch, max.Records}, max, max)
}
func InventoryConfigFromCommon12(common contracts.MachineConfig) (contracts.InventoryConfig12, error) {
	var empty contracts.InventoryConfig12
	if common.CollectorID == nil {
		return empty, domain.Invalid
	}
	offer, err := InventorySpoolOffer12(common.SpoolBytes)
	if err != nil {
		return empty, err
	}
	c := contracts.InventoryConfig12{SourceID: common.SourceID, CollectorID: *common.CollectorID, Revision: common.Revision, Policy: contracts.InventoryPolicy12, Platform: contracts.InventoryPlatform12, Sections: []string{"identity", "os", "network", "hardware", "software", "updates", "services", "users_groups", "routes_ports", "resources", "protection", "neighbors"}, Heartbeat: common.Heartbeat, Inventory: common.Inventory, Jitter: common.Jitter, SpoolBytes: common.SpoolBytes, WorkerSeconds: 30, CollectionSeconds: 420, SnapshotMode: "partial", Observation: contracts.Version{Major: 1, Minor: 2}, Batch: contracts.Version{Major: 1, Minor: 2}, Limits: contracts.InventoryLimits12{CanonicalBytes: offer.CanonicalBytes, SignedBytes: offer.SignedBytes, BatchBytes: offer.BatchBytes, Records: offer.Records}}
	if err = inventoryConfig12(c); err != nil {
		return empty, err
	}
	return c, nil
}
func inventoryConfig12(c contracts.InventoryConfig12) error {
	raw, err := RecordJSON(c)
	if err != nil {
		return err
	}
	if err = ValidateInventoryProfile12("Config", raw); err != nil {
		return err
	}
	if _, err = ProfileRevision12(c.Revision); err != nil {
		return err
	}
	offer, err := InventorySpoolOffer12(c.SpoolBytes)
	if err != nil {
		return err
	}
	expected := contracts.InventoryLimits12{CanonicalBytes: offer.CanonicalBytes, SignedBytes: offer.SignedBytes, BatchBytes: offer.BatchBytes, Records: offer.Records}
	if c.Limits != expected {
		return domain.Invalid
	}
	return nil
}
func InventoryProfileRequest12(raw []byte) (contracts.ProfileFrame, contracts.InventoryProfileRequest12, error) {
	var frame contracts.ProfileFrame
	var p contracts.InventoryProfileRequest12
	if err := ValidateInventoryProfile12("SignedRequest", raw); err != nil {
		return frame, p, err
	}
	if json.Unmarshal(raw, &frame) != nil || json.Unmarshal(frame.Payload, &p) != nil || !validInventoryNonce(p.Nonce) {
		return frame, p, domain.Invalid
	}
	if p.Applied != nil {
		if _, err := ProfileRevision12(p.Applied.Common); err != nil {
			return frame, p, err
		}
	}
	return frame, p, nil
}
func InventoryProfileResponse12(raw []byte) (contracts.ProfileFrame, contracts.InventoryProfile12, error) {
	var frame contracts.ProfileFrame
	var p contracts.InventoryProfile12
	if err := ValidateInventoryProfile12("SignedResponse", raw); err != nil {
		return frame, p, err
	}
	if json.Unmarshal(raw, &frame) != nil || json.Unmarshal(frame.Payload, &p) != nil || !validInventoryNonce(p.Nonce) {
		return frame, p, domain.Invalid
	}
	if p.Config.SourceID != p.Origin.SourceID || p.Managed != (p.Config.Revision != "1") || !p.Expires.After(p.Issued) || p.Expires.Sub(p.Issued) > 2*time.Minute {
		return frame, p, domain.Invalid
	}
	if err := inventoryConfig12(p.Config); err != nil {
		return frame, p, err
	}
	return frame, p, nil
}
func ProfileMessage12(payload []byte, prefix string) ([]byte, string, error) {
	if prefix != InventoryProfileRequestDomain12 && prefix != InventoryProfileResponseDomain12 {
		return nil, "", domain.Invalid
	}
	canonical, err := Canonical(payload)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(canonical)
	return append([]byte(prefix), canonical...), hex.EncodeToString(sum[:]), nil
}
func SignInventoryProfile12(payload any, prefix, keyID string, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, domain.Invalid
	}
	raw, err := RecordJSON(payload)
	if err != nil {
		return nil, err
	}
	message, digest, err := ProfileMessage12(raw, prefix)
	if err != nil {
		return nil, err
	}
	return RecordJSON(contracts.ProfileFrame{Payload: raw, Digest: digest, KeyID: keyID, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message))})
}
func VerifyProfileFrame12(frame contracts.ProfileFrame, prefix, keyID string, public ed25519.PublicKey) error {
	if len(public) != ed25519.PublicKeySize {
		return domain.Invalid
	}
	message, digest, err := ProfileMessage12(frame.Payload, prefix)
	sig, decode := base64.RawURLEncoding.Strict().DecodeString(frame.Signature)
	if err != nil || decode != nil || frame.KeyID != keyID || frame.Digest != digest || !ed25519.Verify(public, message, sig) {
		return domain.Invalid
	}
	return nil
}

// Only fresh responses may enter through this method. Offline cache is a separate
// durable acceptance path, never a fresh=false switch on network verification.
func VerifyInventoryProfile12(raw []byte, tenant string, origin contracts.Origin, collector, nonce, keyID string, public ed25519.PublicKey) (contracts.InventoryProfile12, error) {
	frame, p, err := InventoryProfileResponse12(raw)
	if err != nil {
		return p, err
	}
	if err = VerifyProfileFrame12(frame, InventoryProfileResponseDomain12, keyID, public); err != nil {
		return contracts.InventoryProfile12{}, err
	}
	now := time.Now()
	if p.Tenant != tenant || p.Origin != origin || p.Config.CollectorID != collector || p.Nonce != nonce || !validInventoryNonce(nonce) || p.Issued.After(now.Add(30*time.Second)) || !p.Expires.After(now) {
		return contracts.InventoryProfile12{}, domain.Invalid
	}
	return p, nil
}
