package wire

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
)

// ErrInventory12Unavailable is retryable for already-staged bytes after a
// configuration downgrade. It must never become a terminal per-record reject.
var ErrInventory12Unavailable = errors.New("inventory1.2 processing unavailable")

type InventoryDecoder struct {
	legacy   *Validator
	extended *InventoryTransport12
}

func NewInventoryDecoder(legacy *Validator, allow12 bool) (*InventoryDecoder, error) {
	if legacy == nil {
		return nil, domain.Invalid
	}
	d := &InventoryDecoder{legacy: legacy}
	if allow12 {
		var err error
		d.extended, err = NewInventoryTransport12(InventoryMaximum12())
		if err != nil {
			return nil, err
		}
	}
	return d, nil
}

func (d *InventoryDecoder) Supports12() bool { return d != nil && d.extended != nil }

func (d *InventoryDecoder) Observation(raw []byte) (contracts.SignedObservation, contracts.Observation, []byte, error) {
	signed, o, canonical, err := d.legacy.Observation(raw)
	if err == nil || d.extended == nil {
		return signed, o, canonical, err
	}
	signed, o, canonical, err = d.extended.Observation(raw)
	if err != nil {
		return signed, o, canonical, err
	}
	// Current12projection has no provider-scoped complete/deletion semantics.
	for _, section := range o.Sections {
		if section.Complete || section.Status == "ok" {
			return signed, o, nil, domain.Invalid
		}
	}
	return signed, o, canonical, nil
}

type DecodedInventoryBatch struct {
	Batch        contracts.Batch
	Observations []contracts.Observation
	Canonical    []byte
}

func (d *InventoryDecoder) Batch(raw []byte) (DecodedInventoryBatch, error) {
	var out DecodedInventoryBatch
	var err error
	if d.legacy.Validate("Batch", raw) == nil {
		if json.Unmarshal(raw, &out.Batch) != nil {
			return out, domain.Invalid
		}
		out.Canonical, err = Canonical(raw)
	} else if d.extended != nil {
		out.Batch, out.Canonical, err = d.extended.Batch(raw)
	} else {
		return out, domain.Invalid
	}
	if err != nil {
		return out, err
	}
	if len(out.Canonical) > 1048576 {
		return out, domain.Invalid
	}
	seen := map[string]bool{}
	for _, raw := range out.Batch.Records {
		signed, o, canonical, err := d.Observation(raw)
		if err != nil {
			return out, err
		}
		sum := sha256.Sum256(canonical)
		if signed.Digest != hex.EncodeToString(sum[:]) || o.TenantID != out.Batch.TenantID || seen[o.ID] {
			return out, domain.Invalid
		}
		seen[o.ID] = true
		out.Observations = append(out.Observations, o)
	}
	return out, nil
}

func (d *InventoryDecoder) VerifyCenterResult(raw, batchRaw []byte, keyID string, public ed25519.PublicKey) (contracts.SignedCenterResult, bool, error) {
	var signed contracts.SignedCenterResult
	if len(public) != ed25519.PublicKeySize {
		return signed, false, domain.Invalid
	}
	if err := d.legacy.Validate("SignedCenterResult", raw); err != nil {
		return signed, false, err
	}
	batch, err := d.Batch(batchRaw)
	if err != nil {
		return signed, false, err
	}
	if json.Unmarshal(raw, &signed) != nil {
		return signed, false, domain.Invalid
	}
	return verifyCenterResult(signed, batch.Batch, batchRaw, keyID, public)
}
