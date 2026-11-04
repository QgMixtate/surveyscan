package wire

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"time"
)

// VerifyCenterResult принимает только заранее доверенный key, не ключ из receipt.
func (v *Validator) VerifyCenterResult(raw, batchRaw []byte, keyID string, public ed25519.PublicKey) (contracts.SignedCenterResult, bool, error) {
	var signed contracts.SignedCenterResult
	if len(public) != 32 {
		return signed, false, domain.Invalid
	}
	if e := v.Validate("SignedCenterResult", raw); e != nil {
		return signed, false, e
	}
	if e := v.Validate("Batch", batchRaw); e != nil {
		return signed, false, e
	}
	if e := json.Unmarshal(raw, &signed); e != nil {
		return signed, false, e
	}
	var batch contracts.Batch
	if e := json.Unmarshal(batchRaw, &batch); e != nil {
		return signed, false, e
	}
	payload, _ := json.Marshal(signed.Payload)
	canonical, e := Canonical(payload)
	if e != nil {
		return signed, false, e
	}
	sum := sha256.Sum256(canonical)
	signature, e := base64.RawURLEncoding.Strict().DecodeString(signed.Signature)
	if e != nil || signed.KeyID != keyID || signed.Digest != hex.EncodeToString(sum[:]) || !ed25519.Verify(public, append([]byte("SURVEYSCAN-CENTER-RESULT-V1\n"), canonical...), signature) {
		return signed, false, domain.Invalid
	}
	canonical, e = Canonical(batchRaw)
	if e != nil {
		return signed, false, e
	}
	sum = sha256.Sum256(canonical)
	p := signed.Payload
	if p.Version.Major != 1 || p.Version.Minor != 0 || p.TenantID != batch.TenantID || p.DeliveryID != batch.DeliveryID || p.BatchDigest != hex.EncodeToString(sum[:]) || p.CommittedAt.After(time.Now().Add(5*time.Minute)) || len(p.Results) != len(batch.Records) {
		return signed, false, domain.Invalid
	}
	expected := map[string][2]string{}
	for _, record := range batch.Records {
		var s contracts.SignedObservation
		var o contracts.Observation
		if json.Unmarshal(record, &s) != nil || json.Unmarshal(s.Payload, &o) != nil {
			return signed, false, domain.Invalid
		}
		if _, exists := expected[o.ID]; exists {
			return signed, false, domain.Invalid
		}
		expected[o.ID] = [2]string{o.Origin.SourceID, s.Digest}
	}
	remove := true
	for _, r := range p.Results {
		b, ok := expected[r.ObservationID]
		if !ok || b[0] != r.SourceID || b[1] != r.Digest {
			return signed, false, domain.Invalid
		}
		delete(expected, r.ObservationID)
		if r.SpoolAction != "remove" {
			remove = false
		}
	}
	return signed, remove, nil
}
