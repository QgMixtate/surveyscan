package sourceprofile

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/pki"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
	"time"
)

const RequestDomain = "SURVEYSCAN-PROFILE-REQUEST-V1\n"
const ResponseDomain = "SURVEYSCAN-PROFILE-V1\n"

func Message(payload []byte, domain string) ([]byte, string, error) {
	canonical, e := wire.Canonical(payload)
	if e != nil {
		return nil, "", e
	}
	sum := sha256.Sum256(canonical)
	return append([]byte(domain), canonical...), hex.EncodeToString(sum[:]), nil
}
func SignRequest(payload contracts.ProfileRequestPayload, keyID string, key ed25519.PrivateKey) (contracts.ProfileFrame, error) {
	raw, e := json.Marshal(payload)
	if e != nil {
		return contracts.ProfileFrame{}, e
	}
	message, digest, e := Message(raw, RequestDomain)
	if e != nil {
		return contracts.ProfileFrame{}, e
	}
	return contracts.ProfileFrame{Payload: raw, Digest: digest, KeyID: keyID, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message))}, nil
}
func Verify(frame contracts.ProfileFrame, prefix, keyID string, public ed25519.PublicKey) error {
	message, digest, e := Message(frame.Payload, prefix)
	if e != nil {
		return e
	}
	sig, e := base64.RawURLEncoding.Strict().DecodeString(frame.Signature)
	if e != nil || len(public) != 32 || frame.KeyID != keyID || frame.Digest != digest || !ed25519.Verify(public, message, sig) {
		return domain.Invalid
	}
	return nil
}
func VerifyResponse(v *wire.Validator, raw []byte, claims pki.Claims, nonce string, fresh bool) (contracts.ProfilePayload, error) {
	var out contracts.ProfilePayload
	if e := v.Validate("SignedProfile", raw); e != nil {
		return out, e
	}
	var frame contracts.ProfileFrame
	_ = json.Unmarshal(raw, &frame)
	if e := Verify(frame, ResponseDomain, claims.CenterKeyID, claims.CenterPublic); e != nil {
		return out, e
	}
	_ = json.Unmarshal(frame.Payload, &out)
	expected := contracts.Origin{SourceID: claims.Source, SourceKind: claims.Kind, GenerationID: claims.Generation}
	if out.Version.Major != 1 || out.Version.Minor != 0 || out.Tenant != claims.Tenant || out.Origin != expected || out.Nonce != nonce || out.Config.SourceID != claims.Source || out.Managed != (out.Config.Revision != "1") {
		return out, domain.Invalid
	}
	if (out.Config.CollectorID == nil) != (claims.Collector == "") || (out.Config.CollectorID != nil && *out.Config.CollectorID != claims.Collector) {
		return out, domain.Invalid
	}
	if !out.Expires.After(out.Issued) || out.Expires.Sub(out.Issued) > 5*time.Minute || (fresh && (!time.Now().Before(out.Expires) || out.Issued.After(time.Now().Add(30*time.Second)))) {
		return out, domain.Invalid
	}
	return out, nil
}
