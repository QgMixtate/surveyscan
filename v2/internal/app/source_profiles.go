package app

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/pki"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/sourceprofile"
	"net/http"
	"strings"
	"time"
)

func profileETag(c contracts.MachineConfig) string {
	return fmt.Sprintf(`"profile:%s:%s"`, c.SourceID, c.Revision)
}
func (m *MachineAPI) humanProfile(w http.ResponseWriter, r *http.Request) {
	actor, _ := access.Identity(r.Context())
	source := r.PathValue("source_id")
	if len(r.URL.Query()) != 0 {
		access.APIError(w, 400, "INVALID_QUERY")
		return
	}
	var result contracts.SourceProfile
	var e error
	if r.Method == "GET" {
		result, e = m.Sources.Profile(r.Context(), actor, source)
	} else {
		headers := r.Header.Values("If-Match")
		if len(headers) == 0 {
			access.APIError(w, 428, "PRECONDITION_REQUIRED")
			return
		}
		prefix := `"profile:` + source + `:`
		if len(headers) != 1 || !strings.HasPrefix(headers[0], prefix) || !strings.HasSuffix(headers[0], `"`) {
			access.APIError(w, 412, "REVISION_MISMATCH")
			return
		}
		revision := strings.TrimSuffix(strings.TrimPrefix(headers[0], prefix), `"`)
		var options contracts.ProfileOptions
		if !m.decode(w, r, "SourceProfileUpdate", &options) {
			return
		}
		result, e = m.Sources.UpdateProfile(r.Context(), actor, source, revision, options)
	}
	if e != nil {
		m.fail(w, e)
		return
	}
	body, _ := json.Marshal(result)
	if e = m.Sources.Wire.Validate("SourceProfile", body); e != nil {
		m.fail(w, e)
		return
	}
	w.Header().Set("ETag", profileETag(result.Config))
	registryJSON(w, result)
}
func (m *MachineAPI) machineProfile(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		access.APIError(w, 401, "AUTHENTICATION_REQUIRED")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	var frame contracts.ProfileFrame
	if !m.decode(w, r, "ProfileRequest", &frame) {
		return
	}
	payload, e := m.Sources.PollProfile(ctx, pki.Fingerprint(r.TLS.PeerCertificates[0]), frame)
	if e != nil {
		m.fail(w, e)
		return
	}
	raw, _ := json.Marshal(payload)
	message, digest, e := sourceprofile.Message(raw, sourceprofile.ResponseDomain)
	if e != nil {
		m.fail(w, e)
		return
	}
	if m.Uploads == nil {
		m.fail(w, domain.DependencyUnavailable)
		return
	}
	var signature []byte
	if m.Uploads.Signer != nil {
		signature, e = m.Uploads.Signer.Sign(ctx, message)
	} else if len(m.Uploads.Key) == ed25519.PrivateKeySize {
		signature = ed25519.Sign(m.Uploads.Key, message)
	} else {
		e = domain.DependencyUnavailable
	}
	if e != nil {
		m.fail(w, e)
		return
	}
	signed := contracts.ProfileFrame{Payload: raw, Digest: digest, KeyID: m.Uploads.KeyID, Signature: base64.RawURLEncoding.EncodeToString(signature)}
	response, _ := json.Marshal(signed)
	if e = m.Sources.Wire.Validate("SignedProfile", response); e != nil {
		m.fail(w, e)
		return
	}
	registryJSON(w, signed)
}
