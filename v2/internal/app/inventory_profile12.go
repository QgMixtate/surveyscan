package app

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/pki"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

func (m *MachineAPI) inventoryProfile12(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		access.APIError(w, 401, "AUTHENTICATION_REQUIRED")
		return
	}
	if r.URL.RawQuery != "" {
		access.APIError(w, 400, "INVALID_QUERY")
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		access.APIError(w, 400, "INVALID_JSON")
		return
	}
	if m.Uploads == nil || !m.Uploads.Inventory12Enabled() {
		access.APIError(w, 503, "INVENTORY12_UNAVAILABLE")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, wire.InventoryProfileMaxBytes12))
	if err != nil {
		access.APIError(w, 413, "PAYLOAD_TOO_LARGE")
		return
	}
	_, request, err := wire.InventoryProfileRequest12(raw)
	if err != nil {
		access.APIError(w, 422, "SCHEMA_INVALID")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	payload, err := m.Sources.PollInventoryProfile12(ctx, pki.Fingerprint(r.TLS.PeerCertificates[0]), raw)
	if err != nil {
		m.fail(w, err)
		return
	}
	body, err := wire.RecordJSON(payload)
	if err != nil {
		m.fail(w, err)
		return
	}
	message, digest, err := wire.ProfileMessage12(body, wire.InventoryProfileResponseDomain12)
	if err != nil {
		m.fail(w, err)
		return
	}
	var signature []byte
	if m.Uploads.KeyID != m.Sources.CenterKeyID {
		access.APIError(w, 503, "TEMPORARILY_UNAVAILABLE")
		return
	}
	if m.Uploads.Signer != nil {
		signature, err = m.Uploads.Signer.Sign(ctx, message)
	} else if len(m.Uploads.Key) == ed25519.PrivateKeySize {
		signature = ed25519.Sign(m.Uploads.Key, message)
	} else {
		access.APIError(w, 503, "TEMPORARILY_UNAVAILABLE")
		return
	}
	if err != nil {
		m.fail(w, err)
		return
	}
	response, err := wire.RecordJSON(contracts.ProfileFrame{Payload: body, Digest: digest, KeyID: m.Uploads.KeyID, Signature: base64.RawURLEncoding.EncodeToString(signature)})
	if err != nil {
		m.fail(w, err)
		return
	}
	public, err := base64.RawURLEncoding.Strict().DecodeString(m.Sources.CenterPublicKey)
	if err != nil {
		access.APIError(w, 503, "TEMPORARILY_UNAVAILABLE")
		return
	}
	if _, err = wire.VerifyInventoryProfile12(response, payload.Tenant, payload.Origin, payload.Config.CollectorID, request.Nonce, m.Sources.CenterKeyID, public); err != nil {
		access.APIError(w, 503, "TEMPORARILY_UNAVAILABLE")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(response)
}
func (m *MachineAPI) humanInventoryProfile12(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		access.APIError(w, 400, "INVALID_QUERY")
		return
	}
	actor, _ := access.Identity(r.Context())
	result, err := m.Sources.InventoryProfile12View(r.Context(), actor, r.PathValue("source_id"))
	if err != nil {
		m.fail(w, err)
		return
	}
	result.Enabled = m.Uploads != nil && m.Uploads.Inventory12Enabled()
	registryJSON(w, result)
}
