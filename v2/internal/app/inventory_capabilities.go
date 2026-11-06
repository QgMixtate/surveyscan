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

func (m *MachineAPI) inventoryCapabilities(w http.ResponseWriter, req *http.Request) {
	ctx, cancel := context.WithTimeout(req.Context(), 10*time.Second)
	defer cancel()
	if req.TLS == nil || len(req.TLS.VerifiedChains) == 0 || len(req.TLS.PeerCertificates) == 0 {
		access.APIError(w, 401, "AUTHENTICATION_REQUIRED")
		return
	}
	if req.URL.RawQuery != "" {
		access.APIError(w, 400, "INVALID_QUERY")
		return
	}
	kind, _, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil || kind != "application/json" {
		access.APIError(w, 400, "INVALID_JSON")
		return
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, req.Body, 4096))
	if err != nil {
		access.APIError(w, 413, "PAYLOAD_TOO_LARGE")
		return
	}
	nonce, err := wire.InventoryCapabilityRequest(b)
	if err != nil {
		access.APIError(w, 400, "INVALID_JSON")
		return
	}
	if m.Sources == nil || m.Sources.Pool == nil {
		access.APIError(w, 503, "TEMPORARILY_UNAVAILABLE")
		return
	}
	tx, err := m.Sources.Pool.Begin(ctx)
	if err != nil {
		m.fail(w, err)
		return
	}
	defer tx.Rollback(ctx)
	actor, err := m.Sources.PeerFingerprint(ctx, tx, pki.Fingerprint(req.TLS.PeerCertificates[0]))
	if err != nil {
		m.fail(w, err)
		return
	}
	if actor.Kind != "collector" || actor.Collector == nil {
		access.APIError(w, 403, "FORBIDDEN")
		return
	}
	if err = tx.Commit(ctx); err != nil {
		m.fail(w, err)
		return
	}
	now := time.Now().UTC()
	payload := contracts.InventoryCapabilities{Version: contracts.Version{Major: 1}, Issuer: "center", Tenant: actor.Tenant, Audience: contracts.Origin{SourceID: actor.Source, SourceKind: actor.Kind, GenerationID: actor.Generation}, Nonce: nonce, Issued: now, Expires: now.Add(wire.InventoryCapabilitiesLifetime), Observations: []contracts.Version{{Major: 1}}, Batches: []contracts.Version{{Major: 1}}, SnapshotModes: []string{}}
	// Advertise the handlers actually available, not the draft codec. This is
	// deliberately legacy-only until 1.2 admission/projection is wired together.
	raw, err := wire.RecordJSON(payload)
	if err != nil {
		m.fail(w, err)
		return
	}
	message, digest, err := wire.InventoryCapabilityMessage(raw)
	if err != nil {
		m.fail(w, err)
		return
	}
	if m.Uploads == nil || m.Uploads.KeyID != m.Sources.CenterKeyID {
		access.APIError(w, 503, "TEMPORARILY_UNAVAILABLE")
		return
	}
	var signature []byte
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
	frame := contracts.SignedInventoryCapabilities{Payload: payload, Digest: digest, KeyID: m.Uploads.KeyID, Signature: base64.RawURLEncoding.EncodeToString(signature)}
	raw, err = wire.RecordJSON(frame)
	if err != nil {
		m.fail(w, err)
		return
	}
	public, err := base64.RawURLEncoding.Strict().DecodeString(m.Sources.CenterPublicKey)
	if err != nil {
		access.APIError(w, 503, "TEMPORARILY_UNAVAILABLE")
		return
	}
	if _, err = wire.VerifyInventoryCapabilities(raw, actor.Tenant, payload.Audience, nonce, m.Sources.CenterKeyID, public); err != nil {
		access.APIError(w, 503, "TEMPORARILY_UNAVAILABLE")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(raw)
}
