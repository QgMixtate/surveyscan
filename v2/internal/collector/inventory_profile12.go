package collector

import (
	"io"
	"mime"
	"net/http"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

func (c *Collector) inventoryProfile12(w http.ResponseWriter, r *http.Request) {
	peer, err := c.peer(r)
	if err != nil {
		failure(w, 401, "AUTHENTICATION_REQUIRED")
		return
	}
	if r.URL.RawQuery != "" {
		failure(w, 400, "INVALID_QUERY")
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		failure(w, 400, "INVALID_JSON")
		return
	}
	if c.protocol == nil || !c.protocol.Supports12() {
		failure(w, 503, "INVENTORY12_UNAVAILABLE")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, wire.InventoryProfileMaxBytes12))
	if err != nil {
		failure(w, 413, "PAYLOAD_TOO_LARGE")
		return
	}
	frame, request, err := wire.InventoryProfileRequest12(raw)
	if err != nil {
		failure(w, 422, "SCHEMA_INVALID")
		return
	}
	expected := contracts.Origin{SourceID: peer.Source, SourceKind: "agent", GenerationID: peer.Generation}
	if request.Tenant != peer.Tenant || request.Origin != expected || wire.VerifyProfileFrame12(frame, wire.InventoryProfileRequestDomain12, peer.KeyID, peer.SigningPublic) != nil {
		failure(w, 403, "FORBIDDEN")
		return
	}
	status, response, err := c.post(r.Context(), "/api/v1/machine/inventory-profile", raw, "")
	if err != nil {
		failure(w, 503, "CENTER_UNAVAILABLE")
		return
	}
	if status == 200 {
		if _, err = wire.VerifyInventoryProfile12(response, peer.Tenant, expected, peer.Collector, request.Nonce, c.Claims.CenterKeyID, c.Claims.CenterPublic); err != nil {
			failure(w, 503, "INVALID_CENTER_RESPONSE")
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(response)
}
