package collector

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/diskspool"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

func (c *Collector) inventoryCapabilities(w http.ResponseWriter, r *http.Request) {
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
	request, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil {
		failure(w, 413, "PAYLOAD_TOO_LARGE")
		return
	}
	nonce, err := wire.InventoryCapabilityRequest(request)
	if err != nil {
		failure(w, 400, "INVALID_JSON")
		return
	}
	if len(c.signing) != ed25519.PrivateKeySize {
		failure(w, 503, "TEMPORARILY_UNAVAILABLE")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	code, raw, err := c.post(ctx, "/api/v1/machine/inventory-capabilities", request, "")
	if err != nil || code != 200 {
		failure(w, 503, "TEMPORARILY_UNAVAILABLE")
		return
	}
	issuer := contracts.Origin{SourceID: c.Claims.Source, SourceKind: "collector", GenerationID: c.Claims.Generation}
	center, err := wire.VerifyInventoryCapabilities(raw, c.Claims.Tenant, issuer, nonce, c.Claims.CenterKeyID, c.Claims.CenterPublic)
	if err != nil {
		failure(w, 503, "TEMPORARILY_UNAVAILABLE")
		return
	}
	now := time.Now().UTC()
	p := contracts.CollectorInventoryCapabilities{Version: contracts.Version{Major: 1}, Issuer: issuer, Tenant: c.Claims.Tenant, Audience: contracts.Origin{SourceID: peer.Source, SourceKind: "agent", GenerationID: peer.Generation}, Nonce: nonce, Issued: now, Expires: center.Expires, Observations: []contracts.Version{{Major: 1}}, Batches: []contracts.Version{{Major: 1}}, SnapshotModes: []string{}, Center: raw}
	// A single admitted batch must fit alongside the ACK and packet metadata.
	// Current occupancy is backpressure, not a persistent capability downgrade.
	c.mu.Lock()
	limit := c.Config.Limit
	enabled := c.protocol != nil && c.protocol.Supports12()
	c.mu.Unlock()
	if enabled {
		max := wire.InventoryMaximum12()
		batch := min(max.BatchBytes, int(limit-diskspool.AckReserve-4096))
		signed := min(max.SignedBytes, batch-(64<<10))
		canonical := min(max.CanonicalBytes, signed-(64<<10))
		if canonical < 1 {
			failure(w, 503, "TEMPORARILY_UNAVAILABLE")
			return
		}
		p.Observations = append(p.Observations, contracts.Version{Major: 1, Minor: 2})
		p.Batches = append(p.Batches, contracts.Version{Major: 1, Minor: 2})
		p.Limits12 = &contracts.InventoryLimits12{CanonicalBytes: canonical, SignedBytes: signed, BatchBytes: batch, Records: max.Records}
		p.SnapshotModes = []string{"partial"}
	}
	payload, err := wire.RecordJSON(p)
	if err != nil {
		failure(w, 503, "TEMPORARILY_UNAVAILABLE")
		return
	}
	message, digest, err := wire.CollectorInventoryCapabilityMessage(payload)
	if err != nil {
		failure(w, 503, "TEMPORARILY_UNAVAILABLE")
		return
	}
	frame := contracts.SignedCollectorInventoryCapabilities{Payload: p, Digest: digest, KeyID: c.Claims.KeyID, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(c.signing, message))}
	body, err := wire.RecordJSON(frame)
	if err != nil {
		failure(w, 503, "TEMPORARILY_UNAVAILABLE")
		return
	}
	if _, _, err = wire.VerifyCollectorInventoryCapabilities(body, c.Claims.Tenant, issuer, p.Audience, nonce, c.Claims.KeyID, c.Claims.SigningPublic, c.Claims.CenterKeyID, c.Claims.CenterPublic); err != nil {
		failure(w, 503, "TEMPORARILY_UNAVAILABLE")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(body)
}
