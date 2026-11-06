package agent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/pki"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

// InventoryNegotiation12 is a short-lived, authenticated selection, not a
// command to collect and not permission to rewrite already queued observations.
type InventoryNegotiation12 struct {
	proof     []byte
	own       wire.InventoryOffer12
	Limits    wire.InventoryOffer12
	Expires   time.Time
	Collector contracts.Origin
}

// NegotiateInventory12 does not change the frozen C03 runtime/profile. Callers
// must supply their own supported limits and finish the Windows runtime gates.
func (c *Client) NegotiateInventory12(ctx context.Context, own wire.InventoryOffer12) (InventoryNegotiation12, error) {
	var empty InventoryNegotiation12
	nonce, err := wire.NewInventoryNonce()
	if err != nil {
		return empty, err
	}
	body, err := wire.RecordJSON(map[string]string{"nonce": nonce})
	if err != nil {
		return empty, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", c.cfg.CollectorURL+"/api/v1/machine/inventory-capabilities", bytes.NewReader(body))
	if err != nil {
		return empty, err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(req)
	if err != nil {
		return empty, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 || len(response.TLS.PeerCertificates) == 0 {
		return empty, errors.New("authenticated inventory capabilities unavailable")
	}
	peer, err := pki.ClaimsFromCertificate(response.TLS.PeerCertificates[0])
	if err != nil || peer.Kind != "collector" || peer.Source != c.cfg.CollectorSource || peer.Tenant != c.claims.Tenant || peer.Collector != c.claims.Collector {
		return empty, errors.New("inventory capability collector scope mismatch")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, wire.InventoryCapabilitiesMaxBytes+1))
	if err != nil || len(raw) > wire.InventoryCapabilitiesMaxBytes {
		return empty, errors.New("inventory capability response exceeds limit")
	}
	issuer := contracts.Origin{SourceID: peer.Source, SourceKind: "collector", GenerationID: peer.Generation}
	audience := contracts.Origin{SourceID: c.claims.Source, SourceKind: c.claims.Kind, GenerationID: c.claims.Generation}
	collector, center, err := wire.VerifyCollectorInventoryCapabilities(raw, c.claims.Tenant, issuer, audience, nonce, peer.KeyID, peer.SigningPublic, c.claims.CenterKeyID, c.claims.CenterPublic)
	if err != nil {
		return empty, err
	}
	relayOffer, err := wire.CollectorCapabilityOffer(collector)
	if err != nil {
		return empty, err
	}
	centerOffer, err := wire.CapabilityOffer(center)
	if err != nil {
		return empty, err
	}
	selected, err := wire.NegotiateInventory12(own, relayOffer, centerOffer)
	if err != nil {
		return empty, err
	}
	return InventoryNegotiation12{Limits: selected, Expires: collector.Expires, Collector: issuer, proof: append([]byte(nil), raw...), own: own}, nil
}
