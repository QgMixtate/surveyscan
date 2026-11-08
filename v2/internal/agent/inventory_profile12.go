package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/pki"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

type InventoryProfileSelection12 struct {
	Profile contracts.InventoryProfile12
	Raw     []byte
	Limits  wire.InventoryOffer12
}

// FetchInventoryProfile12 is read-only protocol discovery. It neither applies
// policy nor reports it applied; durable acceptance/cache is a separate step.
// Only a fresh result produced by this client's negotiation may be used here.
func (c *Client) FetchInventoryProfile12(ctx context.Context, negotiated InventoryNegotiation12) (InventoryProfileSelection12, error) {
	return c.fetchInventoryProfile12(ctx, negotiated, nil)
}

// fetchInventoryProfile12 передаёт applied только из durable-кэша (см. Sync): центр
// принимает ревизию, которую агент уже сохранил, а не ту, которую только собирается применить.
func (c *Client) fetchInventoryProfile12(ctx context.Context, negotiated InventoryNegotiation12, applied *contracts.InventoryRevision12) (InventoryProfileSelection12, error) {
	var empty InventoryProfileSelection12
	if len(negotiated.proof) == 0 || !negotiated.Expires.After(time.Now()) {
		return empty, errors.New("fresh inventory negotiation required")
	}
	nonce, err := wire.NewInventoryNonce()
	if err != nil {
		return empty, err
	}
	origin := contracts.Origin{SourceID: c.claims.Source, SourceKind: "agent", GenerationID: c.claims.Generation}
	request := contracts.InventoryProfileRequest12{Version: contracts.Version{Major: 1, Minor: 2}, Tenant: c.claims.Tenant, Origin: origin, Nonce: nonce, Sent: time.Now().UTC(), Platform: contracts.InventoryPlatform12, Applied: applied}
	raw, err := wire.SignInventoryProfile12(request, wire.InventoryProfileRequestDomain12, c.claims.KeyID, c.key)
	if err != nil {
		return empty, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", c.cfg.CollectorURL+"/api/v1/machine/inventory-profile", bytes.NewReader(raw))
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
		return empty, errors.New("authenticated inventory profile unavailable")
	}
	peer, err := pki.ClaimsFromCertificate(response.TLS.PeerCertificates[0])
	if err != nil || peer.Kind != "collector" || peer.Tenant != c.claims.Tenant || peer.Source != c.cfg.CollectorSource || peer.Collector != c.claims.Collector {
		return empty, errors.New("inventory profile collector scope mismatch")
	}
	issuer := contracts.Origin{SourceID: peer.Source, SourceKind: "collector", GenerationID: peer.Generation}
	var saved contracts.SignedCollectorInventoryCapabilities
	if json.Unmarshal(negotiated.proof, &saved) != nil {
		return empty, errors.New("inventory negotiation proof unavailable")
	}
	relay, center, err := wire.VerifyCollectorInventoryCapabilities(negotiated.proof, c.claims.Tenant, issuer, origin, saved.Payload.Nonce, peer.KeyID, peer.SigningPublic, c.claims.CenterKeyID, c.claims.CenterPublic)
	if err != nil {
		return empty, err
	}
	relayOffer, _ := wire.CollectorCapabilityOffer(relay)
	centerOffer, _ := wire.CapabilityOffer(center)
	selected, err := wire.NegotiateInventory12(negotiated.own, relayOffer, centerOffer)
	if err != nil || selected != negotiated.Limits || issuer != negotiated.Collector || !relay.Expires.Equal(negotiated.Expires) {
		return empty, errors.New("inventory selection changed")
	}
	raw, err = io.ReadAll(io.LimitReader(response.Body, wire.InventoryProfileMaxBytes12+1))
	if err != nil || len(raw) > wire.InventoryProfileMaxBytes12 {
		return empty, errors.New("inventory profile response exceeds bound")
	}
	profile, err := wire.VerifyInventoryProfile12(raw, c.claims.Tenant, origin, c.claims.Collector, nonce, c.claims.CenterKeyID, c.claims.CenterPublic)
	if err != nil {
		return empty, err
	}
	limits := profile.Config.Limits
	final, err := wire.NegotiateInventory12(selected, wire.InventoryOffer12{Observation12: true, Batch12: true, CanonicalBytes: limits.CanonicalBytes, SignedBytes: limits.SignedBytes, BatchBytes: limits.BatchBytes, Records: limits.Records}, wire.InventoryMaximum12())
	if err != nil {
		return empty, err
	}
	return InventoryProfileSelection12{Profile: profile, Raw: raw, Limits: final}, nil
}
