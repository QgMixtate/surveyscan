//go:build integration

package app_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

// Real PostgreSQL/Ed25519/enrolled courier identity, direct service calls using
// its registered fingerprint. This is not a real Windows or network relay run.
func TestC15OptInAdmissionProjectionACKAndReadAPI(t *testing.T) {
	u := uploadSetup(t)
	f := u.f
	o := testObservation12(t, f, "1")
	o.Origin = u.observation("1").Origin
	batch := func(o contracts.Observation) []byte {
		t.Helper()
		raw, err := wire.RecordJSON(contracts.Batch{Version: contracts.Version{Major: 1, Minor: 2}, TenantID: tenant, DeliveryID: identifier.New(), Records: []json.RawMessage{f.signed(t, o)}})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	raw := batch(o)
	if _, err := u.service.Stage(f.ctx, u.fingerprint, raw); !errors.Is(err, domain.Invalid) {
		t.Fatal("default legacy admission accepted1.2", err)
	}
	protocol, err := f.registry.ConfigureInventoryProtocol12(true)
	if err != nil {
		t.Fatal(err)
	}
	if u.service.Inventory12Enabled() {
		t.Fatal("registry alone advertised a working pipeline")
	}
	u.service.Protocol = protocol
	if !u.service.Inventory12Enabled() {
		t.Fatal("matching admission/registry not enabled")
	}
	transport, err := u.service.Stage(f.ctx, u.fingerprint, raw)
	if err != nil {
		t.Fatal(err)
	}
	if transport.SpoolAction != "retain" {
		t.Fatal("transport claimed durable application")
	}
	// An operator restart with12disabled cannot turn staged bytes into a terminal
	// schema reject, consume retries or drop them. Re-enabling resumes processing.
	u.service.Protocol = nil
	if _, err = u.service.Process(f.ctx, u.fingerprint, transport.DeliveryID); !errors.Is(err, wire.ErrInventory12Unavailable) {
		t.Fatal("disabled processor did not retain12", err)
	}
	var claims int
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM imports.processing_claims").Scan(&claims); err != nil || claims != 0 {
		t.Fatal("unavailable protocol consumed a processing attempt", claims, err)
	}
	var retained bool
	if err = f.pool.QueryRow(f.ctx, "SELECT payload IS NOT NULL AND receipt IS NULL FROM imports.delivery_payloads WHERE tenant_id=$1 AND delivery_id=$2", tenant, transport.DeliveryID).Scan(&retained); err != nil || !retained {
		t.Fatal("staged bytes lost on downgrade", err)
	}
	u.service.Protocol = protocol
	receipt, err := u.service.Process(f.ctx, u.fingerprint, transport.DeliveryID)
	if err != nil {
		t.Fatal(err)
	}
	verified, remove, err := protocol.VerifyCenterResult(receipt, raw, u.service.KeyID, u.key.Public().(ed25519.PublicKey))
	if err != nil || !remove || len(verified.Payload.Results) != 1 || verified.Payload.Results[0].Disposition != "applied" || verified.Payload.Results[0].AssetID == nil {
		t.Fatal("signed receipt/batch binding failed", err)
	}
	if verified.Payload.Version != (contracts.Version{Major: 1}) {
		t.Fatal("unchanged receipt contract unexpectedly changed version")
	}
	asset := *verified.Payload.Results[0].AssetID
	var sections int
	if err = f.pool.QueryRow(f.ctx, "SELECT count(DISTINCT section_name) FROM inventory.record_facts12 WHERE tenant_id=$1 AND asset_uid=$2", tenant, asset).Scan(&sections); err != nil || sections != 12 {
		t.Fatal("new sections lost", sections, err)
	}
	page, err := f.registry.InventoryRecordFacts(f.ctx, f.identity, asset, "services", "", 100)
	if err != nil || len(page.Items) == 0 || page.State == nil || page.State.Attempt.Observation != o.ID {
		t.Fatal("versioned read lost admitted evidence", err)
	}
	for _, field := range page.Items {
		if field.Evidence.Observation != o.ID {
			t.Fatal("wrong admitted field provenance")
		}
	}
	legacy, err := f.registry.InventoryDetail(f.ctx, f.identity, asset)
	if err != nil || len(legacy.Facts) != 0 || len(legacy.Sections) != 0 {
		t.Fatal("1.2data polluted legacyC09", err)
	}
	// A cached committed receipt remains readable even with new admission off.
	u.service.Protocol = nil
	cached, err := u.service.Process(f.ctx, u.fingerprint, transport.DeliveryID)
	cachedCanonical, _ := wire.Canonical(cached)
	receiptCanonical, _ := wire.Canonical(receipt)
	if err != nil || !bytes.Equal(cachedCanonical, receiptCanonical) {
		t.Fatal("committed ACK unavailable after disable", err)
	}
	u.service.Protocol = protocol
	if _, err = u.service.Stage(f.ctx, u.fingerprint, raw); err != nil {
		t.Fatal("delivery replay rejected", err)
	}
	// Same signed observation through a fresh delivery must not create new facts.
	duplicate := batch(o)
	tpt, err := u.service.Stage(f.ctx, u.fingerprint, duplicate)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := u.service.Process(f.ctx, u.fingerprint, tpt.DeliveryID)
	if err != nil {
		t.Fatal(err)
	}
	if _, remove, err = protocol.VerifyCenterResult(ack, duplicate, u.service.KeyID, u.key.Public().(ed25519.PublicKey)); err != nil || !remove {
		t.Fatal("observation replay not acknowledged", err)
	}
	// Complete snapshots remain unsupported until provider-scoped deletion exists.
	o.ID = identifier.New()
	o.Sequence = "2"
	o.Sections[6].Status = "ok"
	o.Sections[6].Complete = true
	if _, err = u.service.Stage(f.ctx, u.fingerprint, batch(o)); !errors.Is(err, domain.Invalid) {
		t.Fatal("unimplemented complete snapshot admitted", err)
	}
	var observations int
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM inventory.observations").Scan(&observations); err != nil || observations != 1 {
		t.Fatal("replay/unsupported mode created observations", observations, err)
	}
}
