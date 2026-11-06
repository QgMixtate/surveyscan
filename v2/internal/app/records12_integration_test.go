//go:build integration

package app_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

// This exercises the internal projection with signed synthetic fixtures and real
// FK-bound PG evidence. It is deliberately not a 1.2 HTTP ingest acceptance test.
// The transaction rolls back: runtime admission/audit/outbox remain disabled.
func TestC15PartialProjectionProvenanceAndLegacyIsolation(t *testing.T) {
	f := registrySetup(t)
	baseline := f.ingest(t, f.observation("1"))
	if baseline.AssetID == nil {
		t.Fatal("missing baseline asset")
	}
	asset := *baseline.AssetID
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	oldFacts, oldStates, err := f.registry.Inventory.Detail(f.ctx, tx, tenant, asset)
	if err != nil {
		t.Fatal(err)
	}
	oldDetail, _ := json.Marshal([]any{oldFacts, oldStates})
	var record string
	if err = tx.QueryRow(f.ctx, "SELECT source_record_key::text FROM assets.source_records WHERE tenant_id=$1 AND source_id=$2", tenant, sourceID).Scan(&record); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../../../docs/plans/surveyscan-v2/contracts/C15/fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		ID      string                `json:"id"`
		Payload contracts.Observation `json:"payload"`
	}
	if err = json.Unmarshal(b, &fixtures); err != nil {
		t.Fatal(err)
	}
	o := f.observation("2")
	o.Version.Minor = 2
	for _, fixture := range fixtures {
		if fixture.ID == "all-sections" {
			o.Sections = fixture.Payload.Sections
		}
	}
	if len(o.Sections) != 12 {
		t.Fatal("missing 12-section fixture")
	}
	for i := range o.Sections {
		s := &o.Sections[i]
		s.Status = "partial"
		s.Complete = false
		s.CollectedAt = o.CollectedAt
	}
	// A field missing in the next partial response must keep this evidence ID.
	o.Sections[6].Records[0]["display_name"] = "Original display"
	first := o.ID
	project := func(o contracts.Observation) bool {
		t.Helper()
		var signed contracts.SignedObservation
		if err := json.Unmarshal(f.signed(t, o), &signed); err != nil {
			t.Fatal(err)
		}
		canonical, err := wire.Canonical(signed.Payload)
		if err != nil {
			t.Fatal(err)
		}
		signature, err := base64.RawURLEncoding.DecodeString(signed.Signature)
		if err != nil {
			t.Fatal(err)
		}
		if err = f.registry.Inventory.Record(f.ctx, tx, o, signed, canonical, signature, record, 1); err != nil {
			t.Fatal(err)
		}
		link, err := f.registry.Assets.Link(f.ctx, tx, o, asset)
		if err != nil {
			t.Fatal(err)
		}
		changed, err := f.registry.Inventory.ProjectPartial12(f.ctx, tx, o, asset, link, record, 1)
		if err != nil {
			t.Fatal(err)
		}
		return changed
	}
	if !project(o) {
		t.Fatal("first projection unchanged")
	}
	var count int
	if err = tx.QueryRow(f.ctx, "SELECT count(DISTINCT section_name) FROM inventory.record_facts12 WHERE tenant_id=$1 AND asset_uid=$2", tenant, asset).Scan(&count); err != nil || count != 12 {
		t.Fatal("all sections must retain fields", count, err)
	}
	assertField := func(field, value, id string) {
		t.Helper()
		var got, origin string
		err := tx.QueryRow(f.ctx, "SELECT value#>>'{}',observation_id::text FROM inventory.record_facts12 WHERE tenant_id=$1 AND asset_uid=$2 AND section_name='services' AND field_name=$3", tenant, asset, field).Scan(&got, &origin)
		if err != nil || got != value || origin != id {
			t.Fatal("field lost its own provenance", field, got, origin, err)
		}
	}
	o.ID = identifier.New()
	o.Sequence = "4"
	o.CollectedAt = o.CollectedAt.Add(time.Second)
	for i := range o.Sections {
		o.Sections[i].CollectedAt = o.CollectedAt
	}
	delete(o.Sections[6].Records[0], "display_name")
	o.Sections[6].Records[0]["state"] = "stopped"
	second := o.ID
	if !project(o) {
		t.Fatal("new projection unchanged")
	}
	assertField("state", "stopped", second)
	assertField("display_name", "Original display", first)
	// Arrival of a lower sequence cannot change facts or the last-attempt state.
	o.ID = identifier.New()
	o.Sequence = "3"
	o.Sections[6].Records[0]["state"] = "running"
	if project(o) {
		t.Fatal("older sequence changed projection")
	}
	assertField("state", "stopped", second)
	// An unavailable provider advances the attempt, never clears known facts.
	o.ID = identifier.New()
	o.Sequence = "5"
	o.Sections[6].Status = "unavailable"
	o.Sections[6].Reason = "ACCESS_DENIED"
	o.Sections[6].Records = []map[string]any{}
	o.Sections[6].Count = 0
	if !project(o) {
		t.Fatal("unavailable attempt not recorded")
	}
	assertField("state", "stopped", second)
	assertField("display_name", "Original display", first)
	var status string
	if err = tx.QueryRow(f.ctx, "SELECT last_status FROM inventory.record_section_state12 WHERE tenant_id=$1 AND asset_uid=$2 AND section_name='services'", tenant, asset).Scan(&status); err != nil || status != "unavailable" {
		t.Fatal(status, err)
	}
	// Tenant predicates cannot reveal the same asset UID to another tenant.
	if err = tx.QueryRow(f.ctx, "SELECT count(*) FROM inventory.record_facts12 WHERE tenant_id=$1 AND asset_uid=$2", "00000000-0000-4000-8000-000000000099", asset).Scan(&count); err != nil || count != 0 {
		t.Fatal("tenant isolation", count, err)
	}
	facts, states, err := f.registry.Inventory.Detail(f.ctx, tx, tenant, asset)
	if err != nil {
		t.Fatal(err)
	}
	detail, _ := json.Marshal([]any{facts, states})
	if string(detail) != string(oldDetail) {
		t.Fatal("C09 detail changed after 1.2 projection")
	}
}
