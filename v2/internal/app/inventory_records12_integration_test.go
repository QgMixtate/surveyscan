//go:build integration

package app_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/inventory"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/health"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/messaging"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

func testObservation12(t *testing.T, f *registryFixture, sequence string) contracts.Observation {
	t.Helper()
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
	o := f.observation(sequence)
	o.Version.Minor = 2
	for _, fixture := range fixtures {
		if fixture.ID == "all-sections" {
			o.Sections = fixture.Payload.Sections
		}
	}
	if len(o.Sections) != 12 {
		t.Fatal("missing fixture")
	}
	for i := range o.Sections {
		s := &o.Sections[i]
		s.Status = "partial"
		s.Complete = false
		s.CollectedAt = o.CollectedAt
	}
	return o
}

// Trusted synthetic setup, not production admission: persist a signed fixture
// through internal stores plus genuine commit guards/history/audit/outbox. No
// collector, machine authorization or 1.2 upload endpoint is exercised here.
func commitTestProjection12(t *testing.T, f *registryFixture, asset string, o contracts.Observation) {
	t.Helper()
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	resolved, err := f.registry.Assets.Resolve(f.ctx, tx, o)
	if err != nil || resolved.AssetID != asset {
		t.Fatal("fixture asset mapping", err)
	}
	var signed contracts.SignedObservation
	if err = json.Unmarshal(f.signed(t, o), &signed); err != nil {
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
	if err = f.registry.Inventory.Record(f.ctx, tx, o, signed, canonical, signature, resolved.RecordKey, 1); err != nil {
		t.Fatal(err)
	}
	link, err := f.registry.Assets.Link(f.ctx, tx, o, asset)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.registry.Inventory.ProjectPartial12(f.ctx, tx, o, asset, link, resolved.RecordKey, 1); err != nil {
		t.Fatal(err)
	}
	version, err := f.registry.Assets.Bump(f.ctx, tx, tenant, asset)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.registry.Assets.History(f.ctx, tx, tenant, asset, version, "TEST_PROJECTION", sourceID); err != nil {
		t.Fatal(err)
	}
	if err = f.registry.Audit.Record(f.ctx, tx, tenant, sourceID, "asset.facts_changed.v1", "asset", asset); err != nil {
		t.Fatal(err)
	}
	if err = f.registry.Events.Emit(f.ctx, tx, messaging.Event{Tenant: tenant, Producer: "Assets", Aggregate: "asset", AssetID: asset, Version: version, Type: "asset.facts_changed.v1", Correlation: o.ID, Data: map[string]string{"asset_uid": asset}}); err != nil {
		t.Fatal(err)
	}
	if err = f.registry.Inventory.Result(f.ctx, tx, tenant, inventory.Result{ObservationID: o.ID, AssetID: &asset, Disposition: "applied", Reason: "SOURCE_MAPPING"}); err != nil {
		t.Fatal(err)
	}
	if err = f.registry.Audit.Record(f.ctx, tx, tenant, sourceID, "observation.recorded.v1", "observation", o.ID); err != nil {
		t.Fatal(err)
	}
	if err = f.registry.Events.Emit(f.ctx, tx, messaging.Event{Tenant: tenant, Producer: "Inventory", Aggregate: "observation", AssetID: o.ID, Version: "1", Type: "observation.recorded.v1", Correlation: o.ID, Data: map[string]string{"observation_id": o.ID}}); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
}

func TestC15RecordsHTTPPaginationRevisionAndAuthorization(t *testing.T) {
	f := registrySetup(t)
	asset := *f.ingest(t, f.observation("1")).AssetID
	o := testObservation12(t, f, "2")
	auth, err := access.NewHTTP(f.users, "https://ui.example", false)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := app.NewHTTP(auth, health.Handler(func(context.Context) error { return nil }), f.registry)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	b := newBrowser(t, server)
	path := "/api/v1/assets/" + asset + "/inventory/facts/services"
	code, _, _ := b.request(t, "GET", path, "", "", "", nil)
	expect(t, 401, code)
	b.login(t, "admin")
	code, raw, _ := b.request(t, "GET", path, "", "", "", nil)
	expect(t, 200, code)
	var empty contracts.RecordFactPage12
	if err = json.Unmarshal(raw, &empty); err != nil || empty.Revision != "0" || empty.State != nil || len(empty.Items) != 0 {
		t.Fatal("uncollected section represented as collected", err)
	}
	commitTestProjection12(t, f, asset, o)

	cursor := ""
	seen := map[string]bool{}
	firstCursor := ""
	for pages := 0; pages < 10; pages++ {
		query := "?limit=1"
		if cursor != "" {
			query += "&cursor=" + cursor
		}
		code, raw, _ := b.request(t, "GET", path+query, "", "", "", nil)
		expect(t, 200, code)
		if err = wire.ValidateRecordPage12(raw); err != nil {
			t.Fatal(err)
		}
		var page contracts.RecordFactPage12
		if err = json.Unmarshal(raw, &page); err != nil {
			t.Fatal(err)
		}
		if len(page.Items) != 1 || page.State == nil || page.State.Attempt.Observation != o.ID {
			t.Fatal("page/state lost evidence")
		}
		item := page.Items[0]
		if item.Evidence.Observation != o.ID || seen[item.Record+item.Field] {
			t.Fatal("duplicate or wrong provenance")
		}
		seen[item.Record+item.Field] = true
		if page.NextCursor == nil {
			break
		}
		cursor = *page.NextCursor
		if firstCursor == "" {
			firstCursor = cursor
		}
		if pages == 9 {
			t.Fatal("pagination did not terminate")
		}
	}
	if len(seen) != len(o.Sections[6].Records[0]) || firstCursor == "" {
		t.Fatal("pagination omitted fields")
	}
	for _, suffix := range []string{"?tenant_id=" + tenant, "?limit=0", "?limit=101", "?limit=1&limit=2", "?cursor=", "?cursor=%%%", "?cursor=bad", "?limit=1;cursor=bad"} {
		code, _, _ := b.request(t, "GET", path+suffix, "", "", "", nil)
		expect(t, 400, code)
	}
	code, _, _ = b.request(t, "GET", "/api/v1/assets/"+asset+"/inventory/facts/os?cursor="+firstCursor, "", "", "", nil)
	expect(t, 400, code)
	code, _, _ = b.request(t, "GET", "/api/v1/assets/"+identifier.New()+"/inventory/facts/services", "", "", "", nil)
	expect(t, 404, code)
	o.ID = identifier.New()
	o.Sequence = "3"
	o.Sections[6].Records[0]["state"] = "stopped"
	commitTestProjection12(t, f, asset, o)
	code, raw, _ = b.request(t, "GET", path+"?cursor="+firstCursor, "", "", "", nil)
	expect(t, 409, code)
	var failure map[string]any
	if err = json.Unmarshal(raw, &failure); err != nil || failure["code"] != "PROJECTION_CHANGED" {
		t.Fatal("cursor conflict not explained", err)
	}
	// A tenant has no access to another tenant's asset even with its valid cursor.
	if _, err = f.pool.Exec(f.ctx, "INSERT INTO access.tenants(tenant_id,name,status) VALUES($1,'foreign','active')", otherTenant); err != nil {
		t.Fatal(err)
	}
	if err = f.users.Provision(f.ctx, false, otherTenant, "", "foreign-records", password, "viewer"); err != nil {
		t.Fatal(err)
	}
	foreign := newBrowser(t, server)
	foreign.login(t, "foreign-records")
	code, _, _ = foreign.request(t, "GET", path+"?cursor="+firstCursor, "", "", "", nil)
	expect(t, 404, code)
	if err = f.users.Provision(f.ctx, false, tenant, "", "viewer-records", password, "viewer"); err != nil {
		t.Fatal(err)
	}
	viewer := newBrowser(t, server)
	viewer.login(t, "viewer-records")
	code, _, _ = viewer.request(t, "GET", path, "", "", "", nil)
	expect(t, 200, code)
	if err = f.users.ChangeUser(f.ctx, tenant, "viewer-records", "viewer", false); err != nil {
		t.Fatal(err)
	}
	code, _, _ = viewer.request(t, "GET", path, "", "", "", nil)
	expect(t, 401, code)
}
