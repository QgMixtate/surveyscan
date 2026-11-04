//go:build integration

package app_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/health"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

func detail(t *testing.T, f *registryFixture, uid string) contracts.InventoryDetail {
	t.Helper()
	v, e := f.registry.InventoryDetail(f.ctx, f.identity, uid)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func TestC09DetailRetainsPerFactOriginAndFailedAttempt(t *testing.T) {
	f := registrySetup(t)
	first := f.observation("1")
	uid := *f.ingest(t, first).AssetID
	before := detail(t, f, uid)
	if len(before.Sources) != 1 || before.Sources[0].LastInventory == nil || before.Sources[0].LastContact != nil || before.Accountable.Name == "" {
		t.Fatal("missing source/owner summary")
	}
	mac := false
	ip := false
	for _, fact := range before.Facts {
		if fact.Section == "network" {
			if fact.Interface == nil || *fact.Interface != "eth0" || fact.Evidence.Observation != first.ID || !fact.Evidence.Collected.Equal(first.Sections[2].CollectedAt) {
				t.Fatal("network provenance lost")
			}
			mac = mac || fact.Value == "aa:bb:cc:dd:ee:ff"
			ip = ip || strings.Contains(fact.Value, "192.0.2.1")
		}
	}
	if !mac || !ip {
		t.Fatal("missing network facts")
	}
	failed := f.observation("2")
	failed.Sections[2].Status = "unavailable"
	failed.Sections[2].Complete = false
	failed.Sections[2].Reason = "ACCESS_DENIED"
	failed.Sections[2].Count = 0
	failed.Sections[2].Records = []map[string]any{}
	f.ingest(t, failed)
	after := detail(t, f, uid)
	for _, fact := range after.Facts {
		if fact.Section == "network" && fact.Evidence.Observation != first.ID {
			t.Fatal("failure replaced current fact provenance")
		}
	}
	found := false
	for _, s := range after.Sections {
		if s.Name == "network" {
			found = true
			if s.Status != "unavailable" || s.Attempt == nil || s.Success == nil || s.Attempt.Observation != failed.ID || s.Success.Observation != first.ID {
				t.Fatal("attempt/success conflated")
			}
		}
	}
	if !found {
		t.Fatal("missing network state")
	}
	if !after.Sources[0].LastInventory.Equal(*before.Sources[0].LastInventory) {
		t.Fatal("failed inventory advanced source success")
	}
	empty := f.observation("3")
	empty.Sections[2].Count = 0
	empty.Sections[2].Records = []map[string]any{}
	f.ingest(t, empty)
	for _, fact := range detail(t, f, uid).Facts {
		if fact.Section == "network" {
			t.Fatal("complete empty snapshot did not clear network")
		}
	}
}
func TestC09DetailHTTPRejectsForeignRevokedAndAnonymous(t *testing.T) {
	f := registrySetup(t)
	uid := *f.ingest(t, f.observation("1")).AssetID
	h, e := access.NewHTTP(f.users, "https://ui.example", false)
	if e != nil {
		t.Fatal(e)
	}
	handler, e := app.NewHTTP(h, health.Handler(func(context.Context) error { return nil }), f.registry)
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	b := newBrowser(t, server)
	path := "/api/v1/assets/" + uid + "/inventory"
	code, _, _ := b.request(t, "GET", path, "", "", "", nil)
	expect(t, 401, code)
	b.login(t, "admin")
	code, raw, _ := b.request(t, "GET", path, "", "", "", nil)
	expect(t, 200, code)
	if e = f.registry.Wire.Validate("InventoryDetail", raw); e != nil {
		t.Fatal(e)
	}
	code, _, _ = b.request(t, "GET", path+"?tenant_id="+otherTenant, "", "", "", nil)
	expect(t, 400, code)
	code, _, _ = b.request(t, "GET", "/api/v1/assets/"+identifier.New()+"/inventory", "", "", "", nil)
	expect(t, 404, code)
	if _, e = f.pool.Exec(f.ctx, "INSERT INTO access.tenants(tenant_id,name,status) VALUES($1,'other','active')", otherTenant); e != nil {
		t.Fatal(e)
	}
	if e = f.users.Provision(f.ctx, false, otherTenant, "", "foreign-inventory", password, "viewer"); e != nil {
		t.Fatal(e)
	}
	foreign := newBrowser(t, server)
	foreign.login(t, "foreign-inventory")
	code, _, _ = foreign.request(t, "GET", path, "", "", "", nil)
	expect(t, 404, code)
	if e = f.users.Provision(f.ctx, false, tenant, "", "viewer-inventory", password, "viewer"); e != nil {
		t.Fatal(e)
	}
	viewer := newBrowser(t, server)
	viewer.login(t, "viewer-inventory")
	code, _, _ = viewer.request(t, "GET", path, "", "", "", nil)
	expect(t, 200, code)
	if e = f.users.ChangeUser(f.ctx, tenant, "viewer-inventory", "viewer", false); e != nil {
		t.Fatal(e)
	}
	code, _, _ = viewer.request(t, "GET", path, "", "", "", nil)
	expect(t, 401, code)
}
func TestC09SourceSuccessCannotAdvanceByLateOrUntrustedObservation(t *testing.T) {
	f := registrySetup(t)
	first := f.observation("1")
	uid := *f.ingest(t, first).AssetID
	before := detail(t, f, uid)
	late := f.observation("2")
	late.CollectedAt = first.CollectedAt.Add(-time.Hour)
	for i := range late.Sections {
		late.Sections[i].CollectedAt = late.CollectedAt
	}
	f.ingest(t, late)
	unknown := f.observation("3")
	unknown.Clock = "unknown"
	f.ingest(t, unknown)
	after := detail(t, f, uid)
	if !before.Sources[0].LastInventory.Equal(*after.Sources[0].LastInventory) {
		t.Fatal("source inventory summary advanced by late/untrusted data")
	}
	raw, _ := json.Marshal(after)
	if strings.Contains(string(raw), "signing_public_key") || strings.Contains(string(raw), "signature") {
		t.Fatal("raw identity material exposed")
	}
}
