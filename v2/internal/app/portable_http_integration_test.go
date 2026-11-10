//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/audit"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/health"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

// C23.03 HTTPS-путь: загрузка portable-пакета через API с авторизацией пользователя.
func TestC23PortableHTTPImport(t *testing.T) {
	f := registrySetup(t)
	if _, err := f.registry.ConfigureInventoryProtocol12(true); err != nil {
		t.Fatal(err)
	}
	machine := &sources.MachineService{Pool: f.pool, Audit: audit.Store{}}
	f.registry.Machine = &app.MachineAPI{Sources: machine}
	if err := f.users.Provision(f.ctx, false, tenant, "", "viewer", password, "viewer"); err != nil {
		t.Fatal(err)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	source, generation := identifier.New(), identifier.New()
	if _, err := machine.RegisterPortable(f.ctx, "console", sources.PortableRegistration{Tenant: tenant, Site: siteID, Scope: scopeID, Source: source, Generation: generation, PublicKey: pub}); err != nil {
		t.Fatal(err)
	}
	pkg := string(portablePackage(t, key, source,
		portableObservation(t, f, source, generation, "host:http-audited", "1"),
		portableObservation(t, f, source, generation, "host:http-audited", "2")))

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
	path := "/api/v1/sources/" + source + "/portable-import"
	zipHdr := map[string]string{"Content-Type": "application/zip"}

	anon := newBrowser(t, server)
	code, _, _ := anon.request(t, "POST", path, pkg, "", "https://ui.example", zipHdr)
	expect(t, 401, code)

	viewer := newBrowser(t, server)
	vs := viewer.login(t, "viewer")
	code, _, _ = viewer.request(t, "POST", path, pkg, vs.CSRFToken, "https://ui.example", zipHdr)
	expect(t, 403, code)

	b := newBrowser(t, server)
	s := b.login(t, "admin")
	code, _, _ = b.request(t, "POST", path, pkg, "", "https://ui.example", zipHdr) // без CSRF
	expect(t, 403, code)
	code, _, _ = b.request(t, "POST", path, pkg, s.CSRFToken, "https://ui.example", nil) // application/json
	expect(t, 415, code)
	code, _, _ = b.request(t, "POST", path, "not a zip", s.CSRFToken, "https://ui.example", zipHdr)
	expect(t, 422, code)
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	forged := string(portablePackage(t, otherKey, source, portableObservation(t, f, source, generation, "host:http-audited", "3")))
	code, _, _ = b.request(t, "POST", path, forged, s.CSRFToken, "https://ui.example", zipHdr)
	expect(t, 422, code)
	code, _, _ = b.request(t, "POST", "/api/v1/sources/"+identifier.New()+"/portable-import", pkg, s.CSRFToken, "https://ui.example", zipHdr)
	expect(t, 404, code)
	if n := countObservations(t, f, source); n != 0 {
		t.Fatal("rejected uploads must not store observations:", n)
	}

	// бюджет исчерпан до начала — ни одна запись не обработана, остаток сообщён; повтор продолжит
	part, err := f.registry.ImportPortableUntil(f.ctx, machine, tenant, source, []byte(pkg), time.Now().Add(-time.Second))
	if err != nil || part.Complete || part.Remaining != 2 || len(part.Records) != 0 || countObservations(t, f, source) != 0 {
		t.Fatalf("exhausted budget must stop before records: %+v %v", part, err)
	}
	code, raw, _ := b.request(t, "POST", path, pkg, s.CSRFToken, "https://ui.example", zipHdr)
	expect(t, 200, code)
	var report app.PortableReport
	if err = json.Unmarshal(raw, &report); err != nil || report.SourceID != source || len(report.Records) != 2 || !report.Complete || report.Remaining != 0 {
		t.Fatalf("report: %s %v", raw, err)
	}
	for _, r := range report.Records {
		if r.Disposition != "applied" || r.AssetID == "" {
			t.Fatalf("record must be applied: %+v", r)
		}
	}
	// повтор (оборванная загрузка) — без дублей
	code, raw, _ = b.request(t, "POST", path, pkg, s.CSRFToken, "https://ui.example", zipHdr)
	expect(t, 200, code)
	if err = json.Unmarshal(raw, &report); err != nil || len(report.Records) != 2 || report.Records[0].Disposition != "duplicate" || report.Records[1].Disposition != "duplicate" {
		t.Fatalf("repeat must be duplicate: %s", raw)
	}
	if n := countObservations(t, f, source); n != 2 {
		t.Fatal("observations stored:", n)
	}
	var audited int
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM audit.audit_events WHERE tenant_id=$1 AND action='source.portable_imported' AND object_id=$2 AND actor_ref<>'console'", tenant, source).Scan(&audited); err != nil || audited != 2 {
		t.Fatal("each accepted upload must be audited with the user:", audited, err)
	}
}
