//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/audit"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/health"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

// C25.02: очередь ручного разбора — привязка, новый актив, отложить; ожидавшие наблюдения применяются к активу.
func TestC25ManualReconciliationQueue(t *testing.T) {
	f := registrySetup(t)
	if _, err := f.registry.ConfigureInventoryProtocol12(true); err != nil {
		t.Fatal(err)
	}
	machine := &sources.MachineService{Pool: f.pool, Audit: audit.Store{}}
	type src struct {
		id, gen string
		key     ed25519.PrivateKey
	}
	newSource := func() src {
		pub, key, _ := ed25519.GenerateKey(rand.Reader)
		s := src{identifier.New(), identifier.New(), key}
		if _, err := machine.RegisterPortable(f.ctx, "console", sources.PortableRegistration{Tenant: tenant, Site: siteID, Scope: scopeID, Source: s.id, Generation: s.gen, PublicKey: pub}); err != nil {
			t.Fatal(err)
		}
		return s
	}
	send := func(s src, seq string, hostname string, c ...contracts.Candidate) (string, string) {
		o := testObservation12(t, f, seq)
		o.Origin = contracts.Origin{SourceID: s.id, SourceKind: "portable", GenerationID: s.gen}
		o.Record = contracts.SourceRecord{Namespace: "host", LocalID: "host:view"}
		o.Clock = "estimated"
		o.Candidates = c
		for i := range o.Sections {
			if o.Sections[i].Name == "identity" {
				o.Sections[i].Records = []map[string]any{{"hostname": hostname}}
			}
		}
		raw, _ := json.Marshal(o)
		r, err := f.registry.ImportPortable(f.ctx, machine, tenant, s.id, portablePackage(t, s.key, s.id, raw))
		if err != nil || len(r.Records) != 1 {
			t.Fatal(err, r)
		}
		return r.Records[0].Disposition, r.Records[0].AssetID
	}
	host := func(v string) contracts.Candidate {
		return contracts.Candidate{Kind: "hostname", Namespace: "hostname.raw", Value: v}
	}
	mu := contracts.Candidate{Kind: "machine_uuid", Namespace: "linux-machine-id", Value: "4c4c4544-0000-1000-8000-" + identifier.New()[24:]}

	a := newSource()
	if d, asset := send(a, "1", "srv-a", mu, host("srv-a")); d != "applied" || asset == "" {
		t.Fatal("first source", d)
	}
	_, a1 := send(a, "2", "srv-a", mu, host("srv-a"))
	b := newSource()
	if d, _ := send(b, "1", "srv-b-view", host("srv-a")); d != "recorded_pending_resolution" {
		t.Fatal("weak-only must be pending", d)
	}
	page, err := f.registry.Conflicts(f.ctx, f.identity, "open", "", 50)
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("open conflicts: %+v %v", page, err)
	}
	item := page.Items[0]
	if item.SourceID != b.id || item.PendingObservations != 1 || len(item.Candidates) != 1 || item.Candidates[0] != a1 || item.ObservedHostname != "srv-a" {
		t.Fatalf("conflict item: %+v", item)
	}
	// неверная ревизия и неизвестное действие отвергаются
	if _, err = f.registry.ResolveConflict(f.ctx, f.identity, item.ID, app.ConflictResolution{Action: "attach", AssetUID: a1, Revision: "99"}); !errors.Is(err, domain.Revision) {
		t.Fatal("stale revision must be rejected", err)
	}
	if _, err = f.registry.ResolveConflict(f.ctx, f.identity, item.ID, app.ConflictResolution{Action: "merge"}); !errors.Is(err, domain.Invalid) {
		t.Fatal("unknown action must be rejected", err)
	}
	// привязка к кандидату: ожидавшее наблюдение применено к активу
	res, err := f.registry.ResolveConflict(f.ctx, f.identity, item.ID, app.ConflictResolution{Action: "attach", AssetUID: a1, Revision: item.Revision})
	if err != nil || res.AssetUID == nil || *res.AssetUID != a1 || res.Replayed != 1 {
		t.Fatalf("attach: %+v %v", res, err)
	}
	var n int
	// ожидавшее наблюдение связано с активом (факты применяются по рангу: оценочные часы другого источника не
	// перезаписывают существующие поля — применение фактов проверяет сценарий create_asset ниже)
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM assets.observation_links l JOIN inventory.observations o USING(tenant_id,observation_id) WHERE l.tenant_id=$1 AND l.asset_uid=$2 AND o.source_id=$3 AND l.reason_code='MANUAL_RECONCILIATION'", tenant, a1, b.id).Scan(&n); err != nil || n != 1 {
		t.Fatal("pending observation must be linked to the asset", n, err)
	}
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM assets.asset_changes WHERE tenant_id=$1 AND asset_uid=$2 AND reason_code='MANUAL_RECONCILIATION'", tenant, a1).Scan(&n); err != nil || n != 1 {
		t.Fatal("operator decision must be in asset history", n, err)
	}
	if _, err = f.registry.ResolveConflict(f.ctx, f.identity, item.ID, app.ConflictResolution{Action: "attach", AssetUID: a1}); !errors.Is(err, domain.Conflict) {
		t.Fatal("resolved conflict must not be resolved twice", err)
	}
	// следующий пакет того же источника идёт к активу напрямую
	if d, asset := send(b, "2", "srv-b-view", host("srv-a")); d != "applied" || asset != a1 {
		t.Fatal("record must stay attached after manual resolution", d, asset)
	}

	// новый актив для записи
	c := newSource()
	send(c, "1", "srv-c", host("srv-a"))
	page, _ = f.registry.Conflicts(f.ctx, f.identity, "open", "", 50)
	if len(page.Items) != 1 {
		t.Fatalf("one open conflict expected: %+v", page.Items)
	}
	res, err = f.registry.ResolveConflict(f.ctx, f.identity, page.Items[0].ID, app.ConflictResolution{Action: "create_asset"})
	if err != nil || res.AssetUID == nil || *res.AssetUID == a1 || res.Replayed != 1 {
		t.Fatalf("create_asset: %+v %v", res, err)
	}
	card := detail(t, f, *res.AssetUID)
	if card.Snapshot.Hostname == nil || *card.Snapshot.Hostname != "srv-c" {
		t.Fatalf("new asset must carry the replayed facts: %+v", card.Snapshot)
	}

	// отложить: запись остаётся без актива
	d := newSource()
	send(d, "1", "srv-d", host("srv-a"))
	page, _ = f.registry.Conflicts(f.ctx, f.identity, "open", "", 50)
	if _, err = f.registry.ResolveConflict(f.ctx, f.identity, page.Items[0].ID, app.ConflictResolution{Action: "dismiss"}); err != nil {
		t.Fatal(err)
	}
	if page, _ = f.registry.Conflicts(f.ctx, f.identity, "dismissed", "", 50); len(page.Items) != 1 || page.Items[0].AssetID != nil || page.Items[0].PendingObservations != 1 {
		t.Fatalf("dismissed: %+v", page.Items)
	}
	if page, _ = f.registry.Conflicts(f.ctx, f.identity, "resolved", "", 50); len(page.Items) != 2 {
		t.Fatalf("resolved: %+v", page.Items)
	}

	// регрессия стенда R-027: каждое наблюдение записи в конфликте создавало новую строку конфликта
	e := newSource()
	var firstRevision string
	for _, seq := range []string{"1", "2", "3"} {
		if d, _ := send(e, seq, "srv-e", host("srv-a")); d != "recorded_pending_resolution" {
			t.Fatal("pending", seq, d)
		}
		if seq == "1" {
			p, _ := f.registry.Conflicts(f.ctx, f.identity, "open", "", 50)
			for _, it := range p.Items {
				if it.SourceID == e.id {
					firstRevision = it.Revision
				}
			}
		}
	}
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM assets.reconciliation_conflicts c JOIN assets.source_records r USING(tenant_id,source_record_key) WHERE c.tenant_id=$1 AND r.source_id=$2 AND c.state='open'", tenant, e.id).Scan(&n); err != nil || n != 1 {
		t.Fatal("one open conflict row per source record expected, got", n, err)
	}
	page, _ = f.registry.Conflicts(f.ctx, f.identity, "open", "", 50)
	if len(page.Items) != 1 || page.Items[0].SourceID != e.id || page.Items[0].PendingObservations != 3 {
		t.Fatalf("queue must show one item with 3 pending observations: %+v", page.Items)
	}
	// те же кандидаты в новых наблюдениях не меняют ревизию: решение по ревизии, открытой до них, проходит (не 409)
	if firstRevision == "" || page.Items[0].Revision != firstRevision {
		t.Fatalf("revision must not change on repeated observations with same candidates: first %q now %q", firstRevision, page.Items[0].Revision)
	}
	if _, err = f.registry.ResolveConflict(f.ctx, f.identity, page.Items[0].ID, app.ConflictResolution{Action: "dismiss", Revision: firstRevision}); err != nil {
		t.Fatal(err)
	}
	// R-027 (решение 4А): «Отложить» держится, пока не изменятся кандидаты — повтор того же конфликта не возвращает его
	openOf := func(s src) int {
		t.Helper()
		var n int
		if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM assets.reconciliation_conflicts c JOIN assets.source_records r USING(tenant_id,source_record_key) WHERE c.tenant_id=$1 AND r.source_id=$2 AND c.state='open'", tenant, s.id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if d, _ := send(e, "4", "srv-e", host("srv-a")); d != "recorded_pending_resolution" || openOf(e) != 0 {
		t.Fatal("dismissed conflict must not reopen on the same candidates", d, openOf(e))
	}
	g := newSource()
	if d, _ := send(g, "1", "srv-g", contracts.Candidate{Kind: "machine_uuid", Namespace: "linux-machine-id", Value: "4c4c4544-0000-1000-8000-" + identifier.New()[24:]}, host("srv-g")); d != "applied" {
		t.Fatal("separate asset for srv-g", d)
	}
	if d, _ := send(e, "5", "srv-e", host("srv-a"), host("srv-g")); d != "recorded_pending_resolution" || openOf(e) != 1 {
		t.Fatal("changed candidates must reopen the dismissed record", d, openOf(e))
	}
	page, _ = f.registry.Conflicts(f.ctx, f.identity, "open", "", 50)
	for _, it := range page.Items {
		if it.SourceID == e.id {
			if _, err = f.registry.ResolveConflict(f.ctx, f.identity, it.ID, app.ConflictResolution{Action: "dismiss"}); err != nil {
				t.Fatal(err)
			}
		}
	}

	// HTTP: чтение — assets:read, решение — сессия с CSRF
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
	br := newBrowser(t, server)
	session := br.login(t, "admin")
	code, raw, _ := br.request(t, "GET", "/api/v1/reconciliation/conflicts?state=resolved", "", "", "", nil)
	expect(t, 200, code)
	var got app.ConflictPage
	if json.Unmarshal(raw, &got) != nil || len(got.Items) != 2 {
		t.Fatalf("http list: %s", raw)
	}
	// ответ соответствует контракту contracts/c25-reconciliation.schema.json (его же проверяет браузер)
	schemaRaw, err := os.ReadFile("../../contracts/c25-reconciliation.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := jsonschema.UnmarshalJSON(strings.NewReader(string(schemaRaw)))
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err = compiler.AddResource("urn:surveyscan:c25:reconciliation:1:0", doc); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("urn:surveyscan:c25:reconciliation:1:0#/$defs/ConflictPage")
	if err != nil {
		t.Fatal(err)
	}
	instance, _ := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
	if err = schema.Validate(instance); err != nil {
		t.Fatal("conflict page violates its contract:", err)
	}
	code, _, _ = br.request(t, "POST", "/api/v1/reconciliation/conflicts/"+got.Items[0].ID+"/resolve", `{"action":"dismiss"}`, "", "https://ui.example", nil)
	expect(t, 403, code) // без CSRF
	code, _, _ = br.request(t, "POST", "/api/v1/reconciliation/conflicts/"+got.Items[0].ID+"/resolve", `{"action":"dismiss"}`, session.CSRFToken, "https://ui.example", nil)
	expect(t, 409, code) // уже решён
}
