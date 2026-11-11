//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/audit"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/health"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// C26.02–C26.04: класс актива (наблюдаемый и ручной, сбор не затирает ручной), ПО с курсорной пагинацией и
// поиском по тенанту, компоненты с provenance, сервисы и связи (ревизии, дубли, недопустимые сочетания, вывод
// сервиса, перенос при слиянии), межтенантный запрет; каждый ответ — по контракту c26-cmdb.schema.json.
func TestC26CMDB(t *testing.T) {
	f := registrySetup(t)
	if _, err := f.registry.ConfigureInventoryProtocol12(true); err != nil {
		t.Fatal(err)
	}
	machine := &sources.MachineService{Pool: f.pool, Audit: audit.Store{}}
	type host struct {
		source, generation string
		key                ed25519.PrivateKey
		sequence           int
	}
	newHost := func() *host {
		pub, key, _ := ed25519.GenerateKey(rand.Reader)
		h := &host{source: identifier.New(), generation: identifier.New(), key: key}
		if _, err := machine.RegisterPortable(f.ctx, "console", sources.PortableRegistration{Tenant: tenant, Site: siteID, Scope: scopeID, Source: h.source, Generation: h.generation, PublicKey: pub}); err != nil {
			t.Fatal(err)
		}
		return h
	}
	mu := func() contracts.Candidate {
		return contracts.Candidate{Kind: "machine_uuid", Namespace: "linux-machine-id", Value: "4c4c4544-0000-1000-8000-" + identifier.New()[24:]}
	}
	send := func(h *host, local string, candidate contracts.Candidate, packages int, model string) string {
		h.sequence++
		o := testObservation12(t, f, strconv.Itoa(h.sequence))
		o.Origin = contracts.Origin{SourceID: h.source, SourceKind: "portable", GenerationID: h.generation}
		o.Record = contracts.SourceRecord{Namespace: "host", LocalID: local}
		o.Clock = "estimated"
		o.Candidates = []contracts.Candidate{candidate}
		for i := range o.Sections {
			switch o.Sections[i].Name {
			case "software":
				records := make([]map[string]any, packages)
				for p := range records {
					records[p] = map[string]any{"name": fmt.Sprintf("Пакет-%03d", p), "version": "1." + strconv.Itoa(p%3), "vendor": "Поставщик", "scope": "machine", "source": "uninstall_registry", "registry_view": "64", "registry_key": fmt.Sprintf("k-%03d", p)}
				}
				o.Sections[i].Records, o.Sections[i].Count = records, packages
			case "hardware":
				o.Sections[i].Records = []map[string]any{{"kind": "memory", "name": "RAM", "bytes": 8589934592}, {"kind": "bios", "name": "BIOS 1.0", "vendor": "Microsoft Corporation", "model": model}}
				o.Sections[i].Count = 2
			}
		}
		raw, _ := json.Marshal(o)
		report, err := f.registry.ImportPortable(f.ctx, machine, tenant, h.source, portablePackage(t, h.key, h.source, raw))
		if err != nil || len(report.Records) != 1 || report.Records[0].Disposition != "applied" {
			t.Fatal(err, report)
		}
		return report.Records[0].AssetID
	}
	schemaRaw, err := os.ReadFile("../../contracts/c26-cmdb.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := jsonschema.UnmarshalJSON(strings.NewReader(string(schemaRaw)))
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err = compiler.AddResource("urn:surveyscan:c26:cmdb:1:0", doc); err != nil {
		t.Fatal(err)
	}
	valid := func(def string, raw []byte) {
		t.Helper()
		schema, err := compiler.Compile("urn:surveyscan:c26:cmdb:1:0#/$defs/" + def)
		if err != nil {
			t.Fatal(err)
		}
		instance, err := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
		if err != nil {
			t.Fatal(err)
		}
		if err = schema.Validate(instance); err != nil {
			t.Fatalf("%s violates contract: %v\n%s", def, err, raw)
		}
	}
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
	session := b.login(t, "admin")
	get := func(path string, want int) []byte {
		t.Helper()
		code, raw, _ := b.request(t, "GET", path, "", "", "", nil)
		if code != want {
			t.Fatalf("GET %s: want %d, got %d %s", path, want, code, raw)
		}
		return raw
	}
	send2 := func(method, path, body string, want int) []byte {
		t.Helper()
		code, raw, _ := b.request(t, method, path, body, session.CSRFToken, "https://ui.example", nil)
		if code != want {
			t.Fatalf("%s %s %s: want %d, got %d %s", method, path, body, want, code, raw)
		}
		return raw
	}

	ha, hb := newHost(), newHost()
	ma, mb := mu(), mu()
	a := send(ha, "host:cmdb-a", ma, 250, "Virtual Machine")
	bAsset := send(hb, "host:cmdb-b", mb, 3, "PowerEdge R650")

	// 1. класс: наблюдаемый по фактам, ручной главнее и переживает новый сбор
	var card app.AssetCMDB
	raw := get("/api/v1/assets/"+a+"/cmdb", 200)
	valid("AssetCMDB", raw)
	_ = json.Unmarshal(raw, &card)
	if card.Class.Observed != "virtual_machine" || card.Class.Manual != nil || card.Class.Effective != "virtual_machine" || card.SoftwareCount != 250 || card.ComponentCount != 3 { // 2 hardware + том из resources
		t.Fatalf("observed class/counts: %+v", card)
	}
	send2("PATCH", "/api/v1/assets/"+a+"/classification", `{"asset_class":"server","revision":"999"}`, 412)
	send2("PATCH", "/api/v1/assets/"+a+"/classification", `{"asset_class":"toaster","revision":"`+card.BusinessRevision+`"}`, 422)
	raw = send2("PATCH", "/api/v1/assets/"+a+"/classification", `{"asset_class":"server","revision":"`+card.BusinessRevision+`"}`, 200)
	valid("AssetCMDB", raw)
	send(ha, "host:cmdb-a", ma, 250, "Virtual Machine")
	_ = json.Unmarshal(get("/api/v1/assets/"+a+"/cmdb", 200), &card)
	if card.Class.Manual == nil || *card.Class.Manual != "server" || card.Class.Effective != "server" || card.Class.Observed != "virtual_machine" {
		t.Fatalf("collection must not overwrite the manual class: %+v", card.Class)
	}

	// 2. ПО: курсорная пагинация без пропусков и повторов, фильтр, provenance
	seen := map[string]bool{}
	cursor, pages, last := "", 0, ""
	for {
		path := "/api/v1/assets/" + a + "/software?limit=40"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		raw = get(path, 200)
		valid("SoftwarePage", raw)
		var page app.SoftwarePage
		_ = json.Unmarshal(raw, &page)
		pages++
		for _, i := range page.Items {
			if seen[i.RecordKey] || i.Evidence.SourceID != ha.source || i.Name == nil {
				t.Fatal("duplicate or missing provenance", i)
			}
			seen[i.RecordKey] = true
			if strings.ToLower(*i.Name) < last {
				t.Fatal("software must be ordered by name across pages", *i.Name, last)
			}
			last = strings.ToLower(*i.Name)
		}
		if page.NextCursor == nil {
			break
		}
		cursor = *page.NextCursor
	}
	if len(seen) != 250 || pages != 7 {
		t.Fatal("software pagination", len(seen), pages)
	}
	var filtered app.SoftwarePage
	_ = json.Unmarshal(get("/api/v1/assets/"+a+"/software?filter="+url.QueryEscape("пакет-01"), 200), &filtered)
	if len(filtered.Items) != 10 {
		t.Fatal("filter by name", len(filtered.Items))
	}
	get("/api/v1/assets/"+a+"/software?cursor=zzz", 400)
	// поиск ПО по тенанту: продукт на двух активах
	raw = get("/api/v1/software?q="+url.QueryEscape("Пакет-001"), 200)
	valid("ProductList", raw)
	var products app.ProductList
	_ = json.Unmarshal(raw, &products)
	if len(products.Items) != 1 || products.Items[0].Assets != 2 {
		t.Fatalf("product search: %s", raw)
	}
	get("/api/v1/software?q=x", 400)
	// компоненты
	raw = get("/api/v1/assets/"+bAsset+"/components", 200)
	valid("ComponentList", raw)
	if !strings.Contains(string(raw), "PowerEdge R650") {
		t.Fatal("components", string(raw))
	}

	// 3. сервисы: создание, дубль имени, ревизия, связи и недопустимые сочетания
	raw = send2("POST", "/api/v1/services", `{"name":"1С Бухгалтерия","criticality":"high"}`, 201)
	valid("ServiceDetail", raw)
	var svc app.ServiceDetail
	_ = json.Unmarshal(raw, &svc)
	send2("POST", "/api/v1/services", `{"name":"1с бухгалтерия"}`, 409)
	send2("POST", "/api/v1/services", `{"name":"x","criticality":"extreme"}`, 422)
	raw = send2("POST", "/api/v1/services", `{"name":"СУБД"}`, 201)
	var db app.ServiceDetail
	_ = json.Unmarshal(raw, &db)
	rel := func(typ, fk, fid, tk, tid string, want int) []byte {
		return send2("POST", "/api/v1/relations", fmt.Sprintf(`{"relation_type":%q,"from":{"kind":%q,"id":%q},"to":{"kind":%q,"id":%q}}`, typ, fk, fid, tk, tid), want)
	}
	raw = rel("runs_on", "service", svc.UID, "asset", a, 201)
	valid("Relation", raw)
	rel("runs_on", "service", svc.UID, "asset", a, 409) // дубль
	rel("depends_on", "service", svc.UID, "service", db.UID, 201)
	rel("runs_on", "service", db.UID, "asset", bAsset, 201)
	rel("runs_on", "asset", a, "service", svc.UID, 422) // недопустимое направление
	rel("hosts", "asset", a, "asset", a, 422)           // петля
	rel("runs_on", "service", svc.UID, "asset", identifier.New(), 404)
	raw = get("/api/v1/services/"+svc.UID, 200)
	valid("ServiceDetail", raw)
	_ = json.Unmarshal(raw, &svc)
	if len(svc.Relations) != 2 {
		t.Fatal("service relations", len(svc.Relations))
	}
	send2("PATCH", "/api/v1/services/"+svc.UID, `{"revision":"999","description":"x"}`, 412)
	raw = send2("PATCH", "/api/v1/services/"+svc.UID, `{"revision":"`+svc.Revision+`","description":"Главная книга"}`, 200)
	_ = json.Unmarshal(raw, &svc)
	if svc.Description == nil || *svc.Description != "Главная книга" || svc.Revision != "2" {
		t.Fatal("service update", string(raw))
	}
	raw = get("/api/v1/services?limit=1", 200)
	valid("ServicePage", raw)
	var sp app.ServicePage
	_ = json.Unmarshal(raw, &sp)
	if len(sp.Items) != 1 || sp.NextCursor == nil {
		t.Fatal("service paging", string(raw))
	}
	// событие на активе-конце связи
	var changes int
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM assets.asset_changes WHERE tenant_id=$1 AND asset_uid=$2 AND reason_code='RELATION_CHANGED'", tenant, a).Scan(&changes)
	if changes != 1 {
		t.Fatal("relation change must be in asset history", changes)
	}

	// 4. слияние: связи поглощённого переходят на канонический; дубль закрывается
	rel("runs_on", "service", svc.UID, "asset", bAsset, 201) // после слияния станет дублем runs_on svc→a
	if _, err = f.registry.MergeAssets(f.ctx, f.identity, app.MergeRequest{Target: a, Absorbed: bAsset}); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(get("/api/v1/assets/"+a+"/cmdb", 200), &card)
	types := map[string]int{}
	for _, r := range card.Relations {
		types[r.Type+":"+r.From.ID]++
		if r.To.ID == bAsset || r.From.ID == bAsset {
			t.Fatal("relation still points to the absorbed asset")
		}
	}
	if types["runs_on:"+svc.UID] != 1 || types["runs_on:"+db.UID] != 1 {
		t.Fatalf("relations after merge: %v", types)
	}

	// 5. вывод сервиса закрывает его связи
	_ = json.Unmarshal(get("/api/v1/services/"+db.UID, 200), &db)
	send2("PATCH", "/api/v1/services/"+db.UID, `{"revision":"`+db.Revision+`","retire":true}`, 200)
	_ = json.Unmarshal(get("/api/v1/services/"+db.UID, 200), &db)
	if db.RetiredAt == nil || len(db.Relations) != 0 {
		t.Fatal("retired service keeps no active relations")
	}
	rel("runs_on", "service", db.UID, "asset", a, 404)

	// 6. межтенантный запрет: чужой администратор не видит и не связывает чужие CI
	if _, err = f.pool.Exec(f.ctx, "INSERT INTO access.tenants(tenant_id,name,status) VALUES($1,'other','active')", otherTenant); err != nil {
		t.Fatal(err)
	}
	if err = f.users.Provision(f.ctx, false, otherTenant, "", "cmdb-foreign", password, "admin"); err != nil {
		t.Fatal(err)
	}
	foreign := newBrowser(t, server)
	fs := foreign.login(t, "cmdb-foreign")
	code, _, _ := foreign.request(t, "GET", "/api/v1/services/"+svc.UID, "", "", "", nil)
	expect(t, 404, code)
	code, _, _ = foreign.request(t, "POST", "/api/v1/services", `{"name":"Чужой"}`, fs.CSRFToken, "https://ui.example", nil)
	expect(t, 201, code)
	var mine app.ServicePage
	code, raw, _ = foreign.request(t, "GET", "/api/v1/services", "", "", "", nil)
	_ = json.Unmarshal(raw, &mine)
	if code != 200 || len(mine.Items) != 1 {
		t.Fatal("foreign tenant sees only its own services", string(raw))
	}
	code, _, _ = foreign.request(t, "POST", "/api/v1/relations", fmt.Sprintf(`{"relation_type":"runs_on","from":{"kind":"service","id":%q},"to":{"kind":"asset","id":%q}}`, mine.Items[0].UID, a), fs.CSRFToken, "https://ui.example", nil)
	expect(t, 404, code)
	if _, err = f.pool.Exec(f.ctx, "INSERT INTO cmdb.relations(tenant_id,relation_id,relation_type,from_service_uid,to_asset_uid,origin,confidence,actor_ref) VALUES($1,$2,'runs_on',$3,$4,'manual','confirmed','test')", otherTenant, identifier.New(), mine.Items[0].UID, a); err == nil {
		t.Fatal("cross-tenant relation must violate foreign keys")
	}
	// история и аудит модуля
	var history, audits int
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM cmdb.changes WHERE tenant_id=$1", tenant).Scan(&history)
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM audit.audit_events WHERE tenant_id=$1 AND action LIKE 'cmdb.%'", tenant).Scan(&audits)
	if history < 10 || audits < 8 {
		t.Fatal("cmdb history/audit", history, audits)
	}
}
