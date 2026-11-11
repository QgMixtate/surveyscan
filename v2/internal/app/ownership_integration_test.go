//go:build integration

package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/health"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// C27.02–C27.04: субъекты и связь со входом, роли, атомарная передача без разрыва, деактивация с переназначением
// на резервную команду, рабочие списки, массовое назначение «всё или ничего», права, конкурентная передача двумя
// операторами, отключённый вход, сохранность интервалов и оснований, outbox; ответы — по контракту c27.
func TestC27Ownership(t *testing.T) {
	f := registrySetup(t)
	newAsset := func(i int) string {
		o := f.observation("1")
		mu := fmt.Sprintf("00000000-0000-4000-8000-%012d", 500+i)
		o.Record.LocalID = fmt.Sprintf("own-%d", i)
		o.Candidates = []contracts.Candidate{{Kind: "machine_uuid", Namespace: "host", Value: mu}}
		o.Sections[0].Records = []map[string]any{{"hostname": fmt.Sprintf("own-%d", i), "machine_uuid": mu}}
		r := f.ingest(t, o)
		if r.AssetID == nil {
			t.Fatal("asset not created", r)
		}
		return *r.AssetID
	}
	schemaRaw, err := os.ReadFile("../../contracts/c27-ownership.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := jsonschema.UnmarshalJSON(strings.NewReader(string(schemaRaw)))
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err = compiler.AddResource("urn:surveyscan:c27:ownership:1:0", doc); err != nil {
		t.Fatal(err)
	}
	valid := func(def string, raw []byte) {
		t.Helper()
		schema, err := compiler.Compile("urn:surveyscan:c27:ownership:1:0#/$defs/" + def)
		if err != nil {
			t.Fatal(err)
		}
		instance, err := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
		if err != nil {
			t.Fatal(err, string(raw))
		}
		if err = schema.Validate(instance); err != nil {
			t.Fatalf("%s violates contract: %v\n%s", def, err, raw)
		}
	}
	for _, u := range []struct{ name, role string }{{"op1", "operator"}, {"op2", "operator"}, {"watcher", "viewer"}} {
		if err = f.users.Provision(f.ctx, false, tenant, "", u.name, password, u.role); err != nil {
			t.Fatal(err)
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
	type client struct {
		b    browser
		csrf string
	}
	login := func(name string) client {
		b := newBrowser(t, server)
		return client{b, b.login(t, name).CSRFToken}
	}
	admin, op1, op2, watcher := login("admin"), login("op1"), login("op2"), login("watcher")
	call := func(c client, method, path, body string, want int) []byte {
		t.Helper()
		csrf, origin := c.csrf, "https://ui.example"
		if method == "GET" {
			csrf, origin = "", ""
		}
		code, raw, _ := c.b.request(t, method, path, body, csrf, origin, nil)
		if code != want {
			t.Fatalf("%s %s %s: want %d, got %d %s", method, path, body, want, code, raw)
		}
		return raw
	}
	subject := func(body string) app.SubjectResult {
		raw := call(admin, "POST", "/api/v1/subjects", body, 201)
		valid("SubjectResult", raw)
		var out app.SubjectResult
		_ = json.Unmarshal(raw, &out)
		return out
	}

	// 1. субъекты: человек со входом, команда с составом; collector субъектом быть не может
	p1 := subject(`{"kind":"person","name":"Иванов","contact":"ivanov@example.test","username":"op1"}`).Subject
	p2 := subject(`{"kind":"person","name":"Петров","contact":"petrov@example.test","username":"op2"}`).Subject
	team := subject(`{"kind":"team","name":"Группа серверов","contact":"srv@example.test"}`).Subject
	call(admin, "POST", "/api/v1/subjects", `{"kind":"person","name":"Двойник","contact":"x@example.test","username":"op1"}`, 409)
	call(admin, "POST", "/api/v1/subjects", `{"kind":"team","name":"T","contact":"t@example.test","username":"op2"}`, 422)
	call(admin, "POST", "/api/v1/subjects", `{"kind":"collector","name":"C","contact":"c@example.test"}`, 422)
	call(op1, "POST", "/api/v1/subjects", `{"kind":"team","name":"T","contact":"t@example.test"}`, 403) // оператор не ведёт оргструктуру
	valid("Subject", call(admin, "PUT", "/api/v1/subjects/"+team.ID+"/members/"+p1.ID, "", 200))
	call(admin, "PUT", "/api/v1/subjects/"+team.ID+"/members/"+p1.ID, "", 409)
	call(admin, "PUT", "/api/v1/subjects/"+p1.ID+"/members/"+p2.ID, "", 404) // человек не команда
	valid("SubjectPage", call(watcher, "GET", "/api/v1/subjects?kind=person", "", 200))

	assets := []string{newAsset(1), newAsset(2), newAsset(3)}
	a := assets[0]
	read := func(uid string) app.AssetAssignments {
		raw := call(op1, "GET", "/api/v1/assets/"+uid+"/assignments", "", 200)
		valid("AssetAssignments", raw)
		var out app.AssetAssignments
		_ = json.Unmarshal(raw, &out)
		return out
	}
	worklist := func(c client, scope string) map[string]bool {
		raw := call(c, "GET", "/api/v1/worklist?scope="+scope, "", 200)
		valid("WorklistPage", raw)
		var page app.WorklistPage
		_ = json.Unmarshal(raw, &page)
		out := map[string]bool{}
		for _, it := range page.Items {
			out[it.Asset] = true
		}
		return out
	}

	// 2. новый актив — «не распределён» (резервная команда площадки), не «на мне»
	if !worklist(op1, "unassigned")[a] || worklist(op1, "mine")[a] {
		t.Fatal("new asset must be unassigned")
	}
	// 3. передача accountable: устаревшая версия — 412; без разрыва интервала
	state := read(a)
	call(op1, "POST", "/api/v1/assets/"+a+"/assignments", `{"role":"accountable","subject_id":"`+p1.ID+`","expected_version":"999"}`, 412)
	call(watcher, "POST", "/api/v1/assets/"+a+"/assignments", `{"role":"accountable","subject_id":"`+p1.ID+`","expected_version":"`+state.Version+`"}`, 403)
	call(op1, "POST", "/api/v1/assets/"+a+"/assignments", `{"role":"accountable","subject_id":"`+p1.ID+`","note":"принял сервер","expected_version":"`+state.Version+`"}`, 200)
	state = read(a)
	var newFrom, oldTo string
	for _, h := range state.History {
		if h.Role != "accountable" {
			continue
		}
		if h.Subject == p1.ID && h.ValidTo == nil {
			newFrom = h.ValidFrom.String()
			if h.Note == nil || *h.Note != "принял сервер" || h.Reason != "MANUAL_ASSIGNMENT" {
				t.Fatal("basis and author must be stored", h)
			}
		} else if h.ValidTo != nil {
			oldTo = h.ValidTo.String()
		}
	}
	if newFrom == "" || newFrom != oldTo {
		t.Fatal("transfer must not leave a gap without accountable", newFrom, oldTo)
	}
	if !worklist(op1, "mine")[a] || worklist(op1, "unassigned")[a] || worklist(op2, "mine")[a] {
		t.Fatal("worklists after transfer")
	}
	// 4. необязательные роли: технический — команда («на команде» у её участника), снятие роли; accountable снять нельзя
	call(op1, "POST", "/api/v1/assets/"+a+"/assignments", `{"role":"technical","subject_id":"`+team.ID+`","expected_version":"`+read(a).Version+`"}`, 200)
	if !worklist(op1, "team")[a] || worklist(op2, "team")[a] {
		t.Fatal("team worklist follows team membership")
	}
	call(op1, "POST", "/api/v1/assets/"+a+"/assignments", `{"role":"custodian","subject_id":"`+team.ID+`","expected_version":"`+read(a).Version+`"}`, 404) // хранитель — только человек
	call(op1, "POST", "/api/v1/assets/"+a+"/assignments", `{"role":"accountable","subject_id":null,"expected_version":"`+read(a).Version+`"}`, 422)
	call(op1, "POST", "/api/v1/assets/"+a+"/assignments", `{"role":"technical","subject_id":null,"expected_version":"`+read(a).Version+`"}`, 200)
	if len(read(a).Active) != 1 {
		t.Fatal("technical role must be closed")
	}

	// 5. конкурентная передача двумя операторами с одной версией: ровно одна проходит, вторая — 412
	version := read(a).Version
	codes := make([]int, 2)
	var wg sync.WaitGroup
	for i, c := range []client{op1, op2} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i], _, _ = c.b.request(t, "POST", "/api/v1/assets/"+a+"/assignments", `{"role":"accountable","subject_id":"`+p2.ID+`","expected_version":"`+version+`"}`, c.csrf, "https://ui.example", nil)
		}()
	}
	wg.Wait()
	if !(codes[0] == 200 && codes[1] == 412 || codes[0] == 412 && codes[1] == 200) {
		t.Fatal("exactly one concurrent transfer must win", codes)
	}
	var activeAccountable int
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM responsibility.responsibility_assignments WHERE tenant_id=$1 AND asset_uid=$2 AND role='accountable' AND valid_to IS NULL", tenant, a).Scan(&activeAccountable)
	if activeAccountable != 1 {
		t.Fatal("one active accountable", activeAccountable)
	}

	// 6. отключённый вход ответственного — «требует передачи»; деактивация человека — переход на резервную команду
	if err = f.users.ChangeUser(f.ctx, tenant, "op2", "operator", false); err != nil {
		t.Fatal(err)
	}
	if !worklist(op1, "attention")[a] {
		t.Fatal("asset of a disabled login must need attention")
	}
	raw := call(admin, "PATCH", "/api/v1/subjects/"+p2.ID, `{"revision":"`+p2.Revision+`","deactivate":true}`, 200)
	valid("SubjectResult", raw)
	var res app.SubjectResult
	_ = json.Unmarshal(raw, &res)
	if res.Subject.Active || res.Reassign != 1 {
		t.Fatalf("deactivation: %s", raw)
	}
	state = read(a)
	if len(state.Active) != 1 || state.Active[0].Reason != "SUBJECT_DEACTIVATED" || !worklist(op1, "unassigned")[a] || worklist(op1, "attention")[a] {
		t.Fatalf("accountable must move to the site fallback team: %+v", state.Active)
	}
	intervals := map[string]int{}
	for _, h := range state.History {
		if h.Role == "accountable" {
			intervals[h.Subject]++
		}
	}
	if intervals[p1.ID] != 1 || intervals[p2.ID] != 1 || len(state.History) < 5 {
		t.Fatal("historic intervals and bases must be kept", intervals, len(state.History))
	}
	call(op1, "POST", "/api/v1/assets/"+a+"/assignments", `{"role":"accountable","subject_id":"`+p2.ID+`","expected_version":"`+state.Version+`"}`, 404)
	var fallback string
	_ = f.pool.QueryRow(f.ctx, "SELECT fallback_subject_id::text FROM scope.sites WHERE tenant_id=$1 AND site_id=$2", tenant, siteID).Scan(&fallback)
	var fb app.SubjectPage
	_ = json.Unmarshal(call(admin, "GET", "/api/v1/subjects?kind=team", "", 200), &fb)
	for _, s := range fb.Items {
		if s.ID == fallback {
			call(admin, "PATCH", "/api/v1/subjects/"+fallback, `{"revision":"`+s.Revision+`","deactivate":true}`, 409) // резервную команду нельзя
		}
	}

	// 7. массовое назначение: всё или ничего; чужой тенант не находится; наблюдатель не может
	items := func(stale int) string {
		var parts []string
		for i, uid := range assets {
			v := read(uid).Version
			if i == stale {
				v = "999"
			}
			parts = append(parts, `{"asset_uid":"`+uid+`","expected_version":"`+v+`"}`)
		}
		return `{"role":"accountable","subject_id":"` + team.ID + `","items":[` + strings.Join(parts, ",") + `]}`
	}
	raw = call(op1, "POST", "/api/v1/assignments/bulk", items(2), 412)
	valid("BulkAssignResult", raw)
	if !strings.Contains(string(raw), assets[2]) || worklist(op1, "team")[assets[0]] {
		t.Fatalf("stale bulk must change nothing: %s", raw)
	}
	call(watcher, "POST", "/api/v1/assignments/bulk", items(-1), 403)
	call(op1, "POST", "/api/v1/assignments/bulk", `{"role":"accountable","subject_id":"`+team.ID+`","items":[{"asset_uid":"`+identifier.New()+`","expected_version":"1"}]}`, 404)
	raw = call(op1, "POST", "/api/v1/assignments/bulk", items(-1), 200)
	valid("BulkAssignResult", raw)
	if !strings.Contains(string(raw), `"applied":3`) {
		t.Fatalf("bulk applied: %s", raw)
	}
	for _, uid := range assets {
		if !worklist(op1, "team")[uid] {
			t.Fatal("bulk-assigned asset must be on the team worklist", uid)
		}
	}
	if _, err = f.registry.BulkAssign(f.ctx, f.identity, app.BulkAssignRequest{Role: "accountable", Subject: team.ID, Items: []app.BulkItem{{Asset: assets[0], ExpectedVersion: "1"}, {Asset: assets[0], ExpectedVersion: "1"}}}); !errors.Is(err, domain.Invalid) {
		t.Fatal("duplicate assets in bulk must be invalid", err)
	}

	// 8. события: потребитель outbox доходит до версий активов
	for range 10000 {
		worked, err := f.registry.ConsumeOne(f.ctx, tenant)
		if err != nil {
			t.Fatal(err)
		}
		if !worked {
			break
		}
	}
	var lagging, audits int
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM assets.assets a LEFT JOIN assets.consumer_versions c USING(tenant_id,asset_uid) WHERE a.tenant_id=$1 AND c.aggregate_version IS DISTINCT FROM a.aggregate_version", tenant).Scan(&lagging)
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM audit.audit_events WHERE tenant_id=$1 AND action LIKE 'responsibility.%'", tenant).Scan(&audits)
	if lagging != 0 || audits < 10 {
		t.Fatal("events/audit", lagging, audits)
	}
}
