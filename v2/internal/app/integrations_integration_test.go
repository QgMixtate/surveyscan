//go:build integration

package app_test

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/responsibility"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/health"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

type c31Env struct {
	t       *testing.T
	f       *registryFixture
	call    func(c c31Client, method, path, body string, want int, headers ...string) []byte
	valid   func(urn, def string, raw []byte)
	admin   c31Client
	op      c31Client
	watcher c31Client
}

type c31Client struct {
	b    browser
	csrf string
}

func c31Setup(t *testing.T) *c31Env {
	f := registrySetup(t)
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	for file, urn := range map[string]string{"c27-ownership": "urn:surveyscan:c27:ownership:1:0", "c31-integrations": "urn:surveyscan:c31:integrations:1:0"} {
		raw, err := os.ReadFile("../../contracts/" + file + ".schema.json")
		if err != nil {
			t.Fatal(err)
		}
		doc, _ := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
		if err = compiler.AddResource(urn, doc); err != nil {
			t.Fatal(err)
		}
	}
	env := &c31Env{t: t, f: f}
	env.valid = func(urn, def string, raw []byte) {
		t.Helper()
		schema, err := compiler.Compile(urn + "#/$defs/" + def)
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
	for _, u := range []struct{ name, role string }{{"ivanov", "operator"}, {"op", "operator"}, {"watcher", "viewer"}} {
		if err := f.users.Provision(f.ctx, false, tenant, "", u.name, password, u.role); err != nil {
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
	t.Cleanup(server.Close)
	login := func(name string) c31Client {
		b := newBrowser(t, server)
		return c31Client{b, b.login(t, name).CSRFToken}
	}
	env.admin, env.op, env.watcher = login("admin"), login("op"), login("watcher")
	env.call = func(c c31Client, method, path, body string, want int, headers ...string) []byte {
		t.Helper()
		csrf, origin := c.csrf, "https://ui.example"
		if method == "GET" {
			csrf, origin = "", ""
		}
		h := map[string]string{}
		for i := 0; i+1 < len(headers); i += 2 {
			h[headers[i]] = headers[i+1]
		}
		code, raw, _ := c.b.request(t, method, path, body, csrf, origin, h)
		if code != want {
			t.Fatalf("%s %s: want %d, got %d %s", method, path, want, code, raw)
		}
		return raw
	}
	return env
}

func (env *c31Env) asset(i int) string {
	o := env.f.observation("1")
	mu := fmt.Sprintf("00000000-0000-4000-8000-%012d", 700+i)
	o.Record.LocalID = fmt.Sprintf("c31-%d", i)
	o.Candidates = []contracts.Candidate{{Kind: "machine_uuid", Namespace: "host", Value: mu}}
	o.Sections[0].Records = []map[string]any{{"hostname": fmt.Sprintf("c31-%d", i), "machine_uuid": mu}}
	r := env.f.ingest(env.t, o)
	if r.AssetID == nil {
		env.t.Fatal("asset not created", r)
	}
	return *r.AssetID
}

func ldapEnv(t *testing.T) map[string]string {
	out := map[string]string{}
	for _, k := range []string{"URL", "PLAIN_URL", "BASE_DN", "BIND_DN", "PASSWORD_FILE", "CA_FILE", "ADMIN_PASSWORD_FILE", "CONTAINER"} {
		out[k] = os.Getenv("SURVEYSCAN_TEST_LDAP_" + k)
		if out[k] == "" {
			if os.Getenv("SURVEYSCAN_REQUIRE_LDAP_MOCK") == "1" {
				t.Fatal("LDAP mock required: python3 scripts/ldap_mock.py up")
			}
			t.Skip("LDAP mock not configured (scripts/ldap_mock.py up)")
		}
	}
	return out
}

// ldapAdmin меняет мок-каталог от имени администратора каталога (имитация изменений в AD).
func ldapAdmin(t *testing.T, env map[string]string, tool, ldif string, args ...string) {
	t.Helper()
	pw, err := os.ReadFile(env["ADMIN_PASSWORD_FILE"])
	if err != nil {
		t.Fatal(err)
	}
	cmd := osexec.Command("docker", "exec", "-i", env["CONTAINER"], tool, "-x", "-H", "ldap://localhost", "-D", "cn=admin,"+env["BASE_DN"], "-w", strings.TrimSpace(string(pw)))
	cmd.Args = append(cmd.Args, args...)
	cmd.Stdin = strings.NewReader(ldif)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatal(tool, err, string(out))
	}
}

// C31.02/C31.04: синхронизация оргструктуры из каталога (мок OpenLDAP по LDAPS, отдельно от реального AD):
// полный и инкрементальный проходы, связь логина, состав команд, запрет ручных правок субъектов каталога,
// выбытие удалённого из каталога ответственного → резервная команда (история, событие), отказ bind без раскрытия
// секрета, недоверенный сертификат, журнал прогонов по контракту c31.
func TestC31DirectorySync(t *testing.T) {
	ld := ldapEnv(t)
	env := c31Setup(t)
	f, call := env.f, env.call
	const urn = "urn:surveyscan:c31:integrations:1:0"
	// свой OU на прогон: тест меняет каталог и повторяем
	base := "ou=t" + strings.ReplaceAll(identifier.New()[:8], "-", "") + "," + ld["BASE_DN"]
	seed := "dn: " + base + "\nobjectClass: organizationalUnit\n\n"
	for _, p := range [][2]string{{"ivanov", "Иван Иванов"}, {"petrova", "Мария Петрова"}, {"sidorov", "Пётр Сидоров"}} {
		seed += fmt.Sprintf("dn: uid=%s,%s\nobjectClass: inetOrgPerson\nuid: %s\ncn: %s\nsn: %s\ndisplayName: %s\nmail: %s@example.test\n\n", p[0], base, p[0], p[1], p[1], p[1], p[0])
	}
	seed += fmt.Sprintf("dn: cn=Linux Admins,%s\nobjectClass: groupOfNames\ncn: Linux Admins\nmember: uid=ivanov,%s\nmember: uid=petrova,%s\n\n", base, base, base)
	seed += fmt.Sprintf("dn: cn=Nested,%s\nobjectClass: groupOfNames\ncn: Nested\nmember: cn=Linux Admins,%s\n", base, base)
	ldapAdmin(t, ld, "ldapadd", seed)
	t.Cleanup(func() { ldapAdmin(t, ld, "ldapdelete", base+"\n", "-r") })
	cfg := app.DirectorySyncConfig{TenantID: tenant, URL: ld["URL"], BaseDN: base, BindDN: ld["BIND_DN"], PasswordFile: ld["PASSWORD_FILE"], CAFile: ld["CA_FILE"],
		UserFilter: "(objectClass=inetOrgPerson)", GroupFilter: "(objectClass=groupOfNames)", GUIDAttribute: "entryUUID", LoginAttribute: "uid", ChangedAttribute: "modifyTimestamp"}
	if _, err := app.NewDirectorySync(app.DirectorySyncConfig{TenantID: tenant, URL: ld["PLAIN_URL"], BaseDN: cfg.BaseDN, BindDN: cfg.BindDN, PasswordFile: cfg.PasswordFile}); err == nil {
		t.Fatal("plaintext ldap:// must require allow_plaintext")
	}
	// без синхронизации: состояние есть, запуск — 404
	raw := call(env.watcher, "GET", "/api/v1/directory-sync", "", 200)
	env.valid(urn, "DirectorySyncStatus", raw)
	call(env.admin, "POST", "/api/v1/directory-sync/run", `{"mode":"full"}`, 404)
	d, err := app.NewDirectorySync(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.registry.Directory = d
	run := func(mode string) responsibility.SyncRun {
		t.Helper()
		raw := call(env.admin, "POST", "/api/v1/directory-sync/run", `{"mode":"`+mode+`"}`, 200)
		env.valid(urn, "SyncRun", raw)
		var r responsibility.SyncRun
		_ = json.Unmarshal(raw, &r)
		return r
	}
	counters := func(r responsibility.SyncRun) responsibility.SyncCounters {
		var c responsibility.SyncCounters
		_ = json.Unmarshal(r.Counters, &c)
		return c
	}
	call(env.op, "POST", "/api/v1/directory-sync/run", `{"mode":"full"}`, 403)
	call(env.admin, "POST", "/api/v1/directory-sync/run", `{"mode":"delta"}`, 422)

	// 1. полный проход: 3 человека, 2 команды (вложенная группа — не участник), логин ivanov связан
	r1 := run("auto") // журнал пуст → полный
	c1 := counters(r1)
	if r1.Status != "succeeded" || r1.Mode != "full" || c1.Created != 5 || c1.People != 3 || c1.Teams != 2 || c1.MembersAdded != 2 || c1.LoginsLinked != 1 {
		t.Fatalf("first full sync: %+v %s %v", r1, r1.Counters, deref(r1.Error))
	}
	subjects := func() map[string]responsibility.SubjectInfo {
		raw := call(env.op, "GET", "/api/v1/subjects?limit=200&include_inactive=true", "", 200)
		env.valid("urn:surveyscan:c27:ownership:1:0", "SubjectPage", raw)
		var page struct{ Items []responsibility.SubjectInfo }
		_ = json.Unmarshal(raw, &page)
		out := map[string]responsibility.SubjectInfo{}
		for _, s := range page.Items {
			out[s.Name] = s
		}
		return out
	}
	s := subjects()
	ivanov, petrova, admins, nested := s["Иван Иванов"], s["Мария Петрова"], s["Linux Admins"], s["Nested"]
	if ivanov.Origin != "ldap" || ivanov.Username == nil || *ivanov.Username != "ivanov" || ivanov.SyncedAt == nil || ivanov.Contact != "ivanov@example.test" ||
		admins.Kind != "team" || admins.Members != 2 || nested.Members != 0 || petrova.Username != nil {
		t.Fatalf("directory subjects: %+v", s)
	}
	// 2. мастер — каталог: ручное переименование, выбытие и правка состава запрещены; связь входа — можно
	call(env.admin, "PATCH", "/api/v1/subjects/"+ivanov.ID, `{"revision":"`+ivanov.Revision+`","name":"Другое имя"}`, 409)
	call(env.admin, "PATCH", "/api/v1/subjects/"+petrova.ID, `{"revision":"`+petrova.Revision+`","deactivate":true}`, 409)
	call(env.admin, "DELETE", "/api/v1/subjects/"+admins.ID+"/members/"+ivanov.ID, "", 409)
	call(env.admin, "PUT", "/api/v1/subjects/"+admins.ID+"/members/"+s["Пётр Сидоров"].ID, "", 409)
	call(env.admin, "PATCH", "/api/v1/subjects/"+petrova.ID, `{"revision":"`+petrova.Revision+`","username":"op"}`, 200)

	// 3. ответственный из каталога на активе
	uid := env.asset(1)
	var st app.AssetAssignments
	_ = json.Unmarshal(call(env.op, "GET", "/api/v1/assets/"+uid+"/assignments", "", 200), &st)
	call(env.op, "POST", "/api/v1/assets/"+uid+"/assignments", `{"role":"accountable","subject_id":"`+petrova.ID+`","expected_version":"`+st.Version+`"}`, 200)

	// 4. изменения в каталоге → инкрементальный проход: переименование и выход из группы
	ldapAdmin(t, ld, "ldapmodify", fmt.Sprintf("dn: uid=petrova,%s\nchangetype: modify\nreplace: displayName\ndisplayName: Мария Петрова-Смирнова\n\ndn: cn=Linux Admins,%s\nchangetype: modify\ndelete: member\nmember: uid=ivanov,%s\n", base, base, base))
	r2 := run("auto")
	c2 := counters(r2)
	if r2.Status != "succeeded" || r2.Mode != "incremental" || c2.Updated != 1 || c2.MembersEnded != 1 || c2.Created != 0 {
		t.Fatalf("incremental sync: %+v %s", r2, r2.Counters)
	}
	s = subjects()
	if p := s["Мария Петрова-Смирнова"]; p.ID != petrova.ID || p.Username == nil || *p.Username != "op" || s["Linux Admins"].Members != 1 {
		t.Fatalf("after incremental: %+v", s)
	}

	// 5. удалённый из каталога ответственный выбывает на полном проходе → резервная команда площадки
	ldapAdmin(t, ld, "ldapdelete", "uid=petrova,"+base+"\n")
	r3 := run("full")
	c3 := counters(r3)
	if r3.Status != "succeeded" || c3.Deactivated != 1 || c3.Reassigned != 1 {
		t.Fatalf("full sync after delete: %+v %s", r3, r3.Counters)
	}
	_ = json.Unmarshal(call(env.op, "GET", "/api/v1/assets/"+uid+"/assignments", "", 200), &st)
	var fallback string
	_ = f.pool.QueryRow(f.ctx, "SELECT fallback_subject_id::text FROM scope.sites WHERE tenant_id=$1 AND site_id=$2", tenant, siteID).Scan(&fallback)
	if len(st.Active) != 1 || st.Active[0].Subject != fallback || st.Active[0].Reason != "SUBJECT_DEACTIVATED" || st.Active[0].Actor != app.DirectoryActor {
		t.Fatalf("accountable must move to the site fallback team: %+v", st.Active)
	}
	var events, history int
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM messaging.outbox_events WHERE tenant_id=$1 AND aggregate_id=$2 AND event_type='responsibility.assigned.v1'", tenant, uid).Scan(&events)
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM assets.asset_changes WHERE tenant_id=$1 AND asset_uid=$2 AND reason_code='SUBJECT_DEACTIVATED' AND actor_ref=$3", tenant, uid, app.DirectoryActor).Scan(&history)
	if events < 2 || history != 1 {
		t.Fatalf("deactivation must version the asset: events=%d history=%d", events, history)
	}

	// 5а. C35.02: прогон тенанта уже идёт в другом процессе центра (его блокировка в PostgreSQL) — 409, без прогона
	holder, err := f.pool.Acquire(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	key := "surveyscan:directory-sync:" + tenant
	if _, err = holder.Exec(f.ctx, "SELECT pg_advisory_lock(hashtextextended($1,0))", key); err != nil {
		t.Fatal(err)
	}
	var runsBefore, runsAfter int
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM responsibility.directory_sync_runs WHERE tenant_id=$1", tenant).Scan(&runsBefore)
	call(env.admin, "POST", "/api/v1/directory-sync/run", `{"mode":"full"}`, 409)
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM responsibility.directory_sync_runs WHERE tenant_id=$1", tenant).Scan(&runsAfter)
	_, _ = holder.Exec(f.ctx, "SELECT pg_advisory_unlock(hashtextextended($1,0))", key)
	holder.Release()
	if runsAfter != runsBefore {
		t.Fatal("busy sync must not record a run")
	}
	if r := run("auto"); r.Status != "succeeded" {
		t.Fatalf("after the other process finished: %+v", r)
	}

	// 6. сбой bind: прогон failed в журнале, пароль не раскрыт, данные не тронуты
	bad := filepath.Join(t.TempDir(), "pw")
	_ = os.WriteFile(bad, []byte("wrong-secret-value\n"), 0o600)
	wrong := cfg
	wrong.PasswordFile = bad
	if f.registry.Directory, err = app.NewDirectorySync(wrong); err != nil {
		t.Fatal(err)
	}
	r4 := run("full")
	if r4.Status != "failed" || r4.Error == nil || strings.Contains(*r4.Error, "wrong-secret") || !strings.Contains(*r4.Error, "bind failed") {
		t.Fatalf("bind failure: %+v", r4)
	}
	// 7. LDAPS без доверенного CA — отказ TLS
	untrusted := cfg
	untrusted.CAFile = ""
	if f.registry.Directory, err = app.NewDirectorySync(untrusted); err != nil {
		t.Fatal(err)
	}
	if r5 := run("full"); r5.Status != "failed" || !strings.Contains(*r5.Error, "unavailable") {
		t.Fatalf("untrusted certificate must fail: %+v", r5)
	}
	if after := subjects(); after["Иван Иванов"].Active != true || len(after) != len(s) {
		t.Fatal("failed runs must not change subjects", after)
	}
	raw = call(env.watcher, "GET", "/api/v1/directory-sync", "", 200)
	env.valid(urn, "DirectorySyncStatus", raw)
	var status app.DirectorySyncStatus
	_ = json.Unmarshal(raw, &status)
	if !status.Configured || len(status.Runs) != 6 || status.Runs[0].Status != "failed" || strings.Contains(string(raw), "wrong-secret") {
		t.Fatalf("status: %s", raw)
	}
	var audits int
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM audit.audit_events WHERE tenant_id=$1 AND action IN ('responsibility.directory_synced','responsibility.directory_sync_failed')", tenant).Scan(&audits)
	if audits != 6 {
		t.Fatal("every run must be audited", audits)
	}
}

// C31.02: применение снимка каталога (AD-признак «отключён», повторное включение, защита от массового выбытия).
func TestC31DirectorySnapshot(t *testing.T) {
	f := registrySetup(t)
	apply := func(d responsibility.Directory) (responsibility.SyncCounters, error) {
		tx, err := f.pool.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(f.ctx)
		c, _, err := f.registry.Owners.SyncDirectory(f.ctx, tx, tenant, d, app.DirectoryActor)
		if err == nil {
			err = tx.Commit(f.ctx)
		}
		return c, err
	}
	people := []responsibility.DirPerson{}
	for i := range 12 {
		people = append(people, responsibility.DirPerson{GUID: fmt.Sprintf("guid-%02d", i), Login: fmt.Sprintf("u%02d", i), Name: fmt.Sprintf("Человек %d", i)})
	}
	people = append(people, responsibility.DirPerson{GUID: "guid-off", Login: "off", Name: "Отключён", Disabled: true})
	if c, err := apply(responsibility.Directory{People: people, Full: true}); err != nil || c.Created != 12 {
		t.Fatal("disabled accounts are not created", c, err)
	}
	people[0].Disabled = true
	if c, err := apply(responsibility.Directory{People: people[:1]}); err != nil || c.Deactivated != 1 {
		t.Fatal("disabled in directory → deactivated", c, err)
	}
	people[0].Disabled = false
	if c, err := apply(responsibility.Directory{People: people[:1]}); err != nil || c.Reactivated != 1 {
		t.Fatal("re-enabled → reactivated", c, err)
	}
	// полный снимок без людей (ошибочный фильтр) выбил бы 12 > max(10, 12/4): отказ целиком
	if c, err := apply(responsibility.Directory{Full: true}); !errors.Is(err, responsibility.ErrMassRemoval) || len(c.Problems) != 1 {
		t.Fatal("mass removal must be refused", c, err)
	}
	var active int
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM responsibility.subjects WHERE tenant_id=$1 AND origin='ldap' AND active", tenant).Scan(&active)
	if active != 12 {
		t.Fatal("refused snapshot must change nothing", active)
	}
	// смена вида объекта при том же GUID — проблема, не изменение
	if c, err := apply(responsibility.Directory{Teams: []responsibility.DirTeam{{GUID: "guid-01", Name: "Команда"}}}); err != nil || len(c.Problems) != 1 || c.Created != 0 {
		t.Fatal("kind change must be reported", c, err)
	}
}

// C31.02: CSV экспорт и импорт ручных полей — формат и версия, защита от формул, пробный прогон без изменений,
// ревизии по строкам, история/событие CSV_IMPORT, права, отказ неизвестного формата.
func TestC31AssetsCSV(t *testing.T) {
	env := c31Setup(t)
	f, call := env.f, env.call
	const urn = "urn:surveyscan:c31:integrations:1:0"
	a, b := env.asset(1), env.asset(2)
	parse := func(raw []byte) [][]string {
		t.Helper()
		text := string(raw)
		if !strings.HasPrefix(text, "\uFEFF"+app.CSVFormat+"\r\n") {
			t.Fatalf("export must start with BOM and format line: %q", text[:min(60, len(text))])
		}
		r := csv.NewReader(strings.NewReader(strings.SplitN(text, "\r\n", 2)[1]))
		r.Comma = ';'
		rows, err := r.ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		return rows
	}
	rows := parse(call(env.watcher, "GET", "/api/v1/assets/export.csv", "", 200))
	if len(rows) != 3 || rows[0][0] != "asset_uid" || rows[0][1] != "business_revision" {
		t.Fatalf("export rows: %v", rows)
	}
	revision := map[string]string{}
	for _, r := range rows[1:] {
		revision[r[0]] = r[1]
	}
	file := func(lines ...string) string {
		return "\uFEFF" + app.CSVFormat + "\r\nasset_uid;business_revision;display_name;criticality;tags;asset_class\r\n" + strings.Join(lines, "\r\n") + "\r\n"
	}
	body := file(a+";"+revision[a]+";'=Сервер 1С;high;1c, prod ,1c;server", b+";"+revision[b]+";;;;", "00000000-0000-4000-8000-000000000999;1;X;;;", b+";"+revision[b]+";;extreme;;")
	ct := []string{"Content-Type", "text/csv; charset=utf-8"}
	importCSV := func(c c31Client, dry, body string, want int) app.CSVImportResult {
		t.Helper()
		raw := call(c, "POST", "/api/v1/assets/import.csv?dry_run="+dry, body, want, ct...)
		var out app.CSVImportResult
		if want == 200 {
			env.valid(urn, "CSVImportResult", raw)
			_ = json.Unmarshal(raw, &out)
		}
		return out
	}
	importCSV(env.watcher, "false", body, 403)
	call(env.op, "POST", "/api/v1/assets/import.csv?dry_run=false", body, 415)
	call(env.op, "POST", "/api/v1/assets/import.csv", body, 400, ct...)
	importCSV(env.op, "false", strings.Replace(body, ";v1", ";v2", 1), 422)
	// пробный прогон: итоги по строкам, без изменений
	dry := importCSV(env.op, "true", body, 200)
	if dry.Counts["applied"] != 1 || dry.Counts["unchanged"] != 1 || dry.Counts["not_found"] != 1 || dry.Results[3].Status != "invalid" || dry.Results[3].Field == nil || *dry.Results[3].Field != "asset_uid" {
		t.Fatalf("dry run: %+v", dry)
	}
	if after := parse(call(env.op, "GET", "/api/v1/assets/export.csv", "", 200)); after[1][1] != rows[1][1] || after[2][1] != rows[2][1] {
		t.Fatal("dry run must not change revisions")
	}
	bad := importCSV(env.op, "true", file(b+";"+revision[b]+";;extreme;;"), 200)
	if bad.Counts["invalid"] != 1 || *bad.Results[0].Field != "criticality" {
		t.Fatalf("invalid field must be named: %+v", bad)
	}
	// применение: поля и класс, ревизия +2, формула сохранена как текст, история и событие CSV_IMPORT
	done := importCSV(env.op, "false", body, 200)
	if done.Counts["applied"] != 1 || done.Results[0].Revision == nil {
		t.Fatalf("apply: %+v", done)
	}
	var name, class string
	var tags []string
	_ = f.pool.QueryRow(f.ctx, "SELECT display_name,asset_class,tags FROM assets.asset_business_fields WHERE tenant_id=$1 AND asset_uid=$2", tenant, a).Scan(&name, &class, &tags)
	if name != "=Сервер 1С" || class != "server" || strings.Join(tags, "|") != "1c|prod" {
		t.Fatal("imported fields", name, class, tags)
	}
	var history, events int
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM assets.asset_changes WHERE tenant_id=$1 AND asset_uid=$2 AND reason_code='CSV_IMPORT'", tenant, a).Scan(&history)
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM messaging.outbox_events WHERE tenant_id=$1 AND aggregate_id=$2 AND event_type='asset.facts_changed.v1'", tenant, a).Scan(&events)
	if history != 1 || events < 1 {
		t.Fatal("csv import must version the asset", history, events)
	}
	exported := parse(call(env.op, "GET", "/api/v1/assets/export.csv", "", 200))
	for _, r := range exported[1:] {
		if r[0] == a && (r[2] != "'=Сервер 1С" || r[6] != "server" || r[1] != *done.Results[0].Revision) {
			t.Fatalf("export must neutralize formulas and show the new revision: %v", r)
		}
	}
	// повтор того же файла — ревизия устарела, без изменений
	again := importCSV(env.op, "false", body, 200)
	if again.Results[0].Status != "stale_revision" || *again.Results[0].Revision != *done.Results[0].Revision {
		t.Fatalf("stale revision: %+v", again)
	}
	// снятие класса «-»
	clear := importCSV(env.op, "false", file(a+";"+*done.Results[0].Revision+";;;;-"), 200)
	var cls *string
	_ = f.pool.QueryRow(f.ctx, "SELECT asset_class FROM assets.asset_business_fields WHERE tenant_id=$1 AND asset_uid=$2", tenant, a).Scan(&cls)
	if clear.Counts["applied"] != 1 || cls != nil {
		t.Fatal("class must be cleared", clear, cls)
	}
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}
