//go:build integration

package app_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/responsibility"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

// C31.05 (решение пользователя: интеграции включаются из Web без ручной правки конфигурации центра): настройки
// каталога через API (пароль — только запись, в ответах и журнале прогонов его нет), проверка подключения без
// изменений, синхронизация по сохранённым настройкам, оптимистичная ревизия, отключение; включение уведомлений
// кнопкой (мастер-ключ создаёт центр, повторное включение ничего не меняет); без хранилища секретов — 409.
func TestC31WebSettings(t *testing.T) {
	ld := ldapEnv(t)
	env := c31Setup(t)
	f, call := env.f, env.call
	const urn = "urn:surveyscan:c31:integrations:1:0"
	call(env.admin, "PUT", "/api/v1/directory-sync/settings", `{"revision":"","settings":{"url":"ldaps://x.test","base_dn":"dc=x","bind_dn":"cn=r"},"password":"p"}`, 409) // хранилища нет
	call(env.admin, "POST", "/api/v1/webhooks/enable", `{}`, 409)
	store := t.TempDir()
	f.registry.Secrets = app.FileSecrets{Dir: store}

	base := "ou=w" + strings.ReplaceAll(identifier.New()[:8], "-", "") + "," + ld["BASE_DN"]
	seed := "dn: " + base + "\nobjectClass: organizationalUnit\n\n"
	for _, p := range [][2]string{{"ivanov", "Иван Иванов"}, {"sidorov", "Пётр Сидоров"}} {
		seed += fmt.Sprintf("dn: uid=%s,%s\nobjectClass: inetOrgPerson\nuid: %s\ncn: %s\nsn: %s\ndisplayName: %s\nmail: %s@example.test\n\n", p[0], base, p[0], p[1], p[1], p[1], p[0])
	}
	ldapAdmin(t, ld, "ldapadd", seed)
	t.Cleanup(func() { ldapAdmin(t, ld, "ldapdelete", base+"\n", "-r") })
	ca, _ := os.ReadFile(ld["CA_FILE"])
	password, _ := os.ReadFile(ld["PASSWORD_FILE"])
	pw := strings.TrimSpace(string(password))
	settings := map[string]any{"url": ld["URL"], "base_dn": base, "bind_dn": ld["BIND_DN"], "user_filter": "(objectClass=inetOrgPerson)",
		"guid_attribute": "entryUUID", "login_attribute": "uid", "changed_attribute": "modifyTimestamp", "ca_certificate_pem": string(ca)}
	body := func(revision string, password *string) string {
		m := map[string]any{"revision": revision, "settings": settings}
		if password != nil {
			m["password"] = *password
		}
		raw, _ := json.Marshal(m)
		return string(raw)
	}
	view := func(raw []byte) app.DirectorySettingsView {
		t.Helper()
		env.valid(urn, "DirectorySettingsView", raw)
		if strings.Contains(string(raw), pw) {
			t.Fatal("password must never be returned")
		}
		var v app.DirectorySettingsView
		_ = json.Unmarshal(raw, &v)
		return v
	}

	// 1. пусто; первая настройка без пароля — отказ; права
	if v := view(call(env.admin, "GET", "/api/v1/directory-sync/settings", "", 200)); v.Source != "none" || !v.SecretsAvailable || v.PasswordSet {
		t.Fatalf("initial: %+v", v)
	}
	call(env.op, "GET", "/api/v1/directory-sync/settings", "", 403)
	call(env.admin, "PUT", "/api/v1/directory-sync/settings", body("", nil), 422)
	call(env.op, "PUT", "/api/v1/directory-sync/settings", body("", &pw), 403)

	// 2. проверка подключения: неверный пароль — ошибка в ответе; верный — люди найдены; ничего не меняется
	bad := "wrong-secret-value"
	var test app.DirectoryTestResult
	raw := call(env.admin, "POST", "/api/v1/directory-sync/test", body("", &bad), 200)
	env.valid(urn, "DirectoryTestResult", raw)
	_ = json.Unmarshal(raw, &test)
	if test.OK || test.Error == nil || strings.Contains(*test.Error, bad) {
		t.Fatalf("wrong password test: %s", raw)
	}
	test = app.DirectoryTestResult{}
	_ = json.Unmarshal(call(env.admin, "POST", "/api/v1/directory-sync/test", body("", &pw), 200), &test)
	if !test.OK || test.People != 2 {
		t.Fatalf("test: %+v", test)
	}
	// адрес по IP (сертификат выписан на имя): без имени — отказ TLS; с именем в сертификате — работает
	byIP := strings.Replace(ld["URL"], "localhost", "127.0.0.1", 1)
	settings["url"] = byIP
	test = app.DirectoryTestResult{}
	_ = json.Unmarshal(call(env.admin, "POST", "/api/v1/directory-sync/test", body("", &pw), 200), &test)
	if test.OK || test.Error == nil || !strings.Contains(*test.Error, "IP SANs") || !strings.Contains(*test.Error, "Имя контроллера в сертификате") {
		t.Fatalf("IP address without tls_server_name must fail certificate check: %+v", test)
	}
	settings["tls_server_name"] = "localhost"
	test = app.DirectoryTestResult{}
	_ = json.Unmarshal(call(env.admin, "POST", "/api/v1/directory-sync/test", body("", &pw), 200), &test)
	if !test.OK {
		t.Fatalf("tls_server_name must allow IP address with a name certificate: %+v", test)
	}
	settings["tls_server_name"] = "wrong.example.test"
	test = app.DirectoryTestResult{}
	_ = json.Unmarshal(call(env.admin, "POST", "/api/v1/directory-sync/test", body("", &pw), 200), &test)
	if test.OK {
		t.Fatal("wrong tls_server_name must still fail: certificate check is not disabled")
	}
	settings["url"] = ld["URL"]
	delete(settings, "tls_server_name")
	var subjects int
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM responsibility.subjects WHERE tenant_id=$1 AND origin='ldap'", tenant).Scan(&subjects)
	if subjects != 0 {
		t.Fatal("connection test must not change subjects")
	}

	// 3. сохранение: пароль в хранилище (0600), не в БД; синхронизация по сохранённым настройкам
	v := view(call(env.admin, "PUT", "/api/v1/directory-sync/settings", body("", &pw), 200))
	if v.Source != "web" || !v.PasswordSet || v.Revision == nil {
		t.Fatalf("saved: %+v", v)
	}
	info, err := os.Stat(filepath.Join(store, tenant, "ldap-bind-password"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("password file", err)
	}
	var inDB int
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM responsibility.directory_settings WHERE settings::text LIKE '%'||$1||'%'", pw).Scan(&inDB)
	if inDB != 0 {
		t.Fatal("password must not be stored in the database")
	}
	var status app.DirectorySyncStatus
	_ = json.Unmarshal(call(env.watcher, "GET", "/api/v1/directory-sync", "", 200), &status)
	if !status.Configured {
		t.Fatal("web settings must configure sync")
	}
	var run responsibility.SyncRun
	_ = json.Unmarshal(call(env.admin, "POST", "/api/v1/directory-sync/run", `{"mode":"full"}`, 200), &run)
	var c responsibility.SyncCounters
	_ = json.Unmarshal(run.Counters, &c)
	if run.Status != "succeeded" || c.Created != 2 || c.LoginsLinked != 1 {
		t.Fatalf("sync by web settings: %+v %s", run, run.Counters)
	}

	// 4. правка без пароля сохраняет прежний; устаревшая ревизия — 412; отключение
	settings["interval_minutes"] = 30
	v2 := view(call(env.admin, "PUT", "/api/v1/directory-sync/settings", body(*v.Revision, nil), 200))
	call(env.admin, "PUT", "/api/v1/directory-sync/settings", body(*v.Revision, nil), 412)
	if v2.Settings.IntervalMinutes != 30 || !v2.PasswordSet {
		t.Fatalf("update: %+v", v2)
	}
	run = responsibility.SyncRun{}
	_ = json.Unmarshal(call(env.admin, "POST", "/api/v1/directory-sync/run", `{"mode":"auto"}`, 200), &run)
	if run.Status != "succeeded" {
		t.Fatalf("sync after update: %+v", run)
	}
	settings["url"] = "ldap://plain.example.test"
	call(env.admin, "PUT", "/api/v1/directory-sync/settings", body(*v2.Revision, nil), 422) // ldap:// из Web не принимается
	call(env.admin, "DELETE", "/api/v1/directory-sync/settings?revision="+*v2.Revision, "", 204)
	_ = json.Unmarshal(call(env.watcher, "GET", "/api/v1/directory-sync", "", 200), &status)
	if status.Configured {
		t.Fatal("deleted settings must disable sync")
	}
	var audits int
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM audit.audit_events WHERE tenant_id=$1 AND action LIKE 'responsibility.directory_settings_%'", tenant).Scan(&audits)
	if audits != 3 {
		t.Fatal("settings changes must be audited", audits)
	}

	// 5. уведомления кнопкой
	var list app.WebhookList
	_ = json.Unmarshal(call(env.admin, "GET", "/api/v1/webhooks", "", 200), &list)
	if list.Enabled || !list.CanEnable {
		t.Fatalf("before enable: %+v", list)
	}
	call(env.op, "POST", "/api/v1/webhooks/enable", `{}`, 403)
	raw = call(env.admin, "POST", "/api/v1/webhooks/enable", `{}`, 200)
	env.valid(urn, "WebhookList", raw)
	_ = json.Unmarshal(raw, &list)
	master := filepath.Join(store, "center", "webhook-master")
	before, err := os.ReadFile(master)
	if !list.Enabled || err != nil || len(before) != 32 {
		t.Fatalf("enable: %+v %v", list, err)
	}
	call(env.admin, "POST", "/api/v1/webhooks/enable", `{}`, 200)
	after, _ := os.ReadFile(master)
	if string(before) != string(after) {
		t.Fatal("second enable must keep the master key")
	}
	raw = call(env.admin, "POST", "/api/v1/webhooks", `{"url":"https://itsm.example.test/hook","event_types":["asset.facts_changed.v1"]}`, 201)
	env.valid(urn, "WebhookCreated", raw)
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM audit.audit_events WHERE tenant_id=$1 AND action='messaging.webhooks_enabled'", tenant).Scan(&audits)
	if audits != 1 {
		t.Fatal("enable must be audited once", audits)
	}
	// перезапуск центра: ключ подхватывается из хранилища
	restarted, err := app.NewRegistry(f.pool, f.users)
	if err != nil {
		t.Fatal(err)
	}
	restarted.Secrets = app.FileSecrets{Dir: store}
	if err = restarted.LoadIntegrations(f.ctx); err != nil || restarted.Webhooks == nil {
		t.Fatal("restart must load enabled webhooks", err)
	}
}
