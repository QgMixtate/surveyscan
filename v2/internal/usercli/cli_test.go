package usercli

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func invoke(ctx context.Context, args ...string) (int, string, string) {
	var out, err bytes.Buffer
	code := Run(ctx, args, &out, &err)
	return code, out.String(), err.String()
}
func TestLoginPrivateContextAndRemoteLogout(t *testing.T) {
	tenant, user := identifier.New(), identifier.New()
	var revoked atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/auth/sessions":
			if r.Header.Get("Origin") == "" {
				t.Error("login origin missing")
			}
			http.SetCookie(w, &http.Cookie{Name: "surveyscan_session", Value: "synthetic-cookie"})
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(map[string]any{"tenant_id": tenant, "user_id": user, "csrf_token": "synthetic-csrf", "expires_at": time.Now().Add(time.Hour)})
		case "/api/v1/auth/session":
			if r.Header.Get("Cookie") != "surveyscan_session=synthetic-cookie" || r.Header.Get("X-CSRF-Token") != "synthetic-csrf" {
				t.Error("logout authentication missing")
			}
			revoked.Store(true)
			w.WriteHeader(204)
		default:
			t.Error("unexpected endpoint")
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	dir := t.TempDir()
	password := filepath.Join(dir, "password")
	if e := os.WriteFile(password, []byte("synthetic-password"), 0600); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "context.json")
	code, out, err := invoke(context.Background(), "login", "--context-file", path, "--server", server.URL, "--dev-loopback-http", "--username", "test", "--password-file", password)
	if code != 0 || strings.Contains(out+err, "synthetic-") {
		t.Fatal("login failed or leaked credentials", code, out, err)
	}
	info, e := os.Stat(path)
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("context not private", e)
	}
	code, out, err = invoke(context.Background(), "context", "show", "--context-file", path)
	if code != 0 || !strings.Contains(out, tenant) || strings.Contains(out+err, "synthetic-") {
		t.Fatal("context show exposed secret")
	}
	code, _, _ = invoke(context.Background(), "login", "--context-file", path, "--server", server.URL, "--dev-loopback-http", "--username", "test", "--password-file", password)
	if code != 2 {
		t.Fatal("existing context overwritten")
	}
	code, _, err = invoke(context.Background(), "logout", "--context-file", path)
	if code != 0 || !revoked.Load() {
		t.Fatal("logout did not revoke remote session", err)
	}
	if _, e = os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("logout retained credential file")
	}
}
func TestFailuresAndRedirectNeverEchoOrForwardCredential(t *testing.T) {
	var received atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received.Add(1) }))
	defer destination.Close()
	var redirect atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if redirect.Load() {
			http.Redirect(w, r, destination.URL, 302)
			return
		}
		w.WriteHeader(403)
		_, _ = w.Write([]byte("synthetic-secret-from-error"))
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "context.json")
	p := profile{Version: 1, Server: server.URL, DevHTTP: true, Tenant: identifier.New(), User: identifier.New(), Cookie: "surveyscan_session=synthetic-secret", CSRF: "csrf", Expires: time.Now().Add(time.Hour)}
	if e := writeNew(path, p); e != nil {
		t.Fatal(e)
	}
	code, out, err := invoke(context.Background(), "assets", "get", "--context-file", path, "--id", identifier.New())
	if code != 3 || strings.Contains(out+err, "synthetic-secret") {
		t.Fatal("API error leaked response/credential", code, out, err)
	}
	// A forbidden logout must retain the context so it can be retried, unlike an expired401.
	code, _, _ = invoke(context.Background(), "logout", "--context-file", path)
	if code != 3 {
		t.Fatal("forbidden logout succeeded")
	}
	if _, e := os.Stat(path); e != nil {
		t.Fatal("forbidden logout removed context")
	}
	redirect.Store(true)
	code, _, _ = invoke(context.Background(), "assets", "list", "--context-file", path)
	if code != 6 || received.Load() != 0 {
		t.Fatal("redirect forwarded credentials")
	}
	if e := os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
	code, _, _ = invoke(context.Background(), "context", "show", "--context-file", path)
	if code != 2 {
		t.Fatal("public context accepted")
	}
}
func TestOriginValidationAndTimeout(t *testing.T) {
	for _, p := range []profile{{Server: "http://example.invalid", DevHTTP: true}, {Server: "https://user:password@example.invalid"}, {Server: "https://example.invalid/api"}, {Server: "http://127.0.0.1:1"}} {
		if c, e := client(p); e == nil {
			c.CloseIdleConnections()
			t.Fatal("unsafe origin accepted")
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	p := profile{Server: server.URL, DevHTTP: true}
	c, e := client(p)
	if e != nil {
		t.Fatal(e)
	}
	defer c.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, _, e = call(ctx, c, p, "GET", "/wait", nil)
	if e == nil {
		t.Fatal("timeout ignored")
	}
}

func TestTableOutputWhitelistsFieldsAndRemovesTerminalControls(t *testing.T) {
	var out bytes.Buffer
	raw := []byte(`{"items":[{"asset_uid":"test-id","observed_hostname":"host\u001b[31m\nname","freshness":"fresh","cookie":"must-not-print"}],"next_cursor":null}`)
	if e := render(&out, raw, "assets list", "table"); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(out.String(), "\x1b") || strings.Contains(out.String(), "must-not-print") || !strings.Contains(out.String(), "ASSET_UID") {
		t.Fatal("table leaked extra fields or terminal controls", out.String())
	}
}

// C23.03: CLI отправляет пакет как есть (zip), с сессией, Origin и CSRF; ответ печатается; ошибки — коды выхода.
func TestPortableImportUploadsPackage(t *testing.T) {
	source := identifier.New()
	pkg := bytes.Repeat([]byte("PK\x03\x04synthetic"), 1000)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/v1/sources/"+source+"/portable-import" || r.Header.Get("Content-Type") != "application/zip" || r.Header.Get("X-CSRF-Token") != "csrf" || r.Header.Get("Origin") == "" || r.Header.Get("Cookie") == "" {
			w.WriteHeader(400)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if !bytes.Equal(body, pkg) {
			w.WriteHeader(422)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"source_id":"` + source + `","records":[{"observation_id":"x","disposition":"applied"}],"complete":true,"remaining":0}`))
	}))
	defer server.Close()
	dir := t.TempDir()
	path := filepath.Join(dir, "context.json")
	if e := writeNew(path, profile{Version: 1, Server: server.URL, DevHTTP: true, Tenant: identifier.New(), User: identifier.New(), Cookie: "surveyscan_session=s", CSRF: "csrf", Expires: time.Now().Add(time.Hour)}); e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(dir, "audit.zip")
	if e := os.WriteFile(file, pkg, 0o600); e != nil {
		t.Fatal(e)
	}
	code, out, err := invoke(context.Background(), "sources", "portable-import", "--context-file", path, "--id", source, "--package", file)
	if code != 0 || !strings.Contains(out, `"applied"`) {
		t.Fatal("upload failed", code, out, err)
	}
	if code, _, _ = invoke(context.Background(), "sources", "portable-import", "--context-file", path, "--id", "bad", "--package", file); code != 2 {
		t.Fatal("invalid source id must be an argument error", code)
	}
	if code, _, _ = invoke(context.Background(), "sources", "portable-import", "--context-file", path, "--id", source, "--package", filepath.Join(dir, "missing.zip")); code != 2 {
		t.Fatal("missing package must be an argument error", code)
	}
	if code, _, _ = invoke(context.Background(), "sources", "portable-import", "--context-file", path, "--id", identifier.New(), "--package", file); code != 6 {
		t.Fatal("server rejection must map to API failure exit code", code)
	}
}

// Большой пакет центр обрабатывает частями: CLI повторяет загрузку до complete=true и объединяет итог.
func TestPortableImportResumesUntilComplete(t *testing.T) {
	source := identifier.New()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		if calls.Add(1) == 1 {
			_, _ = w.Write([]byte(`{"source_id":"` + source + `","records":[{"observation_id":"a","disposition":"applied","asset_id":"u1"}],"complete":false,"remaining":1}`))
			return
		}
		_, _ = w.Write([]byte(`{"source_id":"` + source + `","records":[{"observation_id":"a","disposition":"duplicate","asset_id":"u1"},{"observation_id":"b","disposition":"applied","asset_id":"u2"}],"complete":true,"remaining":0}`))
	}))
	defer server.Close()
	dir := t.TempDir()
	path := filepath.Join(dir, "context.json")
	if e := writeNew(path, profile{Version: 1, Server: server.URL, DevHTTP: true, Tenant: identifier.New(), User: identifier.New(), Cookie: "surveyscan_session=s", CSRF: "csrf", Expires: time.Now().Add(time.Hour)}); e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(dir, "audit.zip")
	if e := os.WriteFile(file, []byte("PK"), 0o600); e != nil {
		t.Fatal(e)
	}
	code, out, err := invoke(context.Background(), "sources", "portable-import", "--context-file", path, "--id", source, "--package", file)
	if code != 0 || calls.Load() != 2 {
		t.Fatal("must resume until complete", code, calls.Load(), err)
	}
	var r struct {
		Records []struct {
			ID          string `json:"observation_id"`
			Disposition string `json:"disposition"`
		} `json:"records"`
		Complete bool `json:"complete"`
		Attempts int  `json:"attempts"`
	}
	if e := json.Unmarshal([]byte(out), &r); e != nil || !r.Complete || r.Attempts != 2 || len(r.Records) != 2 || r.Records[0].Disposition != "applied" || r.Records[1].Disposition != "applied" {
		t.Fatal("merged report must keep first non-duplicate result per record:", out)
	}
}

// C25.02: команды очереди разбора — список по состоянию и решение с CSRF и телом JSON.
func TestReconciliationCommands(t *testing.T) {
	conflict, asset := identifier.New(), identifier.New()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/v1/reconciliation/conflicts" && r.URL.Query().Get("state") == "dismissed":
			_, _ = w.Write([]byte(`{"items":[],"next_cursor":null}`))
		case r.Method == "POST" && r.URL.Path == "/api/v1/reconciliation/conflicts/"+conflict+"/resolve" && r.Header.Get("X-CSRF-Token") == "csrf":
			var body map[string]string
			if json.NewDecoder(r.Body).Decode(&body) != nil || body["action"] != "attach" || body["asset_uid"] != asset {
				w.WriteHeader(422)
				return
			}
			_, _ = w.Write([]byte(`{"conflict_id":"` + conflict + `","action":"attach","asset_uid":"` + asset + `","replayed_observations":1}`))
		default:
			w.WriteHeader(400)
		}
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "context.json")
	if e := writeNew(path, profile{Version: 1, Server: server.URL, DevHTTP: true, Tenant: identifier.New(), User: identifier.New(), Cookie: "surveyscan_session=s", CSRF: "csrf", Expires: time.Now().Add(time.Hour)}); e != nil {
		t.Fatal(e)
	}
	if code, out, err := invoke(context.Background(), "reconciliation", "list", "--context-file", path, "--state", "dismissed"); code != 0 || !strings.Contains(out, "items") {
		t.Fatal("list", code, out, err)
	}
	if code, out, err := invoke(context.Background(), "reconciliation", "resolve", "--context-file", path, "--id", conflict, "--action", "attach", "--asset", asset); code != 0 || !strings.Contains(out, "replayed_observations") {
		t.Fatal("resolve", code, out, err)
	}
	if code, _, _ := invoke(context.Background(), "reconciliation", "resolve", "--context-file", path, "--id", "bad", "--action", "attach"); code != 2 {
		t.Fatal("invalid id must be an argument error", code)
	}
	if code, _, _ := invoke(context.Background(), "reconciliation", "list", "--context-file", path, "--state", "weird"); code != 2 {
		t.Fatal("invalid state must be an argument error", code)
	}
}
