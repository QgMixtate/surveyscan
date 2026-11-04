package usercli

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
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
