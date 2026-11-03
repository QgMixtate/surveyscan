//go:build integration

package app_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/health"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const password = "synthetic test passphrase C05"
const otherTenant = "00000000-0000-4000-8000-000000000099"

func authService(t *testing.T) (context.Context, *access.Service, *pgxpool.Pool) {
	t.Helper()
	ctx, c, ms := database(t)
	apply(t, ctx, c, ms)
	cfg, e := pgxpool.ParseConfig("")
	if e != nil {
		t.Fatal(e)
	}
	cfg.ConnConfig = c.Config().Copy()
	cfg.MaxConns = 8
	pool, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(pool.Close)
	s := access.New(pool)
	return ctx, s, pool
}
func bootstrap(t *testing.T, ctx context.Context, s *access.Service) {
	t.Helper()
	if e := s.Provision(ctx, true, tenant, "test", "admin", password, "admin"); e != nil {
		t.Fatal(e)
	}
}
func TestC05ConcurrentBootstrapAndPasswordHash(t *testing.T) {
	ctx, s, pool := authService(t)
	start := time.Now()
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- s.Provision(ctx, true, tenant, "test", "admin", password, "admin") }()
	}
	wg.Wait()
	close(errs)
	ok, conflicts := 0, 0
	for e := range errs {
		if e == nil {
			ok++
		} else if errors.Is(e, access.ErrConflict) {
			conflicts++
		} else {
			t.Fatal(e)
		}
	}
	if ok != 1 || conflicts != 1 {
		t.Fatal(ok, conflicts)
	}
	var salt, hash []byte
	var algo string
	if e := pool.QueryRow(ctx, "SELECT password_salt,password_hash,password_algorithm FROM access.users WHERE username='admin'").Scan(&salt, &hash, &algo); e != nil {
		t.Fatal(e)
	}
	if len(salt) != 16 || len(hash) != 32 || strings.Contains(string(hash), password) || algo != "argon2id-m65536-t3-p1-v19" {
		t.Fatal("invalid password metadata")
	}
	t.Log("two concurrent Argon2id bootstrap attempts:", time.Since(start))
	if e := s.Provision(ctx, false, tenant, "", "weak", "short", "viewer"); !errors.Is(e, access.ErrInvalid) {
		t.Fatal(e)
	}
}

type browser struct {
	client *http.Client
	base   string
}

func (b browser) request(t *testing.T, method, path, body, csrf, origin string, headers map[string]string) (int, []byte, http.Header) {
	t.Helper()
	req, e := http.NewRequest(method, b.base+path, strings.NewReader(body))
	if e != nil {
		t.Fatal(e)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, e := b.client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	data, e := io.ReadAll(io.LimitReader(resp.Body, 32768))
	if e != nil {
		t.Fatal(e)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Error("missing no-store")
	}
	return resp.StatusCode, data, resp.Header
}
func (b browser) login(t *testing.T, username string) access.Session {
	t.Helper()
	data, _ := json.Marshal(map[string]string{"username": username, "password": password})
	code, body, headers := b.request(t, "POST", "/api/v1/auth/sessions", string(data), "", "https://ui.example", nil)
	if code != 201 {
		t.Fatalf("login status=%d body=%s", code, body)
	}
	cookie := headers.Get("Set-Cookie")
	for _, flag := range []string{"HttpOnly", "Secure", "SameSite=Strict", "Path=/"} {
		if !strings.Contains(cookie, flag) {
			t.Error("cookie missing", flag)
		}
	}
	var session access.Session
	if e := json.Unmarshal(body, &session); e != nil {
		t.Fatal(e)
	}
	return session
}
func newBrowser(t *testing.T, srv *httptest.Server) browser {
	t.Helper()
	c := *srv.Client()
	jar, e := cookiejar.New(nil)
	if e != nil {
		t.Fatal(e)
	}
	c.Jar = jar
	return browser{&c, srv.URL}
}
func authServer(t *testing.T, s *access.Service) *httptest.Server {
	t.Helper()
	a, e := access.NewHTTP(s, "https://ui.example", false)
	if e != nil {
		t.Fatal(e)
	}
	h, e := app.NewHTTP(a, health.Handler(func(context.Context) error { return nil }))
	if e != nil {
		t.Fatal(e)
	}
	mux := h.(*http.ServeMux)
	mux.Handle("GET /test/context", a.Wrap("assets:read", false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, _ := access.Identity(r.Context())
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(id.TenantID))
	})))
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	return srv
}
func expect(t *testing.T, want, got int) {
	t.Helper()
	if want != got {
		t.Fatalf("status: want %d, got %d", want, got)
	}
}
func TestC05HTTPOriginCSRFRoleAndTenantContext(t *testing.T) {
	ctx, s, pool := authService(t)
	bootstrap(t, ctx, s)
	for _, role := range []string{"operator", "viewer"} {
		if e := s.Provision(ctx, false, tenant, "", role, password, role); e != nil {
			t.Fatal(e)
		}
	}
	srv := authServer(t, s)
	anon := newBrowser(t, srv)
	for _, origin := range []string{"", "https://evil.example", "null"} {
		code, _, _ := anon.request(t, "POST", "/api/v1/auth/sessions", `{"username":"admin","password":"x"}`, "", origin, nil)
		expect(t, 403, code)
	}
	for _, body := range []string{`{"username":"admin","password":"wrong"}`, `{"username":"unknown","password":"wrong"}`} {
		code, data, _ := anon.request(t, "POST", "/api/v1/auth/sessions", body, "", "https://ui.example", nil)
		expect(t, 401, code)
		if bytes.Contains(data, []byte("password")) {
			t.Fatal("credential leaked")
		}
	}
	code, _, _ := anon.request(t, "POST", "/api/v1/auth/sessions", `{"username":"admin","password":"x","tenant_id":"other"}`, "", "https://ui.example", nil)
	expect(t, 400, code)
	code, _, _ = anon.request(t, "POST", "/api/v1/auth/sessions", `{"username":"admin","password":"`+strings.Repeat("x", 9000)+`"}`, "", "https://ui.example", nil)
	expect(t, 413, code)
	code, _, _ = anon.request(t, "GET", "/api/v1/assets", "", "", "", map[string]string{"X-Tenant-ID": tenant, "X-User-ID": "admin"})
	expect(t, 401, code)
	for _, role := range []string{"admin", "operator", "viewer"} {
		b := newBrowser(t, srv)
		session := b.login(t, role)
		code, body, _ := b.request(t, "GET", "/test/context", "", "", "", map[string]string{"X-Tenant-ID": otherTenant})
		expect(t, 200, code)
		if string(body) != tenant {
			t.Fatal("tenant header trusted")
		}
		code, _, _ = b.request(t, "POST", "/api/v1/jobs", `{}`, "", "https://ui.example", nil)
		expect(t, 403, code)
		code, _, _ = b.request(t, "POST", "/api/v1/jobs", `{}`, session.CSRFToken, "https://evil.example", nil)
		expect(t, 403, code)
		code, _, _ = b.request(t, "POST", "/api/v1/jobs", `{}`, session.CSRFToken, "https://ui.example", nil)
		want := 501
		if role == "viewer" {
			want = 403
		}
		expect(t, want, code)
		code, _, _ = b.request(t, "POST", "/api/v1/enrollments", `{}`, session.CSRFToken, "https://ui.example", nil)
		want = 403
		if role == "admin" {
			want = 501
		}
		expect(t, want, code)
		code, _, _ = b.request(t, "GET", "/api/v1/machine/config", "", "", "", nil)
		expect(t, 401, code)
	}
	var count int
	if e := pool.QueryRow(ctx, "SELECT count(*) FROM access.credentials WHERE kind='session'").Scan(&count); e != nil || count != 3 {
		t.Fatal(count, e)
	}
}
func TestC05TokenScopeOwnershipRevocationExpiryAndLogout(t *testing.T) {
	ctx, s, pool := authService(t)
	bootstrap(t, ctx, s)
	if _, e := pool.Exec(ctx, "INSERT INTO access.tenants(tenant_id,name,status) VALUES($1,'other','active')", otherTenant); e != nil {
		t.Fatal(e)
	}
	if e := s.Provision(ctx, false, otherTenant, "", "other", password, "viewer"); e != nil {
		t.Fatal(e)
	}
	srv := authServer(t, s)
	owner := newBrowser(t, srv)
	session := owner.login(t, "admin")
	other := newBrowser(t, srv)
	otherSession := other.login(t, "other")
	code, body, _ := owner.request(t, "POST", "/api/v1/auth/tokens", `{"name":"test","expires_in_seconds":3600,"scopes":["assets:read"]}`, session.CSRFToken, "https://ui.example", nil)
	expect(t, 201, code)
	var token access.TokenResult
	if e := json.Unmarshal(body, &token); e != nil {
		t.Fatal(e)
	}
	cli := newBrowser(t, srv)
	headers := map[string]string{"Authorization": "Bearer " + token.Token}
	code, _, _ = cli.request(t, "GET", "/api/v1/assets", "", "", "", headers)
	expect(t, 501, code)
	code, _, _ = cli.request(t, "GET", "/api/v1/sources", "", "", "", headers)
	expect(t, 403, code)
	code, _, _ = cli.request(t, "POST", "/api/v1/jobs", `{}`, "", "", headers)
	expect(t, 403, code)
	code, _, _ = owner.request(t, "GET", "/api/v1/assets", "", "", "", headers)
	expect(t, 401, code)
	code, _, _ = other.request(t, "DELETE", "/api/v1/auth/tokens/"+token.TokenID, "", otherSession.CSRFToken, "https://ui.example", nil)
	expect(t, 404, code)
	code, _, _ = owner.request(t, "DELETE", "/api/v1/auth/tokens/"+token.TokenID, "", session.CSRFToken, "https://ui.example", nil)
	expect(t, 204, code)
	code, _, _ = cli.request(t, "GET", "/api/v1/assets", "", "", "", headers)
	expect(t, 401, code)
	code, _, _ = owner.request(t, "DELETE", "/api/v1/auth/session", "", session.CSRFToken, "https://ui.example", nil)
	expect(t, 204, code)
	code, _, _ = owner.request(t, "GET", "/api/v1/assets", "", "", "", nil)
	expect(t, 401, code)
	id, raw, e := s.Login(ctx, "admin", password)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = pool.Exec(ctx, "UPDATE access.credentials SET created_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour' WHERE secret_hash=$1", access.Digest(raw)); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Authenticate(ctx, raw, "session", id.CSRFToken, false); !errors.Is(e, access.ErrAuth) {
		t.Fatal("expired accepted", e)
	}
}
func TestC05ConcurrentSessionsTokensPasswordResetAndSharedRateLimit(t *testing.T) {
	ctx, s, pool := authService(t)
	bootstrap(t, ctx, s)
	var sessions [2]access.Session
	var raws [2]string
	var errs [2]error
	var wg sync.WaitGroup
	for i := range 2 {
		wg.Add(1)
		go func(i int) { defer wg.Done(); sessions[i], raws[i], errs[i] = s.Login(ctx, "admin", password) }(i)
	}
	wg.Wait()
	ids := make([]port.Identity, 2)
	for i := range 2 {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		id, e := s.Authenticate(ctx, raws[i], "session", sessions[i].CSRFToken, true)
		if e != nil {
			t.Fatal(e)
		}
		ids[i] = id
		if _, e = s.Authenticate(ctx, raws[i], "session", sessions[1-i].CSRFToken, true); !errors.Is(e, access.ErrForbidden) {
			t.Fatal("CSRF token accepted for another session", e)
		}
	}
	var tokens [2]access.TokenResult
	for i := range 2 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tokens[i], errs[i] = s.CreateToken(ctx, ids[i], access.TokenRequest{Name: "parallel", ExpiresInSeconds: 3600, Scopes: []string{"assets:read"}})
		}(i)
	}
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	if e := s.Logout(ctx, ids[0]); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Authenticate(ctx, raws[1], "session", "", false); e != nil {
		t.Fatal("other session was revoked", e)
	}
	if e := s.ResetPassword(ctx, tenant, "admin", "new synthetic test passphrase"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Authenticate(ctx, raws[1], "session", "", false); !errors.Is(e, access.ErrAuth) {
		t.Fatal("reset did not revoke session", e)
	}
	for _, token := range tokens {
		if _, e := s.Authenticate(ctx, token.Token, "cli", "", false); !errors.Is(e, access.ErrAuth) {
			t.Fatal("reset did not revoke token", e)
		}
	}
	if _, _, e := s.Login(ctx, "admin", password); !errors.Is(e, access.ErrAuth) {
		t.Fatal("old password accepted after reset", e)
	}
	if _, _, e := s.Login(ctx, "admin", "new synthetic test passphrase"); e != nil {
		t.Fatal("new password rejected", e)
	}
	// Счётчики проверяются через реальные неудачные входы, включая второй Service/process state.
	second := access.New(pool)
	limited := false
	for i := range 22 {
		service := s
		if i%2 == 1 {
			service = second
		}
		_, _, e := service.Login(ctx, "nonexistent", password)
		if errors.Is(e, access.ErrLimit) {
			if i < 10 {
				t.Fatal("premature account limit", i)
			}
			limited = true
			break
		}
		if !errors.Is(e, access.ErrAuth) {
			t.Fatal(i, e)
		}
	}
	if !limited {
		t.Fatal("shared rate limit missing")
	}

}
func TestC05WorkerTenantAndCommitAuthorizationFence(t *testing.T) {
	ctx, s, pool := authService(t)
	bootstrap(t, ctx, s)
	session, raw, e := s.Login(ctx, "admin", password)
	if e != nil {
		t.Fatal(e)
	}
	id, e := s.Authenticate(ctx, raw, "session", session.CSRFToken, true)
	if e != nil {
		t.Fatal(e)
	}
	tx, e := pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	if _, e = s.Authorize(ctx, tx, id.CredentialID, otherTenant, "jobs:write"); !errors.Is(e, access.ErrForbidden) {
		t.Fatal("cross-tenant authorization accepted", e)
	}
	if _, e = s.Authorize(ctx, tx, id.CredentialID, tenant, "jobs:write"); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- s.ChangeUser(ctx, tenant, "admin", "viewer", false) }()
	select {
	case e := <-done:
		t.Fatalf("revocation crossed active transaction fence: %v", e)
	case <-time.After(150 * time.Millisecond):
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	select {
	case e = <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-ctx.Done():
		t.Fatal("revocation did not finish")
	}
	if _, e = s.Authenticate(ctx, raw, "session", "", false); !errors.Is(e, access.ErrAuth) {
		t.Fatal("disabled user accepted", e)
	}
}

func TestC05AuthorizationAndCredentialRevocationLockOrder(t *testing.T) {
	ctx, s, pool := authService(t)
	bootstrap(t, ctx, s)
	session, raw, e := s.Login(ctx, "admin", password)
	if e != nil {
		t.Fatal(e)
	}
	id, e := s.Authenticate(ctx, raw, "session", session.CSRFToken, true)
	if e != nil {
		t.Fatal(e)
	}
	change, e := pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer change.Rollback(ctx)
	var locked string
	if e = change.QueryRow(ctx, "SELECT user_id::text FROM access.users WHERE user_id=$1 FOR UPDATE", id.UserID).Scan(&locked); e != nil {
		t.Fatal(e)
	}
	worker, e := pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer worker.Rollback(ctx)
	var pid int
	if e = worker.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { _, e := s.Authorize(ctx, worker, id.CredentialID, tenant, "jobs:write"); done <- e }()
	waiting := false
	for range 100 {
		if e = pool.QueryRow(ctx, "SELECT cardinality(pg_blocking_pids($1))>0", pid).Scan(&waiting); e != nil {
			t.Fatal(e)
		}
		if waiting {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !waiting {
		t.Fatal("authorization did not wait for user lock")
	}
	short, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	if _, e = change.Exec(short, "UPDATE access.credentials SET revoked_at=clock_timestamp() WHERE credential_id=$1", id.CredentialID); e != nil {
		t.Fatal("authorization held credential lock while waiting for user, violating global lock order")
	}
	if e = change.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	select {
	case e = <-done:
		if !errors.Is(e, access.ErrAuth) {
			t.Fatal("revoked credential was accepted after lock wait", e)
		}
	case <-ctx.Done():
		t.Fatal("authorization did not finish")
	}
}
