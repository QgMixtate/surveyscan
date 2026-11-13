//go:build integration

package app_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/router"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// C37.04: две организации в двух ячейках за маршрутизатором; изоляция, подделка cookie, отказ каталога, заморозка,
// перенос организации с сохранением сессии, UID и неизменяемой истории.
type cell struct {
	srv  *httptest.Server
	conn *pgx.Conn
}

func newCell(t *testing.T, tenantID, username string) cell {
	t.Helper()
	ctx, s, pool := authService(t)
	if e := s.Provision(ctx, true, tenantID, "org "+username, username, password, "admin"); e != nil {
		t.Fatal(e)
	}
	c, e := pgx.ConnectConfig(ctx, pool.Config().ConnConfig.Copy())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close(context.Background()) })
	return cell{authServer(t, s), c}
}

func catalogPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx, c, _ := database(t)
	cfg, e := pgxpool.ParseConfig("")
	if e != nil {
		t.Fatal(e)
	}
	cfg.ConnConfig = c.Config().Copy()
	p, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(p.Close)
	return p
}

func routeCookie(h http.Header) string {
	for _, v := range h.Values("Set-Cookie") {
		if strings.HasPrefix(v, "ss_route=") {
			return strings.SplitN(strings.TrimPrefix(v, "ss_route="), ";", 2)[0]
		}
	}
	return ""
}

func TestC37RouterIsolationFailClosedAndTenantMove(t *testing.T) {
	ctx := context.Background()
	a := newCell(t, tenant, "alice")
	b := newCell(t, otherTenant, "bob")
	cat := router.Catalog{Pool: catalogPool(t)}
	if e := cat.Init(ctx); e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{"cell-a", "cell-b"} {
		if e := cat.AddShard(ctx, s, "ru-1", "test"); e != nil {
			t.Fatal(e)
		}
	}
	if e := cat.Place(ctx, tenant, "cell-a", "ru-1", nil, nil, "test"); e != nil {
		t.Fatal(e)
	}
	if e := cat.Place(ctx, otherTenant, "cell-b", "ru-1", nil, nil, "test"); e != nil {
		t.Fatal(e)
	}
	n, conflicts, e := cat.SyncLogins(ctx, []router.LoginRow{{Username: "alice", Tenant: tenant}, {Username: "bob", Tenant: otherTenant}, {Username: "twin", Tenant: tenant}, {Username: "twin", Tenant: otherTenant}}, "test")
	if e != nil || n != 2 || conflicts != 1 {
		t.Fatalf("sync logins n=%d conflicts=%d %v", n, conflicts, e)
	}
	ua, _ := url.Parse(a.srv.URL)
	ub, _ := url.Parse(b.srv.URL)
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // тестовые ячейки с самоподписанным сертификатом
	r := &router.Router{Catalog: cat, Shards: map[string]*url.URL{"cell-a": ua, "cell-b": ub}, Key: []byte(strings.Repeat("k", 32)), Secure: true, TTL: time.Millisecond, Transport: tr}
	rs := httptest.NewTLSServer(r)
	t.Cleanup(rs.Close)

	alice, bob := newBrowser(t, rs), newBrowser(t, rs)
	login := func(br browser, user string) string {
		code, body, h := br.request(t, "POST", "/api/v1/auth/sessions", `{"username":"`+user+`","password":"`+password+`"}`, "", "https://ui.example", nil)
		if code != 201 {
			t.Fatalf("login %s: %d %s", user, code, body)
		}
		return routeCookie(h)
	}
	routeA, routeB := login(alice, "alice"), login(bob, "bob")
	if routeA == "" || routeB == "" || !strings.HasPrefix(routeA, tenant+".1.") {
		t.Fatalf("route cookies %q %q", routeA, routeB)
	}
	ctxOf := func(br browser, want int, wantBody string) {
		t.Helper()
		code, body, _ := br.request(t, "GET", "/test/context", "", "", "", nil)
		if code != want || (wantBody != "" && string(body) != wantBody) {
			t.Fatalf("context: %d %s, want %d %s", code, body, want, wantBody)
		}
	}
	ctxOf(alice, 200, tenant)
	ctxOf(bob, 200, otherTenant)
	// неизвестный логин и логин в конфликте — отказ без обращения к ячейкам
	if code, _, _ := alice.request(t, "POST", "/api/v1/auth/sessions", `{"username":"nobody","password":"x"}`, "", "https://ui.example", nil); code != 401 {
		t.Fatal("unknown login", code)
	}
	if code, _, _ := alice.request(t, "POST", "/api/v1/auth/sessions", `{"username":"twin","password":"x"}`, "", "https://ui.example", nil); code != 409 {
		t.Fatal("conflict login", code)
	}
	// подделка: чужая организация с подписью своей; без cookie маршрута
	raw := rs.Client()
	forged := strings.Replace(routeA, tenant, otherTenant, 1)
	for _, v := range []string{forged, "", tenant + ".1.AAAA", routeA + "x"} {
		req, _ := http.NewRequest("GET", rs.URL+"/test/context", nil)
		if v != "" {
			req.AddCookie(&http.Cookie{Name: "ss_route", Value: v})
		}
		resp, e := raw.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Fatalf("forged route %q: %d", v, resp.StatusCode)
		}
	}
	// изоляция: сессия alice с подлинным маршрутом bob попадает в ячейку B, где такой сессии нет
	rsURL, _ := url.Parse(rs.URL)
	alice.client.Jar.SetCookies(rsURL, []*http.Cookie{{Name: "ss_route", Value: routeB, Path: "/"}})
	ctxOf(alice, 401, "")
	alice.client.Jar.SetCookies(rsURL, []*http.Cookie{{Name: "ss_route", Value: routeA, Path: "/"}})
	ctxOf(alice, 200, tenant)

	// заморозка: каталог migrating → 503, запись не проходит
	if e := cat.Fence(ctx, tenant, "test"); e != nil {
		t.Fatal(e)
	}
	time.Sleep(5 * time.Millisecond)
	ctxOf(alice, 503, "")
	ctxOf(bob, 200, otherTenant)
	if e := cat.Unfence(ctx, tenant, "test"); e != nil {
		t.Fatal(e)
	}

	// перенос: пробная копия не оставляет строк; затем перенос со сверкой
	var before int
	if e := a.conn.QueryRow(ctx, "SELECT count(*) FROM access.credentials WHERE tenant_id=$1", tenant).Scan(&before); e != nil || before == 0 {
		t.Fatal("credentials in source", before, e)
	}
	rep, e := router.Move(ctx, cat, a.conn, b.conn, tenant, "cell-a", "cell-b", true, "test")
	if e != nil || rep.Outcome != "dry_run_ok" || rep.Rows == 0 {
		t.Fatalf("dry run %+v %v", rep, e)
	}
	var left int
	if e = b.conn.QueryRow(ctx, "SELECT count(*) FROM access.tenants WHERE tenant_id=$1", tenant).Scan(&left); e != nil || left != 0 {
		t.Fatal("dry run left rows", left, e)
	}
	// неверный исходный шард — отказ до заморозки
	if _, e = router.Move(ctx, cat, a.conn, b.conn, tenant, "cell-b", "cell-a", false, "test"); e == nil {
		t.Fatal("move from a wrong shard accepted")
	}
	// откат: в цели уже есть логин alice другой организации — копия падает, всё возвращается
	if _, e = b.conn.Exec(ctx, "INSERT INTO access.users(user_id,tenant_id,username,password_salt,password_hash,role) VALUES(gen_random_uuid(),$1,'alice',decode(repeat('00',16),'hex'),decode(repeat('00',32),'hex'),'viewer')", otherTenant); e != nil {
		t.Fatal(e)
	}
	rep, e = router.Move(ctx, cat, a.conn, b.conn, tenant, "cell-a", "cell-b", false, "test")
	if e == nil || rep.Outcome != "rolled_back" {
		t.Fatalf("conflicting move %+v %v", rep, e)
	}
	if p, _ := cat.Placement(ctx, tenant); p.Shard != "cell-a" || p.State != "active" || p.Epoch != 1 {
		t.Fatalf("catalog after rollback %+v", p)
	}
	time.Sleep(5 * time.Millisecond)
	ctxOf(alice, 200, tenant)
	if _, e = b.conn.Exec(ctx, "DELETE FROM access.users WHERE tenant_id=$1 AND username='alice'", otherTenant); e != nil {
		t.Fatal(e)
	}
	rep, e = router.Move(ctx, cat, a.conn, b.conn, tenant, "cell-a", "cell-b", false, "test")
	if e != nil || rep.Outcome != "moved" || rep.Epoch != 2 || len(rep.Tables) == 0 {
		t.Fatalf("move %+v %v", rep, e)
	}
	var status string
	if e = a.conn.QueryRow(ctx, "SELECT status FROM access.tenants WHERE tenant_id=$1", tenant).Scan(&status); e != nil || status != "disabled" {
		t.Fatal("source not disabled", status, e)
	}
	// ячейка A выключена: alice продолжает работу в B с прежней сессией и прежней cookie маршрута (epoch 1)
	a.srv.Close()
	time.Sleep(5 * time.Millisecond)
	ctxOf(alice, 200, tenant)
	ctxOf(bob, 200, otherTenant)
	// повторный перенос в ту же ячейку отвергается
	if _, e = router.Move(ctx, cat, b.conn, a.conn, otherTenant, "cell-b", "cell-b", false, "test"); e == nil {
		t.Fatal("same-shard move accepted")
	}

	// сводка по шардам: ограниченный fan-out, частичный отказ явно, без дублей UID и чужих размещений
	dial := func(ctx context.Context, name string) (*pgx.Conn, error) {
		switch name {
		case "cell-a":
			return pgx.ConnectConfig(ctx, a.conn.Config().Copy())
		case "cell-b":
			return pgx.ConnectConfig(ctx, b.conn.Config().Copy())
		}
		cfg := a.conn.Config().Copy()
		cfg.Port = 1 // недоступная ячейка
		return pgx.ConnectConfig(ctx, cfg)
	}
	sum := router.Summarize(ctx, cat, []string{"cell-a", "cell-b"}, dial, 2, 5*time.Second)
	if !sum.Complete || len(sum.Duplicates) != 0 || len(sum.Misplaced) != 0 || sum.Shards[0].Tenants != 0 || sum.Shards[0].Disabled != 1 || sum.Shards[1].Tenants != 2 {
		t.Fatalf("summary %+v", sum)
	}
	sum = router.Summarize(ctx, cat, []string{"cell-a", "cell-b", "cell-c"}, dial, 2, 2*time.Second)
	if sum.Complete || sum.Shards[2].OK || sum.Shards[2].Error != "unavailable" || !sum.Shards[1].OK {
		t.Fatalf("partial summary %+v", sum)
	}
	// отказ каталога: нет маршрута по умолчанию
	cat.Pool.Close()
	time.Sleep(5 * time.Millisecond)
	ctxOf(alice, 503, "")
	code, _, _ := bob.request(t, "POST", "/api/v1/auth/sessions", `{"username":"bob","password":"`+password+`"}`, "", "https://ui.example", nil)
	if code != 503 {
		t.Fatal("login with catalog down", code)
	}
}
