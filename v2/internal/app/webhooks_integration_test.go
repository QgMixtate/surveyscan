//go:build integration

package app_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/messaging"
)

type hookCall struct {
	path    string
	headers http.Header
	body    []byte
}

// C31.03/C31.04: исходящие уведомления на тестовый HTTPS-получатель (не реальная ITSM): подпись и идемпотентный
// event_id, история не рассылается, доставленное не повторяется, повторы с паузой → dead после 5 попыток, ручной
// повтор dead с аудитом, перенаправления не выполняются, отключённая подписка не получает событий, права и ревизии.
func TestC31Webhooks(t *testing.T) {
	env := c31Setup(t)
	f, call := env.f, env.call
	const urn = "urn:surveyscan:c31:integrations:1:0"
	var mu sync.Mutex
	var calls []hookCall
	status := 200
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		mu.Lock()
		calls = append(calls, hookCall{req.URL.Path, req.Header.Clone(), body})
		code := status
		mu.Unlock()
		if code == 302 {
			http.Redirect(w, req, "/elsewhere", 302)
			return
		}
		w.WriteHeader(code)
	}))
	defer receiver.Close()
	received := func() []hookCall { mu.Lock(); defer mu.Unlock(); return append([]hookCall{}, calls...) }
	setStatus := func(c int) { mu.Lock(); status = c; mu.Unlock() }
	deliver := func() {
		t.Helper()
		if _, err := f.registry.DeliverWebhooks(f.ctx); err != nil {
			t.Fatal(err)
		}
	}
	asset := env.asset(1) // событие до подписки — не рассылается
	patch := func(name string) {
		t.Helper()
		a, err := f.registry.Get(f.ctx, f.identity, asset)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.registry.Patch(f.ctx, f.identity, asset, a.Revision, contracts.BusinessPatch{DisplayName: &name}); err != nil {
			t.Fatal(err)
		}
	}

	// без мастер-ключа уведомления выключены
	raw := call(env.admin, "GET", "/api/v1/webhooks", "", 200)
	env.valid(urn, "WebhookList", raw)
	if !strings.Contains(string(raw), `"enabled":false`) {
		t.Fatal(string(raw))
	}
	hookURL := receiver.URL + "/hook"
	create := `{"url":"` + hookURL + `","event_types":["asset.facts_changed.v1","responsibility.assigned.v1"]}`
	call(env.admin, "POST", "/api/v1/webhooks", create, 409)
	secretFile := filepath.Join(t.TempDir(), "webhook.key")
	_ = os.WriteFile(secretFile, []byte(strings.Repeat("k", 48)), 0o600)
	sender, err := app.NewWebhookSender(secretFile)
	if err != nil {
		t.Fatal(err)
	}
	sender.Client.Transport = receiver.Client().Transport // доверие к сертификату тестового получателя
	f.registry.Webhooks = sender

	call(env.op, "POST", "/api/v1/webhooks", create, 403)
	call(env.watcher, "GET", "/api/v1/webhooks", "", 403)
	for _, bad := range []string{`{"url":"http://example.test/x","event_types":["asset.created.v1"]}`, `{"url":"ftp://example.test/x","event_types":["asset.created.v1"]}`,
		`{"url":"https://user:pw@example.test/x","event_types":["asset.created.v1"]}`, `{"url":"https://example.test/x","event_types":["secret.leaked.v1"]}`,
		`{"url":"https://example.test/x","event_types":[]}`} {
		call(env.admin, "POST", "/api/v1/webhooks", bad, 422)
	}
	raw = call(env.admin, "POST", "/api/v1/webhooks", create, 201)
	env.valid(urn, "WebhookCreated", raw)
	var created app.WebhookCreated
	_ = json.Unmarshal(raw, &created)
	sub := created.Subscription.ID
	secret, err := base64.RawURLEncoding.DecodeString(created.Secret)
	if err != nil || len(secret) != 32 {
		t.Fatal("secret", err)
	}
	if list := call(env.admin, "GET", "/api/v1/webhooks", "", 200); strings.Contains(string(list), created.Secret) {
		t.Fatal("signing secret must be shown only once")
	}

	// 1. доставка: подпись, заголовки, тело по контракту; события до подписки не рассылаются
	patch("Сервер учёта")
	deliver()
	got := received()
	if len(got) != 1 {
		t.Fatalf("want 1 delivery, got %d", len(got))
	}
	h := got[0]
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(h.headers.Get("X-SurveyScan-Timestamp") + "."))
	mac.Write(h.body)
	if h.headers.Get("X-SurveyScan-Signature") != "v1="+hex.EncodeToString(mac.Sum(nil)) || h.path != "/hook" || h.headers.Get("Content-Type") != "application/json" {
		t.Fatalf("signature/headers: %v", h.headers)
	}
	env.valid(urn, "WebhookPayload", h.body)
	var payload messaging.WebhookPayload
	_ = json.Unmarshal(h.body, &payload)
	if payload.EventType != "asset.facts_changed.v1" || payload.Data["asset_uid"] != asset || payload.EventID != h.headers.Get("X-SurveyScan-Event-Id") || payload.TenantID != tenant {
		t.Fatalf("payload: %s", h.body)
	}
	deliver()
	if len(received()) != 1 {
		t.Fatal("delivered event must not be sent again")
	}

	// 2. отказ получателя: 5 попыток с одним event_id, затем dead
	setStatus(500)
	patch("Сервер учёта 2")
	for range messaging.WebhookMaxAttempts {
		deliver()
		_, _ = f.pool.Exec(f.ctx, "UPDATE messaging.webhook_deliveries SET next_attempt_at=now() WHERE state='pending'") // ускоряем паузы
	}
	deliver()
	got = received()[1:]
	if len(got) != messaging.WebhookMaxAttempts {
		t.Fatalf("want %d attempts, got %d", messaging.WebhookMaxAttempts, len(got))
	}
	failed := got[0].headers.Get("X-SurveyScan-Event-Id")
	for _, c := range got {
		if c.headers.Get("X-SurveyScan-Event-Id") != failed {
			t.Fatal("retries must keep the event id")
		}
	}
	raw = call(env.admin, "GET", "/api/v1/webhooks/"+sub+"/deliveries?state=dead", "", 200)
	env.valid(urn, "WebhookDeliveryPage", raw)
	var page app.WebhookDeliveryPage
	_ = json.Unmarshal(raw, &page)
	if len(page.Items) != 1 || page.Items[0].EventID != failed || page.Items[0].Attempts != 5 || page.Items[0].LastStatus == nil || *page.Items[0].LastStatus != 500 {
		t.Fatalf("dead letter: %s", raw)
	}

	// 3. ручной повтор dead (аудит); доставленное повторить нельзя
	setStatus(204)
	call(env.op, "POST", "/api/v1/webhooks/"+sub+"/deliveries/"+failed+"/retry", "", 403)
	call(env.admin, "POST", "/api/v1/webhooks/"+sub+"/deliveries/"+failed+"/retry", "", 204)
	deliver()
	call(env.admin, "POST", "/api/v1/webhooks/"+sub+"/deliveries/"+failed+"/retry", "", 409)
	call(env.admin, "POST", "/api/v1/webhooks/"+sub+"/deliveries/"+payload.EventID+"/retry", "", 409)
	var audits int
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM audit.audit_events WHERE tenant_id=$1 AND action='messaging.webhook_redelivery_requested'", tenant).Scan(&audits)
	raw = call(env.admin, "GET", "/api/v1/webhooks", "", 200)
	var list app.WebhookList
	_ = json.Unmarshal(raw, &list)
	if audits != 1 || len(list.Items) != 1 || list.Items[0].Delivered != 2 || list.Items[0].Dead != 0 || len(received()) != 7 {
		t.Fatalf("redelivery: audits=%d calls=%d %s", audits, len(received()), raw)
	}

	// 4. перенаправление не выполняется
	setStatus(302)
	patch("Сервер учёта 3")
	deliver()
	for _, c := range received() {
		if c.path == "/elsewhere" {
			t.Fatal("redirect must not be followed")
		}
	}
	page = app.WebhookDeliveryPage{}
	_ = json.Unmarshal(call(env.admin, "GET", "/api/v1/webhooks/"+sub+"/deliveries?state=pending", "", 200), &page)
	if len(page.Items) != 1 || page.Items[0].LastError == nil || !strings.Contains(*page.Items[0].LastError, "302") || page.Items[0].NextAt == nil {
		t.Fatalf("redirect must be a failed attempt: %+v", page.Items)
	}

	// 5. отключённая подписка: новых доставок нет; ревизия обязательна и проверяется
	call(env.admin, "PATCH", "/api/v1/webhooks/"+sub, `{"revision":"1","active":false}`, 200)
	call(env.admin, "PATCH", "/api/v1/webhooks/"+sub, `{"revision":"1","active":true}`, 412)
	call(env.admin, "PATCH", "/api/v1/webhooks/"+sub, `{"revision":"2","url":"http://example.test/x"}`, 422)
	before := len(received())
	setStatus(200)
	patch("Сервер учёта 4")
	_, _ = f.pool.Exec(f.ctx, "UPDATE messaging.webhook_deliveries SET next_attempt_at=now() WHERE state='pending'")
	deliver()
	var rows int
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM messaging.webhook_deliveries WHERE tenant_id=$1 AND subscription_id=$2", tenant, sub).Scan(&rows)
	if len(received()) != before || rows != 3 {
		t.Fatalf("inactive subscription: calls %d→%d, rows=%d", before, len(received()), rows)
	}
}
