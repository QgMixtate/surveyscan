package app

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	accessport "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/buildinfo"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/messaging"
)

// C31.03 (ADR decisions/C31-integrations.md): исходящие уведомления. Подпись HMAC-SHA256 над «timestamp.body» ключом
// подписки; ключ выводится из приватного файла центра (webhook_secret_file) и ID подписки — в БД его нет, выдаётся
// администратору один раз при создании. Доставка «как минимум один раз», X-SurveyScan-Event-Id для отбрасывания повторов.

type WebhookSender struct {
	master []byte
	Client *http.Client
}

func NewWebhookSender(secretFile string) (*WebhookSender, error) {
	master, e := ReadPrivate(secretFile, 4096)
	if e != nil {
		return nil, e
	}
	master = bytes.TrimSpace(master)
	if len(master) < 32 {
		return nil, errors.New("webhook_secret_file must hold at least 32 bytes")
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, Proxy: http.ProxyFromEnvironment, MaxIdleConnsPerHost: 4},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }} // перенаправления не выполняются
	return &WebhookSender{master: master, Client: client}, nil
}

// Key — ключ подписи подписки (выводится, не хранится).
func (s *WebhookSender) Key(tenant, subscription string) []byte {
	m := hmac.New(sha256.New, s.master)
	m.Write([]byte("surveyscan-webhook-v1\x00" + tenant + "\x00" + subscription))
	return m.Sum(nil)
}

// WebhookSignature — значение X-SurveyScan-Signature: v1=hex(HMAC-SHA256(key, timestamp + "." + body)).
func WebhookSignature(key []byte, timestamp string, body []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(timestamp + "."))
	m.Write(body)
	return "v1=" + hex.EncodeToString(m.Sum(nil))
}

func validWebhookURL(raw string) bool {
	u, e := url.Parse(raw)
	if e != nil || len(raw) < 10 || len(raw) > 2048 || u.User != nil || u.Fragment != "" || u.Host == "" || u.Opaque != "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	// http — только loopback (стенд разработки, локальный ретранслятор)
	host := u.Hostname()
	ip := net.ParseIP(host)
	return u.Scheme == "http" && (host == "localhost" || ip != nil && ip.IsLoopback())
}

// deliver — одна попытка; возвращает HTTP-статус и текст неудачи ("" — доставлено).
func (s *WebhookSender) deliver(ctx context.Context, j messaging.WebhookJob) (int, string) {
	body, e := json.Marshal(j.Payload)
	if e != nil {
		return 0, "payload: " + e.Error()
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, j.URL, bytes.NewReader(body))
	if e != nil {
		return 0, "request: invalid url"
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "SurveyScan-Webhook/"+buildinfo.Version)
	req.Header.Set("X-SurveyScan-Event-Id", j.Payload.EventID)
	req.Header.Set("X-SurveyScan-Event-Type", j.Payload.EventType)
	req.Header.Set("X-SurveyScan-Timestamp", ts)
	req.Header.Set("X-SurveyScan-Signature", WebhookSignature(s.Key(j.Tenant, j.Subscription), ts, body))
	resp, e := s.Client.Do(req)
	if e != nil {
		var ue *url.Error
		if errors.As(e, &ue) {
			e = ue.Err // без адреса: он может содержать параметры получателя
		}
		return 0, "transport: " + e.Error()
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.StatusCode, fmt.Sprintf("receiver answered %d", resp.StatusCode)
	}
	return resp.StatusCode, ""
}

// DeliverWebhooks — один проход фоновой роли: раздача новых событий по подпискам и отправка созревших доставок.
func (r *Registry) DeliverWebhooks(ctx context.Context) (int, error) {
	tenants, e := messaging.PendingTenantsFor(ctx, r.Pool, messaging.WebhookConsumer)
	if e != nil {
		return 0, e
	}
	for _, tenant := range tenants {
		for range 20 {
			n, e := messaging.FanoutWebhooks(ctx, r.Pool, tenant, 500)
			if e != nil {
				return 0, e
			}
			if n == 0 {
				break
			}
		}
	}
	jobs, e := messaging.ClaimWebhooks(ctx, r.Pool, 20, time.Minute)
	if e != nil {
		return 0, e
	}
	for _, j := range jobs {
		status, failure := r.Webhooks.deliver(ctx, j)
		if e = messaging.FinishWebhook(ctx, r.Pool, j, status, failure); e != nil {
			return 0, e
		}
	}
	return len(jobs), nil
}

func (r *Registry) WebhookMaintain(ctx context.Context, log func(string)) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		task, done := context.WithTimeout(ctx, 5*time.Minute)
		if _, e := r.DeliverWebhooks(task); e != nil {
			log("webhook delivery pass failed: " + e.Error())
		}
		done()
	}
}

type WebhookList struct {
	Tenant  string                          `json:"tenant_id"`
	Enabled bool                            `json:"enabled"`
	Types   []string                        `json:"event_types"`
	Items   []messaging.WebhookSubscription `json:"items"`
}

type WebhookCreate struct {
	URL        string   `json:"url"`
	EventTypes []string `json:"event_types"`
}

type WebhookCreated struct {
	Subscription messaging.WebhookSubscription `json:"subscription"`
	Secret       string                        `json:"signing_secret"` // показывается один раз
}

type WebhookPatch struct {
	Revision   string   `json:"revision"`
	URL        *string  `json:"url,omitempty"`
	EventTypes []string `json:"event_types,omitempty"`
	Active     *bool    `json:"active,omitempty"`
}

type WebhookDeliveryPage struct {
	Tenant       string                      `json:"tenant_id"`
	Subscription string                      `json:"subscription_id"`
	Items        []messaging.WebhookDelivery `json:"items"`
}

func (r *Registry) ListWebhooks(ctx context.Context, id accessport.Identity) (WebhookList, error) {
	out := WebhookList{Tenant: id.TenantID, Enabled: r.Webhooks != nil, Types: []string{}, Items: []messaging.WebhookSubscription{}}
	for t := range messaging.WebhookEventTypes {
		out.Types = append(out.Types, t)
	}
	slices.Sort(out.Types)
	tx, e := r.adminTx(ctx, id, "sources:admin")
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	if out.Items, e = r.Hooks.List(ctx, tx, id.TenantID); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}

func (r *Registry) CreateWebhook(ctx context.Context, id accessport.Identity, in WebhookCreate) (WebhookCreated, error) {
	if r.Webhooks == nil {
		return WebhookCreated{}, domain.Conflict // уведомления не настроены (нет webhook_secret_file)
	}
	if !validWebhookURL(in.URL) {
		return WebhookCreated{}, domain.Invalid
	}
	tx, e := r.adminTx(ctx, id, "sources:admin")
	if e != nil {
		return WebhookCreated{}, e
	}
	defer tx.Rollback(ctx)
	s, e := r.Hooks.Create(ctx, tx, id.TenantID, in.URL, in.EventTypes, id.UserID)
	if e != nil {
		return WebhookCreated{}, e
	}
	if e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "messaging.webhook_created", "webhook", s.ID); e != nil {
		return WebhookCreated{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return WebhookCreated{}, e
	}
	return WebhookCreated{Subscription: s, Secret: base64.RawURLEncoding.EncodeToString(r.Webhooks.Key(id.TenantID, s.ID))}, nil
}

func (r *Registry) PatchWebhook(ctx context.Context, id accessport.Identity, sub string, p WebhookPatch) (messaging.WebhookSubscription, error) {
	if p.Revision == "" || p.URL != nil && !validWebhookURL(*p.URL) || p.URL == nil && p.EventTypes == nil && p.Active == nil {
		return messaging.WebhookSubscription{}, domain.Invalid
	}
	tx, e := r.adminTx(ctx, id, "sources:admin")
	if e != nil {
		return messaging.WebhookSubscription{}, e
	}
	defer tx.Rollback(ctx)
	s, e := r.Hooks.Update(ctx, tx, id.TenantID, sub, p.Revision, p.URL, p.EventTypes, p.Active)
	if e != nil {
		return s, e
	}
	if e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "messaging.webhook_updated", "webhook", sub); e != nil {
		return s, e
	}
	return s, tx.Commit(ctx)
}

func (r *Registry) WebhookDeliveries(ctx context.Context, id accessport.Identity, sub, state string) (WebhookDeliveryPage, error) {
	out := WebhookDeliveryPage{Tenant: id.TenantID, Subscription: sub, Items: []messaging.WebhookDelivery{}}
	if state != "" && state != "pending" && state != "delivered" && state != "dead" {
		return out, domain.Invalid
	}
	tx, e := r.adminTx(ctx, id, "sources:admin")
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	if _, e = r.Hooks.Get(ctx, tx, id.TenantID, sub); e != nil {
		return out, e
	}
	if out.Items, e = r.Hooks.Deliveries(ctx, tx, id.TenantID, sub, state, 100); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}

func (r *Registry) RetryWebhook(ctx context.Context, id accessport.Identity, sub, event string) error {
	tx, e := r.adminTx(ctx, id, "sources:admin")
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = r.Hooks.Get(ctx, tx, id.TenantID, sub); e != nil {
		return e
	}
	if e = r.Hooks.Retry(ctx, tx, id.TenantID, sub, event); e != nil {
		return e
	}
	if e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "messaging.webhook_redelivery_requested", "webhook_delivery", sub+"/"+event); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

func (r *Registry) webhookHandlers() map[string]http.Handler {
	ctxOf := func(req *http.Request) (context.Context, context.CancelFunc, accessport.Identity) {
		return cmdbContext(req)
	}
	reply := func(w http.ResponseWriter, req *http.Request, status int, v any, e error) {
		if e != nil {
			cmdbError(w, req, e)
			return
		}
		registryJSONStatus(w, status, v)
	}
	return map[string]http.Handler{
		"GET /api/v1/webhooks": http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if _, ok := queryOnly(w, req); !ok {
				return
			}
			ctx, cancel, id := ctxOf(req)
			defer cancel()
			out, e := r.ListWebhooks(ctx, id)
			reply(w, req, 200, out, e)
		}),
		"POST /api/v1/webhooks": http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var body WebhookCreate
			if !readOperationBody(w, req, &body) {
				return
			}
			ctx, cancel, id := ctxOf(req)
			defer cancel()
			out, e := r.CreateWebhook(ctx, id, body)
			reply(w, req, http.StatusCreated, out, e)
		}),
		"PATCH /api/v1/webhooks/{subscription_id}": http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var body WebhookPatch
			if !readOperationBody(w, req, &body) {
				return
			}
			ctx, cancel, id := ctxOf(req)
			defer cancel()
			out, e := r.PatchWebhook(ctx, id, req.PathValue("subscription_id"), body)
			reply(w, req, 200, out, e)
		}),
		"GET /api/v1/webhooks/{subscription_id}/deliveries": http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			q, ok := queryOnly(w, req, "state")
			if !ok {
				return
			}
			ctx, cancel, id := ctxOf(req)
			defer cancel()
			out, e := r.WebhookDeliveries(ctx, id, req.PathValue("subscription_id"), q.Get("state"))
			reply(w, req, 200, out, e)
		}),
		"POST /api/v1/webhooks/{subscription_id}/deliveries/{event_id}/retry": http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.URL.RawQuery != "" {
				access.APIError(w, 400, "INVALID_QUERY")
				return
			}
			ctx, cancel, id := ctxOf(req)
			defer cancel()
			if e := r.RetryWebhook(ctx, id, req.PathValue("subscription_id"), req.PathValue("event_id")); e != nil {
				cmdbError(w, req, e)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusNoContent)
		}),
	}
}
