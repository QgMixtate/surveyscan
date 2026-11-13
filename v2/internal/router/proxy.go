package router

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Router — обратный прокси к ячейкам по каталогу (C37.02). Маршрут организации — подписанная cookie ss_route
// (tenant.epoch.подпись); шард всегда берётся из каталога. Любая неопределённость — отказ, маршрута по умолчанию нет.
type Router struct {
	Catalog   Catalog
	Shards    map[string]*url.URL // shard_id → адрес HTTP-слушателя ячейки (loopback/внутренняя сеть)
	Key       []byte              // ключ подписи cookie маршрута (≥ 32 байт)
	Secure    bool                // атрибут Secure у cookie (за TLS-edge — true)
	TTL       time.Duration       // кэш размещений
	Transport http.RoundTripper   // транспорт к ячейкам (nil — стандартный)
	mu        sync.Mutex
	cache     map[string]cachedPlacement
	proxies   map[string]*httputil.ReverseProxy
	initOnce  sync.Once
}

type cachedPlacement struct {
	p  Placement
	at time.Time
}

const routeCookie = "ss_route"

func (r *Router) init() {
	r.initOnce.Do(func() {
		r.cache = map[string]cachedPlacement{}
		r.proxies = map[string]*httputil.ReverseProxy{}
		for id, u := range r.Shards {
			p := httputil.NewSingleHostReverseProxy(u)
			p.Transport = r.Transport
			p.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) { fail(w, 502, "SHARD_UNAVAILABLE") }
			r.proxies[id] = p
		}
		if r.TTL == 0 {
			r.TTL = 2 * time.Second
		}
	})
}

func fail(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if status == 503 {
		w.Header().Set("Retry-After", "30")
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": code})
}

func (r *Router) sign(tenant string, epoch int64) string {
	payload := tenant + "." + strconv.FormatInt(epoch, 10)
	m := hmac.New(sha256.New, r.Key)
	m.Write([]byte("surveyscan-route-v1\x00" + payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// verify возвращает организацию из подписанной cookie маршрута (tenant.epoch.подпись).
func (r *Router) verify(value string) (string, bool) {
	parts := strings.Split(value, ".")
	if len(parts) != 3 || len(parts[0]) != 36 {
		return "", false
	}
	epoch, e := strconv.ParseInt(parts[1], 10, 64)
	if e != nil || epoch < 1 {
		return "", false
	}
	if !hmac.Equal([]byte(r.sign(parts[0], epoch)), []byte(value)) {
		return "", false
	}
	return parts[0], true
}

func (r *Router) placement(ctx context.Context, tenant string) (Placement, error) {
	r.mu.Lock()
	c, ok := r.cache[tenant]
	r.mu.Unlock()
	if ok && time.Since(c.at) < r.TTL {
		return c.p, nil
	}
	p, e := r.Catalog.Placement(ctx, tenant)
	if e != nil {
		return p, e
	}
	r.mu.Lock()
	r.cache[tenant] = cachedPlacement{p, time.Now()}
	r.mu.Unlock()
	return p, nil
}

func (r *Router) route(w http.ResponseWriter, p Placement) *httputil.ReverseProxy {
	if p.State != "active" {
		fail(w, 503, "TENANT_MIGRATING")
		return nil
	}
	proxy, ok := r.proxies[p.Shard]
	if !ok {
		fail(w, 503, "SHARD_NOT_CONFIGURED") // каталог указывает на ячейку, которой нет в конфигурации: не угадываем
		return nil
	}
	return proxy
}

func (r *Router) catalogError(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, ErrUnknown):
		fail(w, 401, "AUTHENTICATION_REQUIRED")
	case errors.Is(e, ErrConflict):
		fail(w, 409, "LOGIN_CONFLICT")
	default:
		fail(w, 503, "CATALOG_UNAVAILABLE") // каталог недоступен — никуда не пишем
	}
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.init()
	ctx, cancel := context.WithTimeout(req.Context(), 3*time.Second)
	defer cancel()
	switch {
	case req.URL.Path == "/router/health":
		if e := r.Catalog.Pool.Ping(ctx); e != nil {
			fail(w, 503, "CATALOG_UNAVAILABLE")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
		return
	case req.Method == http.MethodPost && req.URL.Path == "/api/v1/auth/sessions":
		r.login(w, req, ctx)
		return
	}
	cookie, e := req.Cookie(routeCookie)
	if e != nil {
		fail(w, 401, "AUTHENTICATION_REQUIRED")
		return
	}
	tenant, ok := r.verify(cookie.Value)
	if !ok {
		fail(w, 401, "AUTHENTICATION_REQUIRED") // поддельная или испорченная cookie маршрута
		return
	}
	p, e := r.placement(ctx, tenant)
	if e != nil {
		r.catalogError(w, e)
		return
	}
	proxy := r.route(w, p)
	if proxy == nil {
		return
	}
	if req.Method == http.MethodDelete && req.URL.Path == "/api/v1/auth/session" {
		http.SetCookie(w, &http.Cookie{Name: routeCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: r.Secure, SameSite: http.SameSiteStrictMode})
	}
	proxy.ServeHTTP(w, req)
}

// login — вход: логин → организация → шард; при успехе ячейки добавляется cookie маршрута.
func (r *Router) login(w http.ResponseWriter, req *http.Request, ctx context.Context) {
	body, e := io.ReadAll(http.MaxBytesReader(w, req.Body, 16384))
	if e != nil {
		fail(w, 413, "PAYLOAD_TOO_LARGE")
		return
	}
	var in struct {
		Username string `json:"username"`
	}
	if json.Unmarshal(body, &in) != nil || in.Username == "" {
		fail(w, 400, "INVALID_REQUEST")
		return
	}
	p, e := r.Catalog.Login(ctx, strings.ToLower(in.Username))
	if e != nil {
		r.catalogError(w, e)
		return
	}
	proxy := r.route(w, p)
	if proxy == nil {
		return
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	rec := &routeWriter{ResponseWriter: w, set: func(h http.Header, status int) {
		if status == http.StatusCreated {
			h.Add("Set-Cookie", (&http.Cookie{Name: routeCookie, Value: r.sign(p.Tenant, p.Epoch), Path: "/", HttpOnly: true, Secure: r.Secure, SameSite: http.SameSiteStrictMode}).String())
		}
	}}
	proxy.ServeHTTP(rec, req)
}

type routeWriter struct {
	http.ResponseWriter
	set  func(http.Header, int)
	done bool
}

func (w *routeWriter) WriteHeader(status int) {
	if !w.done {
		w.done = true
		w.set(w.Header(), status)
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *routeWriter) Write(b []byte) (int, error) {
	if !w.done {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}
