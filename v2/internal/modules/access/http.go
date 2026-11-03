package access

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type HTTP struct {
	service *Service
	origin  string
	secure  bool
}

func NewHTTP(s *Service, origin string, insecureLocal bool) (*HTTP, error) {
	u, e := url.Parse(origin)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("valid SURVEYSCAN_V2_PUBLIC_ORIGIN is required (scheme and host only)")
	}
	if u.Scheme == "http" && (!insecureLocal || (u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1")) {
		return nil, errors.New("HTTP origin requires explicit local-only development mode")
	}
	return &HTTP{s, origin, u.Scheme == "https"}, nil
}
func APIError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	id := identifier.New()
	w.Header().Set("X-Request-ID", id)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
		Details   []any  `json:"details"`
	}{code, "Запрос не выполнен", id, []any{}})
}
func fail(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, ErrAuth):
		APIError(w, 401, "AUTHENTICATION_REQUIRED")
	case errors.Is(e, ErrForbidden):
		APIError(w, 403, "FORBIDDEN")
	case errors.Is(e, ErrInvalid):
		APIError(w, 422, "SCHEMA_INVALID")
	case errors.Is(e, ErrLimit):
		w.Header().Set("Retry-After", "60")
		APIError(w, 429, "RATE_LIMITED")
	default:
		w.Header().Set("Retry-After", "2")
		APIError(w, 503, "TEMPORARILY_UNAVAILABLE")
	}
}
func respond(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if body != nil {
		_ = json.NewEncoder(w).Encode(body)
	}
}
func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	kind, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || kind != "application/json" {
		APIError(w, 400, "INVALID_JSON")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	e = d.Decode(dst)
	if e == nil {
		var extra any
		if d.Decode(&extra) != io.EOF {
			e = ErrInvalid
		}
	}
	if e != nil {
		var big *http.MaxBytesError
		if errors.As(e, &big) {
			APIError(w, 413, "PAYLOAD_TOO_LARGE")
		} else {
			APIError(w, 400, "INVALID_JSON")
		}
		return false
	}
	return true
}

type identityContextKey struct{}

func Identity(ctx context.Context) (port.Identity, bool) {
	id, ok := ctx.Value(identityContextKey{}).(port.Identity)
	return id, ok
}
func (h *HTTP) originOK(r *http.Request) bool {
	return len(r.Header.Values("Origin")) == 1 && r.Header.Get("Origin") == h.origin
}
func (h *HTTP) Wrap(action string, sessionOnly bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		r = r.WithContext(ctx)
		var raw, kind string
		cookies := r.CookiesNamed("surveyscan_session")
		auth := r.Header.Values("Authorization")
		if len(cookies) > 1 || len(auth) > 1 || len(cookies) > 0 && len(auth) > 0 {
			fail(w, ErrAuth)
			return
		}
		if len(auth) == 1 {
			parts := strings.Fields(auth[0])
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
				fail(w, ErrAuth)
				return
			}
			raw = parts[1]
			kind = "cli"
		} else if len(cookies) == 1 {
			raw = cookies[0].Value
			kind = "session"
		} else {
			fail(w, ErrAuth)
			return
		}
		mutation := r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS"
		if sessionOnly && kind != "session" {
			fail(w, ErrForbidden)
			return
		}
		if mutation && kind == "session" && (!h.originOK(r) || len(r.Header.Values("X-CSRF-Token")) != 1) {
			fail(w, ErrForbidden)
			return
		}
		id, e := h.service.Authenticate(r.Context(), raw, kind, r.Header.Get("X-CSRF-Token"), mutation)
		if e != nil {
			fail(w, e)
			return
		}
		if !allowed(id, action) {
			fail(w, ErrForbidden)
			return
		}
		// Tenant определяется только credential; клиентские заголовки не влияют на context.
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityContextKey{}, id)))
	})
}
func (h *HTTP) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/auth/sessions", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		r = r.WithContext(ctx)
		if !h.originOK(r) {
			fail(w, ErrForbidden)
			return
		}
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if !decode(w, r, &req) {
			return
		}
		session, raw, e := h.service.Login(r.Context(), req.Username, req.Password)
		if e != nil {
			fail(w, e)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "surveyscan_session", Value: raw, Path: "/", HttpOnly: true, Secure: h.secure, SameSite: http.SameSiteStrictMode, Expires: session.ExpiresAt, MaxAge: 28800})
		respond(w, 201, session)
	})
	mux.Handle("DELETE /api/v1/auth/session", h.Wrap("auth:self", true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, _ := Identity(r.Context())
		if e := h.service.Logout(r.Context(), id); e != nil {
			fail(w, e)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "surveyscan_session", Path: "/", HttpOnly: true, Secure: h.secure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
		respond(w, 204, nil)
	})))
	mux.Handle("POST /api/v1/auth/tokens", h.Wrap("auth:self", true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req TokenRequest
		if !decode(w, r, &req) {
			return
		}
		id, _ := Identity(r.Context())
		token, e := h.service.CreateToken(r.Context(), id, req)
		if e != nil {
			fail(w, e)
			return
		}
		respond(w, 201, token)
	})))
	mux.Handle("DELETE /api/v1/auth/tokens/{token_id}", h.Wrap("auth:self", true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, _ := Identity(r.Context())
		if e := h.service.RevokeToken(r.Context(), id, r.PathValue("token_id")); e != nil {
			if errors.Is(e, ErrForbidden) {
				APIError(w, 404, "NOT_FOUND")
			} else {
				fail(w, e)
			}
			return
		}
		respond(w, 204, nil)
	})))
}
