package app

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/assets"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
)

// redirectMerged — для GET по UID поглощённого актива: 308 на тот же путь с каноническим UID (C25.03).
func redirectMerged(w http.ResponseWriter, req *http.Request, e error) bool {
	var merged assets.ErrMerged
	if !errors.As(e, &merged) || req.Method != http.MethodGet {
		return false
	}
	target := *req.URL
	target.Path = strings.Replace(req.URL.Path, "/assets/"+req.PathValue("asset_uid"), "/assets/"+merged.Into, 1)
	target.RawPath = ""
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, req, target.RequestURI(), http.StatusPermanentRedirect)
	return true
}
func registryError(w http.ResponseWriter, e error) {
	status, code := 503, "TEMPORARILY_UNAVAILABLE"
	switch {
	case errors.As(e, new(assets.ErrMerged)):
		status, code = 409, "ASSET_MERGED"
	case errors.Is(e, domain.NotFound):
		status, code = 404, "NOT_FOUND"
	case errors.Is(e, domain.Unauthorized):
		status, code = 401, "AUTHENTICATION_REQUIRED"
	case errors.Is(e, domain.Conflict):
		status, code = 409, "CONFLICT"
	case errors.Is(e, domain.Revision):
		status, code = 412, "REVISION_MISMATCH"
	case errors.Is(e, domain.Invalid):
		status, code = 422, "SCHEMA_INVALID"
	case errors.Is(e, access.ErrAuth):
		status, code = 401, "AUTHENTICATION_REQUIRED"
	case errors.Is(e, access.ErrForbidden):
		status, code = 403, "FORBIDDEN"
	}
	access.APIError(w, status, code)
}
func registryJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode(value)
}
func ETag(a contracts.Asset) string { return fmt.Sprintf(`"asset:%s:business:%s"`, a.UID, a.Revision) }
func (r *Registry) Handlers() map[string]http.Handler {
	return map[string]http.Handler{
		"getAsset": http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			uid := req.PathValue("asset_uid")
			if !identifier.Valid(uid) {
				access.APIError(w, 404, "NOT_FOUND")
				return
			}
			id, _ := access.Identity(req.Context())
			a, e := r.Get(req.Context(), id, uid)
			if e != nil {
				if redirectMerged(w, req, e) {
					return
				}
				registryError(w, e)
				return
			}
			w.Header().Set("ETag", ETag(a))
			registryJSON(w, a)
		}),
		"listAssets": http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			id, _ := access.Identity(req.Context())
			limit := 50
			after := ""
			q := req.URL.Query()
			for k, values := range q {
				if (k != "limit" && k != "cursor") || len(values) != 1 {
					access.APIError(w, 400, "INVALID_QUERY")
					return
				}
			}
			if value, exists := q["limit"]; exists {
				n, e := strconv.Atoi(value[0])
				if e != nil || n < 1 || n > 200 {
					access.APIError(w, 400, "INVALID_QUERY")
					return
				}
				limit = n
			}
			if value, exists := q["cursor"]; exists {
				if len(value[0]) > 2048 {
					access.APIError(w, 400, "INVALID_QUERY")
					return
				}
				b, e := base64.RawURLEncoding.DecodeString(value[0])
				var parts []string
				if e != nil || json.Unmarshal(b, &parts) != nil || len(parts) != 2 || parts[0] != id.TenantID || !identifier.Valid(parts[1]) {
					access.APIError(w, 400, "INVALID_QUERY")
					return
				}
				after = parts[1]
			}
			page, e := r.List(req.Context(), id, after, limit)
			if e != nil {
				registryError(w, e)
				return
			}
			registryJSON(w, page)
		}),
		"patchAssetBusiness": http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			uid := req.PathValue("asset_uid")
			if !identifier.Valid(uid) {
				access.APIError(w, 404, "NOT_FOUND")
				return
			}
			match := req.Header.Get("If-Match")
			prefix := `"asset:` + uid + `:business:`
			if len(req.Header.Values("If-Match")) != 1 || !strings.HasPrefix(match, prefix) || !strings.HasSuffix(match, `"`) {
				access.APIError(w, 412, "REVISION_MISMATCH")
				return
			}
			revision := strings.TrimSuffix(strings.TrimPrefix(match, prefix), `"`)
			if n, e := strconv.ParseUint(revision, 10, 64); e != nil || n == 0 {
				access.APIError(w, 412, "REVISION_MISMATCH")
				return
			}
			media, _, e := mime.ParseMediaType(req.Header.Get("Content-Type"))
			if e != nil || media != "application/json" {
				access.APIError(w, 400, "INVALID_JSON")
				return
			}
			b, e := io.ReadAll(http.MaxBytesReader(w, req.Body, 32768))
			if e != nil {
				access.APIError(w, 413, "PAYLOAD_TOO_LARGE")
				return
			}
			if e = r.Wire.Validate("BusinessPatch", b); e != nil {
				registryError(w, e)
				return
			}
			var patch contracts.BusinessPatch
			_ = json.Unmarshal(b, &patch)
			id, _ := access.Identity(req.Context())
			a, e := r.Patch(req.Context(), id, uid, revision, patch)
			if e != nil {
				registryError(w, e)
				return
			}
			w.Header().Set("ETag", ETag(a))
			registryJSON(w, a)
		}),
	}
}
