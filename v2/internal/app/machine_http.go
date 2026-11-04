package app

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/imports"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/pki"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type MachineAPI struct {
	Sources *sources.MachineService
	Uploads *imports.UploadService
}

func (m *MachineAPI) decode(w http.ResponseWriter, r *http.Request, name string, out any) bool {
	kind, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || kind != "application/json" {
		access.APIError(w, 400, "INVALID_JSON")
		return false
	}
	b, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
	if e != nil {
		access.APIError(w, 413, "PAYLOAD_TOO_LARGE")
		return false
	}
	if e = m.Sources.Wire.Validate(name, b); e != nil {
		registryError(w, e)
		return false
	}
	if e = json.Unmarshal(b, out); e != nil {
		access.APIError(w, 400, "INVALID_JSON")
		return false
	}
	return true
}
func (m *MachineAPI) fail(w http.ResponseWriter, e error) {
	if errors.Is(e, sources.ErrEnrollmentLimit) {
		w.Header().Set("Retry-After", "60")
		access.APIError(w, 429, "RATE_LIMITED")
		return
	}
	registryError(w, e)
}
func (m *MachineAPI) human() map[string]http.Handler {
	return map[string]http.Handler{
		"createEnrollmentGrant": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req contracts.EnrollmentGrantRequest
			if !m.decode(w, r, "EnrollmentGrantRequest", &req) {
				return
			}
			id, _ := access.Identity(r.Context())
			if req.TenantID != id.TenantID {
				access.APIError(w, 403, "FORBIDDEN")
				return
			}
			result, e := m.Sources.Grant(r.Context(), id, req)
			if e != nil {
				m.fail(w, e)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(result)
		}),
		"revokeSource": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Reason string `json:"reason_code"`
			}
			if !m.decode(w, r, "RevocationRequest", &req) {
				return
			}
			id, _ := access.Identity(r.Context())
			if e := m.Sources.Revoke(r.Context(), id, r.PathValue("source_id")); e != nil {
				m.fail(w, e)
				return
			}
			result, e := m.Sources.View(r.Context(), id, r.PathValue("source_id"))
			if e != nil {
				m.fail(w, e)
				return
			}
			registryJSON(w, result)
		}),
		"getSource": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, _ := access.Identity(r.Context())
			result, e := m.Sources.View(r.Context(), id, r.PathValue("source_id"))
			if e != nil {
				m.fail(w, e)
				return
			}
			registryJSON(w, result)
		}),
		"listSources": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, _ := access.Identity(r.Context())
			limit := 50
			after := ""
			q := r.URL.Query()
			for key, values := range q {
				if (key != "limit" && key != "cursor") || len(values) != 1 {
					access.APIError(w, 400, "INVALID_QUERY")
					return
				}
			}
			if value, ok := q["limit"]; ok {
				n, e := strconv.Atoi(value[0])
				if e != nil || n < 1 || n > 200 {
					access.APIError(w, 400, "INVALID_QUERY")
					return
				}
				limit = n
			}
			if value, ok := q["cursor"]; ok {
				b, e := base64.RawURLEncoding.DecodeString(value[0])
				var cursor []string
				if len(value[0]) > 2048 || e != nil || json.Unmarshal(b, &cursor) != nil || len(cursor) != 2 || cursor[0] != id.TenantID || !identifier.Valid(cursor[1]) {
					access.APIError(w, 400, "INVALID_QUERY")
					return
				}
				after = cursor[1]
			}
			result, e := m.Sources.List(r.Context(), id, after, limit)
			if e != nil {
				m.fail(w, e)
				return
			}
			registryJSON(w, result)
		}),
	}
}
func (m *MachineAPI) enroll(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || r.TLS.Version < tls.VersionTLS12 {
		access.APIError(w, 401, "AUTHENTICATION_REQUIRED")
		return
	}
	auth := r.Header.Values("Authorization")
	if len(auth) != 1 {
		access.APIError(w, 401, "AUTHENTICATION_REQUIRED")
		return
	}
	parts := strings.Fields(auth[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		access.APIError(w, 401, "AUTHENTICATION_REQUIRED")
		return
	}
	var req contracts.EnrollmentRequest
	if !m.decode(w, r, "EnrollmentRequest", &req) {
		return
	}
	result, e := m.Sources.Enroll(r.Context(), parts[1], req)
	if e != nil {
		m.fail(w, e)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(201)
	_ = json.NewEncoder(w).Encode(result)
}
func (m *MachineAPI) machine(operation string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		r = r.WithContext(ctx)
		if operation == "enrollMachine" {
			m.enroll(w, r)
			return
		}
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
			access.APIError(w, 401, "AUTHENTICATION_REQUIRED")
			return
		}
		fingerprint := pki.Fingerprint(r.TLS.PeerCertificates[0])
		if m.Uploads != nil && (operation == "submitObservationBatch" || operation == "getDeliveryReceipt") {
			m.upload(w, r, fingerprint, operation)
			return
		}
		if operation == "getMachineConfig" {
			result, e := m.Sources.Config(ctx, fingerprint)
			if e != nil {
				m.fail(w, e)
				return
			}
			registryJSON(w, result)
			return
		}
		tx, e := m.Sources.Pool.Begin(ctx)
		if e != nil {
			m.fail(w, e)
			return
		}
		_, e = m.Sources.PeerFingerprint(ctx, tx, fingerprint)
		tx.Rollback(ctx)
		if e != nil {
			m.fail(w, e)
			return
		}
		access.APIError(w, 501, "CAPABILITY_NOT_ENABLED")
	})
}

func (m *MachineAPI) upload(w http.ResponseWriter, r *http.Request, fingerprint, operation string) {
	var response []byte
	if operation == "submitObservationBatch" {
		kind, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if e != nil || kind != "application/json" {
			access.APIError(w, 400, "INVALID_JSON")
			return
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 1048576))
		if e != nil {
			access.APIError(w, 413, "PAYLOAD_TOO_LARGE")
			return
		}
		transport, e := m.Uploads.Stage(r.Context(), fingerprint, raw)
		if e != nil {
			m.fail(w, e)
			return
		}
		response, e = m.Uploads.Process(r.Context(), fingerprint, transport.DeliveryID)
		if e != nil {
			transport.Stage = "processing"
			response, _ = json.Marshal(transport)
		}
	} else {
		id := r.PathValue("delivery_id")
		status, e := m.Uploads.Status(r.Context(), fingerprint, id)
		if e != nil {
			m.fail(w, e)
			return
		}
		response = status
		processed, e := m.Uploads.Process(r.Context(), fingerprint, id)
		if e == nil {
			response = processed
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if operation == "submitObservationBatch" {
		w.WriteHeader(202)
	}
	_, _ = w.Write(response)
}
