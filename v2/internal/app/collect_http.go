package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/pki"

	accessport "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
)

// C51.03: учётки сбора (D-13, «через центр»). Вводит администратор в Web; секрет — в хранилище секретов центра
// (OpenBao KV интеграций или приватные файлы), обратно не отдаётся ни в Web, ни в API, ни в журнал.

// CollectSecret — секретная часть учётки по типу.
type CollectSecret struct {
	Password     string `json:"password,omitempty"`      // ssh, winrm
	PrivateKey   string `json:"private_key,omitempty"`   // ssh (PEM/OpenSSH)
	Passphrase   string `json:"passphrase,omitempty"`    // ssh, к ключу
	AuthProtocol string `json:"auth_protocol,omitempty"` // snmp: SHA|SHA256|SHA512
	AuthKey      string `json:"auth_key,omitempty"`
	PrivProtocol string `json:"priv_protocol,omitempty"` // snmp: AES|AES256
	PrivKey      string `json:"priv_key,omitempty"`
}

func (s CollectSecret) valid(kind string) bool {
	short := func(v string, max int) bool { return len(v) <= max }
	if !short(s.Password, 1024) || !short(s.PrivateKey, 16384) || !short(s.Passphrase, 1024) || !short(s.AuthKey, 256) || !short(s.PrivKey, 256) {
		return false
	}
	switch kind {
	case "ssh":
		return (s.Password != "") != (s.PrivateKey != "") && s.AuthKey == "" && s.PrivKey == "" && (s.PrivateKey == "" || strings.Contains(s.PrivateKey, "PRIVATE KEY"))
	case "winrm":
		return s.Password != "" && s.PrivateKey == "" && s.AuthKey == "" && s.PrivKey == ""
	case "snmp":
		auth := s.AuthProtocol == "SHA" || s.AuthProtocol == "SHA256" || s.AuthProtocol == "SHA512"
		priv := s.PrivProtocol == "AES" || s.PrivProtocol == "AES256"
		return auth && priv && len(s.AuthKey) >= 8 && len(s.PrivKey) >= 8 && s.Password == "" && s.PrivateKey == ""
	}
	return false
}

type credentialCreate struct {
	Name     string        `json:"name"`
	Kind     string        `json:"kind"`
	Username string        `json:"username"`
	Secret   CollectSecret `json:"secret"`
}

type credentialPatch struct {
	Revision string         `json:"revision"`
	Name     *string        `json:"name,omitempty"`
	Username *string        `json:"username,omitempty"`
	Active   *bool          `json:"active,omitempty"`
	Secret   *CollectSecret `json:"secret,omitempty"`
}

func (r *Registry) putCollectSecret(ctx context.Context, tenant, id, kind string, s CollectSecret) error {
	if r.Secrets == nil {
		return domain.Conflict // хранилище секретов не настроено: учётку не сохраняем
	}
	if !s.valid(kind) {
		return domain.Invalid
	}
	raw, _ := json.Marshal(s)
	if e := r.Secrets.Put(ctx, tenant, sources.CredentialSecretKey(id), raw); e != nil {
		if errors.Is(e, ErrSecretsUnavailable) {
			return domain.Conflict
		}
		return e
	}
	return nil
}

func (r *Registry) collectHandlers() map[string]route51 {
	return map[string]route51{
		"GET /api/v1/discovery/credentials": {"sources:admin", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if _, ok := queryOnly(w, req); !ok {
				return
			}
			r.discoveryDo(w, req, http.StatusOK, "sources:admin", func(ctx context.Context, tx pgx.Tx, id accessport.Identity) (any, error) {
				items, e := src51.Credentials(ctx, tx, id.TenantID)
				return map[string]any{"items": items, "secrets_available": r.Secrets != nil}, e
			})
		})},
		"POST /api/v1/discovery/credentials": {"sources:admin", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var body credentialCreate
			if !readOperationBody(w, req, &body) {
				return
			}
			r.discoveryDo(w, req, http.StatusCreated, "sources:admin", func(ctx context.Context, tx pgx.Tx, id accessport.Identity) (any, error) {
				cid := identifier.New()
				// секрет пишется первым: при сбое вставки остаётся недостижимый секрет без описания — безопасно
				if e := r.putCollectSecret(ctx, id.TenantID, cid, body.Kind, body.Secret); e != nil {
					return nil, e
				}
				c, e := src51.CreateCredential(ctx, tx, id.TenantID, cid, body.Name, body.Kind, body.Username)
				if e == nil {
					e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "discovery.credential_created", "collect_credential", c.ID)
				}
				return c, e
			})
		})},
		"PATCH /api/v1/discovery/credentials/{credential_id}": {"sources:admin", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var body credentialPatch
			if !readOperationBody(w, req, &body) {
				return
			}
			r.discoveryDo(w, req, http.StatusOK, "sources:admin", func(ctx context.Context, tx pgx.Tx, id accessport.Identity) (any, error) {
				cur, e := src51.Credential(ctx, tx, id.TenantID, req.PathValue("credential_id"))
				if e != nil {
					return nil, e
				}
				if cur.Revision != body.Revision {
					return nil, domain.Revision
				}
				if body.Secret != nil {
					if e = r.putCollectSecret(ctx, id.TenantID, cur.ID, cur.Kind, *body.Secret); e != nil {
						return nil, e
					}
				}
				c, e := src51.PatchCredential(ctx, tx, id.TenantID, cur.ID, body.Revision, body.Name, body.Username, body.Active, body.Secret != nil)
				if e == nil {
					action := "discovery.credential_changed"
					if body.Secret != nil {
						action = "discovery.credential_secret_changed"
					}
					e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, action, "collect_credential", c.ID)
				}
				return c, e
			})
		})},
	}
}

func (r *Registry) targetHandlers() map[string]route51 {
	return map[string]route51{
		"GET /api/v1/discovery/targets": {"sources:read", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if _, ok := queryOnly(w, req); !ok {
				return
			}
			r.discoveryDo(w, req, http.StatusOK, "sources:read", func(ctx context.Context, tx pgx.Tx, id accessport.Identity) (any, error) {
				items, e := src51.Targets(ctx, tx, id.TenantID)
				return map[string]any{"items": items}, e
			})
		})},
		"POST /api/v1/discovery/targets": {"sources:admin", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var body sources.RemoteTargetInput
			if !readOperationBody(w, req, &body) {
				return
			}
			r.discoveryDo(w, req, http.StatusCreated, "sources:admin", func(ctx context.Context, tx pgx.Tx, id accessport.Identity) (any, error) {
				t, e := src51.CreateTarget(ctx, tx, id.TenantID, body)
				if e == nil {
					e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "discovery.target_created", "remote_target", t.ID)
				}
				return t, e
			})
		})},
		"PATCH /api/v1/discovery/targets/{target_id}": {"sources:admin", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var body struct {
				Revision     string `json:"revision"`
				Disabled     bool   `json:"disabled"`
				ResetHostKey bool   `json:"reset_host_key,omitempty"`
			}
			if !readOperationBody(w, req, &body) {
				return
			}
			r.discoveryDo(w, req, http.StatusOK, "sources:admin", func(ctx context.Context, tx pgx.Tx, id accessport.Identity) (any, error) {
				t, e := src51.SetTargetState(ctx, tx, id.TenantID, req.PathValue("target_id"), body.Revision, body.Disabled, body.ResetHostKey)
				if e == nil {
					action := "discovery.target_changed"
					if body.ResetHostKey {
						action = "discovery.target_host_key_reset"
					}
					e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, action, "remote_target", t.ID)
				}
				return t, e
			})
		})},
	}
}

// collectMachine — машинный канал целей сбора (collector по mTLS, контракт c51-discovery).
func (r *Registry) collectMachine(w http.ResponseWriter, req *http.Request) {
	m := r.Machine
	ctx, cancel := context.WithTimeout(req.Context(), 20*time.Second)
	defer cancel()
	if req.TLS == nil || len(req.TLS.VerifiedChains) == 0 || len(req.TLS.PeerCertificates) == 0 {
		access.APIError(w, 401, "AUTHENTICATION_REQUIRED")
		return
	}
	if kind, _, e := mime.ParseMediaType(req.Header.Get("Content-Type")); e != nil || kind != "application/json" || req.URL.RawQuery != "" {
		access.APIError(w, 400, "INVALID_JSON")
		return
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, req.Body, 64<<10))
	if e != nil {
		access.APIError(w, 413, "PAYLOAD_TOO_LARGE")
		return
	}
	if m == nil || m.Sources == nil || m.Sources.Pool == nil {
		access.APIError(w, 503, "TEMPORARILY_UNAVAILABLE")
		return
	}
	fp := pki.Fingerprint(req.TLS.PeerCertificates[0])
	target := req.PathValue("target_id")
	switch {
	case req.URL.Path == "/api/v1/machine/collect-targets":
		items, e := m.Sources.CollectTargets(ctx, fp)
		if e != nil {
			m.fail(w, e)
			return
		}
		registryJSON(w, map[string]any{"items": items})
	case strings.HasSuffix(req.URL.Path, "/grant"):
		var body sources.TargetGrantRequest
		if sources.Strict(raw, &body) != nil {
			access.APIError(w, 400, "INVALID_JSON")
			return
		}
		grant, e := m.Sources.TargetGrant(ctx, fp, target, body)
		if e != nil {
			m.fail(w, e)
			return
		}
		registryJSON(w, grant)
	case strings.HasSuffix(req.URL.Path, "/secret"):
		if string(raw) != "{}" {
			access.APIError(w, 400, "INVALID_JSON")
			return
		}
		tenant, source, kind, username, credential, e := m.Sources.TargetForSecret(ctx, fp, target)
		if e != nil {
			m.fail(w, e)
			return
		}
		if r.Secrets == nil {
			access.APIError(w, 503, "TEMPORARILY_UNAVAILABLE")
			return
		}
		stored, ok, e := r.Secrets.Get(ctx, tenant, sources.CredentialSecretKey(credential))
		if e != nil || !ok {
			access.APIError(w, 503, "TEMPORARILY_UNAVAILABLE")
			return
		}
		var secret CollectSecret
		if json.Unmarshal(stored, &secret) != nil {
			access.APIError(w, 503, "TEMPORARILY_UNAVAILABLE")
			return
		}
		tx, e := r.Pool.Begin(ctx)
		if e == nil {
			e = r.Audit.Record(ctx, tx, tenant, "collector:"+source, "discovery.credential_issued", "remote_target", target)
			if e == nil {
				e = tx.Commit(ctx)
			}
			tx.Rollback(ctx)
		}
		if e != nil {
			m.fail(w, e)
			return
		}
		registryJSON(w, map[string]any{"kind": kind, "username": username, "secret": secret})
	case strings.HasSuffix(req.URL.Path, "/hostkey"):
		var body struct {
			HostKey string `json:"host_key_sha256"`
		}
		if sources.Strict(raw, &body) != nil {
			access.APIError(w, 400, "INVALID_JSON")
			return
		}
		pinned, tenant, source, e := m.Sources.PinHostKey(ctx, fp, target, body.HostKey)
		if e != nil {
			m.fail(w, e)
			return
		}
		if pinned {
			tx, e := r.Pool.Begin(ctx)
			if e == nil {
				if e = r.Audit.Record(ctx, tx, tenant, "collector:"+source, "discovery.target_host_key_pinned", "remote_target", target); e == nil {
					e = tx.Commit(ctx)
				}
				tx.Rollback(ctx)
			}
			if e != nil {
				m.fail(w, e)
				return
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	case strings.HasSuffix(req.URL.Path, "/report"):
		var body struct {
			OK      bool   `json:"ok"`
			Problem string `json:"problem"`
		}
		if sources.Strict(raw, &body) != nil {
			access.APIError(w, 400, "INVALID_JSON")
			return
		}
		if e = m.Sources.TargetReport(ctx, fp, target, body.OK, body.Problem); e != nil {
			m.fail(w, e)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	default:
		access.APIError(w, 404, "NOT_FOUND")
	}
}
