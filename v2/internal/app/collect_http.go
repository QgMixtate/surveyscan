package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

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
