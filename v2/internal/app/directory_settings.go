package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	accessport "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
)

// C31.05 (решение пользователя 2026-11-12): синхронизация с каталогом настраивается в Web. Несекретные параметры —
// в БД (responsibility.directory_settings), пароль служебной учётки — в хранилище секретов центра; обратно он не
// отдаётся. Блок ldap_sync конфигурации центра по-прежнему поддерживается и имеет приоритет (настройки в Web тогда
// только для чтения).

// DirectoryWebSettings — параметры, которые администратор задаёт в Web (без пароля).
type DirectoryWebSettings struct {
	URL              string `json:"url"`
	BaseDN           string `json:"base_dn"`
	BindDN           string `json:"bind_dn"`
	UserFilter       string `json:"user_filter,omitempty"`
	GroupFilter      string `json:"group_filter,omitempty"`
	GUIDAttribute    string `json:"guid_attribute,omitempty"`
	LoginAttribute   string `json:"login_attribute,omitempty"`
	ChangedAttribute string `json:"changed_attribute,omitempty"`
	IntervalMinutes  int    `json:"interval_minutes,omitempty"`
	FullHours        int    `json:"full_sync_hours,omitempty"`
	CAPEM            string `json:"ca_certificate_pem,omitempty"`
	TLSServerName    string `json:"tls_server_name,omitempty"` // имя в сертификате, если адрес — IP
}

func (s DirectoryWebSettings) config(tenant string) DirectorySyncConfig {
	return DirectorySyncConfig{TenantID: tenant, URL: s.URL, BaseDN: s.BaseDN, BindDN: s.BindDN, UserFilter: s.UserFilter, GroupFilter: s.GroupFilter,
		GUIDAttribute: s.GUIDAttribute, LoginAttribute: s.LoginAttribute, ChangedAttribute: s.ChangedAttribute, IntervalMinutes: s.IntervalMinutes, FullHours: s.FullHours, TLSServerName: s.TLSServerName}
}

type DirectorySettingsView struct {
	Tenant           string                `json:"tenant_id"`
	Source           string                `json:"source"` // none | web | config
	SecretsAvailable bool                  `json:"secrets_available"`
	Revision         *string               `json:"revision"`
	Settings         *DirectoryWebSettings `json:"settings"`
	PasswordSet      bool                  `json:"password_set"`
}

type DirectorySettingsUpdate struct {
	Revision string               `json:"revision"` // "" — первая настройка
	Settings DirectoryWebSettings `json:"settings"`
	Password *string              `json:"password,omitempty"` // только запись; нет — прежний
}

type DirectoryTestResult struct {
	OK     bool    `json:"ok"`
	People int     `json:"people_found"`
	Teams  int     `json:"teams_found"`
	Error  *string `json:"error"`
}

const passwordKey = "ldap-bind-password"

type cachedDirectory struct {
	revision string
	d        *DirectorySync
}

// directoryFor — синхронизация тенанта: из конфигурации центра (приоритет) или из настроек Web (кэш по ревизии).
func (r *Registry) directoryFor(ctx context.Context, tenant string) (*DirectorySync, string, error) {
	if r.Directory != nil && r.Directory.Config.TenantID == tenant {
		return r.Directory, "config", nil
	}
	tx, e := r.Pool.Begin(ctx)
	if e != nil {
		return nil, "", e
	}
	stored, e := r.Owners.DirectorySettings(ctx, tx, tenant)
	tx.Rollback(ctx)
	if e != nil || stored == nil {
		return nil, "none", e
	}
	r.dirMu.Lock()
	defer r.dirMu.Unlock()
	if r.dirCache == nil {
		r.dirCache = map[string]cachedDirectory{}
	}
	if c, ok := r.dirCache[tenant]; ok && c.revision == stored.Revision {
		return c.d, "web", nil
	}
	var s DirectoryWebSettings
	if e = json.Unmarshal(stored.Settings, &s); e != nil {
		return nil, "web", e
	}
	if r.Secrets == nil {
		return nil, "web", ErrSecretsUnavailable
	}
	password, ok, e := r.Secrets.Get(ctx, tenant, passwordKey)
	if e != nil {
		return nil, "web", e
	}
	if !ok {
		return nil, "web", errors.New("directory bind password is not set")
	}
	d, e := buildDirectorySync(s.config(tenant), string(password), []byte(s.CAPEM))
	if e != nil {
		return nil, "web", e
	}
	r.dirCache[tenant] = cachedDirectory{stored.Revision, d}
	return d, "web", nil
}

func (r *Registry) DirectorySettingsGet(ctx context.Context, id accessport.Identity) (DirectorySettingsView, error) {
	out := DirectorySettingsView{Tenant: id.TenantID, Source: "none", SecretsAvailable: r.Secrets != nil}
	tx, e := r.adminTx(ctx, id, "sources:admin")
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	if r.Directory != nil && r.Directory.Config.TenantID == id.TenantID {
		c := r.Directory.Config
		out.Source, out.PasswordSet = "config", true
		out.Settings = &DirectoryWebSettings{URL: c.URL, BaseDN: c.BaseDN, BindDN: c.BindDN, UserFilter: c.UserFilter, GroupFilter: c.GroupFilter, GUIDAttribute: c.GUIDAttribute,
			LoginAttribute: c.LoginAttribute, ChangedAttribute: c.ChangedAttribute, IntervalMinutes: c.IntervalMinutes, FullHours: c.FullHours, TLSServerName: c.TLSServerName}
		return out, tx.Commit(ctx)
	}
	stored, e := r.Owners.DirectorySettings(ctx, tx, id.TenantID)
	if e != nil {
		return out, e
	}
	if stored != nil {
		var s DirectoryWebSettings
		if e = json.Unmarshal(stored.Settings, &s); e != nil {
			return out, e
		}
		out.Source, out.Revision, out.Settings = "web", &stored.Revision, &s
		if r.Secrets != nil {
			_, out.PasswordSet, _ = r.Secrets.Get(ctx, id.TenantID, passwordKey)
		}
	}
	return out, tx.Commit(ctx)
}

// validateSettings — проверка параметров сборкой синхронизации (пароль для проверки не нужен).
func validateSettings(tenant string, s DirectoryWebSettings) error {
	if len(s.CAPEM) > 32768 {
		return domain.Invalid
	}
	if _, e := buildDirectorySync(s.config(tenant), "validation-only", []byte(s.CAPEM)); e != nil {
		return domain.Invalid
	}
	return nil
}

func (r *Registry) DirectorySettingsPut(ctx context.Context, id accessport.Identity, u DirectorySettingsUpdate) (DirectorySettingsView, error) {
	if r.Directory != nil && r.Directory.Config.TenantID == id.TenantID {
		return DirectorySettingsView{}, domain.Conflict // задано в конфигурации центра
	}
	if r.Secrets == nil {
		return DirectorySettingsView{}, domain.Conflict
	}
	if e := validateSettings(id.TenantID, u.Settings); e != nil {
		return DirectorySettingsView{}, e
	}
	if u.Password != nil && (len(*u.Password) == 0 || len(*u.Password) > 1024) {
		return DirectorySettingsView{}, domain.Invalid
	}
	tx, e := r.adminTx(ctx, id, "sources:admin")
	if e != nil {
		return DirectorySettingsView{}, e
	}
	defer tx.Rollback(ctx)
	if u.Password == nil {
		if _, ok, e := r.Secrets.Get(ctx, id.TenantID, passwordKey); e != nil || !ok {
			if e == nil {
				e = domain.Invalid // первый раз пароль обязателен
			}
			return DirectorySettingsView{}, e
		}
	}
	raw, _ := json.Marshal(u.Settings)
	if e = r.Owners.PutDirectorySettings(ctx, tx, id.TenantID, u.Revision, raw, id.UserID); e != nil {
		return DirectorySettingsView{}, e
	}
	action := "responsibility.directory_settings_saved"
	if u.Password != nil {
		action = "responsibility.directory_settings_saved_with_password"
		// секрет пишется до фиксации настроек: при сбое записи настройки не меняются
		if e = r.Secrets.Put(ctx, id.TenantID, passwordKey, []byte(*u.Password)); e != nil {
			return DirectorySettingsView{}, e
		}
	}
	if e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, action, "directory_settings", id.TenantID); e != nil {
		return DirectorySettingsView{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return DirectorySettingsView{}, e
	}
	return r.DirectorySettingsGet(ctx, id)
}

func (r *Registry) DirectorySettingsDelete(ctx context.Context, id accessport.Identity, revision string) error {
	if r.Directory != nil && r.Directory.Config.TenantID == id.TenantID {
		return domain.Conflict
	}
	tx, e := r.adminTx(ctx, id, "sources:admin")
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if e = r.Owners.DeleteDirectorySettings(ctx, tx, id.TenantID, revision); e != nil {
		return e
	}
	if e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "responsibility.directory_settings_deleted", "directory_settings", id.TenantID); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

// DirectoryTest — проверка подключения: bind и чтение каталога без изменений в SurveyScan. Пароль — введённый
// или сохранённый.
func (r *Registry) DirectoryTest(ctx context.Context, id accessport.Identity, u DirectorySettingsUpdate) (DirectoryTestResult, error) {
	if e := validateSettings(id.TenantID, u.Settings); e != nil {
		return DirectoryTestResult{}, e
	}
	tx, e := r.adminTx(ctx, id, "sources:admin")
	if e != nil {
		return DirectoryTestResult{}, e
	}
	tx.Rollback(ctx)
	password := ""
	if u.Password != nil {
		password = *u.Password
	} else if r.Secrets != nil {
		stored, ok, e := r.Secrets.Get(ctx, id.TenantID, passwordKey)
		if e != nil {
			return DirectoryTestResult{}, e
		}
		if ok {
			password = string(stored)
		}
	}
	if password == "" {
		return DirectoryTestResult{}, domain.Invalid
	}
	d, e := buildDirectorySync(u.Settings.config(id.TenantID), password, []byte(u.Settings.CAPEM))
	if e != nil {
		return DirectoryTestResult{}, domain.Invalid
	}
	snapshot, e := d.Read(nil)
	if e != nil {
		msg := directoryHint(e)
		return DirectoryTestResult{Error: &msg}, nil
	}
	return DirectoryTestResult{OK: true, People: len(snapshot.People), Teams: len(snapshot.Teams)}, nil
}

func (r *Registry) directorySettingsHandlers() map[string]http.Handler {
	return map[string]http.Handler{
		"GET /api/v1/directory-sync/settings": http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if _, ok := queryOnly(w, req); !ok {
				return
			}
			ctx, cancel, id := cmdbContext(req)
			defer cancel()
			out, e := r.DirectorySettingsGet(ctx, id)
			if e != nil {
				cmdbError(w, req, e)
				return
			}
			registryJSON(w, out)
		}),
		"PUT /api/v1/directory-sync/settings": http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var body DirectorySettingsUpdate
			if !readOperationBody(w, req, &body) {
				return
			}
			ctx, cancel, id := cmdbContext(req)
			defer cancel()
			out, e := r.DirectorySettingsPut(ctx, id, body)
			if e != nil {
				cmdbError(w, req, e)
				return
			}
			registryJSON(w, out)
		}),
		"DELETE /api/v1/directory-sync/settings": http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			q, ok := queryOnly(w, req, "revision")
			if !ok {
				return
			}
			ctx, cancel, id := cmdbContext(req)
			defer cancel()
			if e := r.DirectorySettingsDelete(ctx, id, q.Get("revision")); e != nil {
				cmdbError(w, req, e)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusNoContent)
		}),
		"POST /api/v1/directory-sync/test": http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var body DirectorySettingsUpdate
			if !readOperationBody(w, req, &body) {
				return
			}
			ctx, cancel := assetOperationContext(w, req)
			defer cancel()
			id, _ := access.Identity(req.Context())
			out, e := r.DirectoryTest(ctx, id, body)
			if e != nil {
				cmdbError(w, req, e)
				return
			}
			registryJSON(w, out)
		}),
		"POST /api/v1/webhooks/enable": http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if !readOperationBody(w, req, &struct{}{}) {
				return
			}
			ctx, cancel, id := cmdbContext(req)
			defer cancel()
			tx, e := r.adminTx(ctx, id, "sources:admin")
			if e == nil {
				var created bool
				if created, e = r.EnableWebhooks(ctx); e == nil && created {
					e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "messaging.webhooks_enabled", "webhooks", id.TenantID)
				}
				if e == nil {
					e = tx.Commit(ctx)
				}
				tx.Rollback(ctx)
			}
			if errors.Is(e, ErrSecretsUnavailable) {
				e = domain.Conflict
			}
			if e != nil {
				cmdbError(w, req, e)
				return
			}
			out, e := r.ListWebhooks(ctx, id)
			if e != nil {
				cmdbError(w, req, e)
				return
			}
			registryJSON(w, out)
		}),
	}
}
