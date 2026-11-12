package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	accessport "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/responsibility"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/go-ldap/ldap/v3"
	"github.com/jackc/pgx/v5"
)

// C31.02 (ADR decisions/C31-integrations.md): синхронизация оргструктуры из Active Directory, только чтение (контракт
// атрибутов ldap-sync/1). Центр читает каталог служебной учёткой, применяет снимок одной транзакцией; выбывшие
// ответственные передают активы резервной команде площадки штатным путём C27 (версия, история, аудит, событие).

const DirectoryActor = "directory-sync"

type DirectorySyncConfig struct {
	TenantID     string `json:"tenant_id"`
	URL          string `json:"url"` // ldaps://host:636; ldap:// — только при allow_plaintext (стенд разработки)
	BaseDN       string `json:"base_dn"`
	BindDN       string `json:"bind_dn"`
	PasswordFile string `json:"bind_password_file"` // приватный файл (0600), не в БД и не в журнале
	CAFile       string `json:"ca_certificate_file,omitempty"`
	UserFilter   string `json:"user_filter,omitempty"`  // по умолчанию (&(objectCategory=person)(objectClass=user))
	GroupFilter  string `json:"group_filter,omitempty"` // по умолчанию — синхронизация команд выключена
	// Атрибуты (для совместимых каталогов; по умолчанию — AD)
	GUIDAttribute    string `json:"guid_attribute,omitempty"`    // objectGUID (двоичный) или entryUUID (строка)
	LoginAttribute   string `json:"login_attribute,omitempty"`   // sAMAccountName
	ChangedAttribute string `json:"changed_attribute,omitempty"` // whenChanged
	IntervalMinutes  int    `json:"interval_minutes,omitempty"`  // 15
	FullHours        int    `json:"full_sync_hours,omitempty"`   // 24
	AllowPlaintext   bool   `json:"allow_plaintext,omitempty"`
	// Имя в сертификате контроллера, если адрес задан IP (сертификат AD выписан на DNS-имя); пусто — хост из url
	TLSServerName string `json:"tls_server_name,omitempty"`
}

type DirectorySync struct {
	Config   DirectorySyncConfig
	password string
	tls      *tls.Config
	mu       sync.Mutex // один прогон за раз
}

// NewDirectorySync проверяет конфигурацию и читает секрет и CA из файлов (блок ldap_sync конфигурации центра).
func NewDirectorySync(cfg DirectorySyncConfig) (*DirectorySync, error) {
	secret, e := ReadPrivate(cfg.PasswordFile, 4096)
	if e != nil {
		return nil, e
	}
	var ca []byte
	if cfg.CAFile != "" {
		if ca, e = os.ReadFile(cfg.CAFile); e != nil {
			return nil, errors.New("ldap_sync.ca_certificate_file unavailable")
		}
	}
	return buildDirectorySync(cfg, strings.TrimRight(string(secret), "\r\n"), ca)
}

// buildDirectorySync — проверка параметров и сборка (общая для конфигурации центра и настроек из Web, C31.05).
func buildDirectorySync(cfg DirectorySyncConfig, password string, caPEM []byte) (*DirectorySync, error) {
	u, e := url.Parse(cfg.URL)
	if e != nil || u.Host == "" || u.Path != "" && u.Path != "/" {
		return nil, errors.New("ldap_sync.url must be ldaps://host[:port]")
	}
	if u.Scheme != "ldaps" && !(u.Scheme == "ldap" && cfg.AllowPlaintext) {
		return nil, errors.New("ldap_sync.url must use ldaps (ldap only with allow_plaintext)")
	}
	if !identifier.Valid(cfg.TenantID) || cfg.BaseDN == "" || cfg.BindDN == "" {
		return nil, errors.New("ldap_sync requires tenant_id, base_dn and bind_dn")
	}
	if _, e = ldap.ParseDN(cfg.BaseDN); e != nil {
		return nil, errors.New("ldap_sync.base_dn is not a DN")
	}
	for _, f := range []string{cfg.UserFilter, cfg.GroupFilter} {
		if f != "" {
			if _, e = ldap.CompileFilter(f); e != nil {
				return nil, errors.New("ldap_sync filter is invalid")
			}
		}
	}
	if cfg.UserFilter == "" {
		cfg.UserFilter = "(&(objectCategory=person)(objectClass=user))"
	}
	if cfg.GUIDAttribute == "" {
		cfg.GUIDAttribute = "objectGUID"
	}
	if cfg.LoginAttribute == "" {
		cfg.LoginAttribute = "sAMAccountName"
	}
	if cfg.ChangedAttribute == "" {
		cfg.ChangedAttribute = "whenChanged"
	}
	if cfg.IntervalMinutes == 0 {
		cfg.IntervalMinutes = 15
	}
	if cfg.FullHours == 0 {
		cfg.FullHours = 24
	}
	if cfg.IntervalMinutes < 1 || cfg.IntervalMinutes > 1440 || cfg.FullHours < 1 || cfg.FullHours > 24*30 {
		return nil, errors.New("ldap_sync interval_minutes 1..1440, full_sync_hours 1..720")
	}
	if password == "" {
		return nil, errors.New("ldap_sync bind password is required")
	}
	d := &DirectorySync{Config: cfg, password: password}
	serverName := u.Hostname()
	if cfg.TLSServerName != "" {
		if len(cfg.TLSServerName) > 253 || strings.ContainsAny(cfg.TLSServerName, " /:@") {
			return nil, errors.New("ldap_sync.tls_server_name must be a host name")
		}
		serverName = cfg.TLSServerName // проверка сертификата не отключается: меняется только ожидаемое имя
	}
	d.tls = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}
	if len(caPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("ldap_sync.ca_certificate_file has no certificates")
		}
		d.tls.RootCAs = pool
	}
	return d, nil
}

// adGUID — objectGUID AD (16 байт, первые три поля little-endian) в каноническом виде.
func adGUID(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x", binary.LittleEndian.Uint32(b[0:4]), binary.LittleEndian.Uint16(b[4:6]), binary.LittleEndian.Uint16(b[6:8]), b[8:10], b[10:16])
}

func (d *DirectorySync) guid(e *ldap.Entry) string {
	if strings.EqualFold(d.Config.GUIDAttribute, "objectGUID") {
		return adGUID(e.GetRawAttributeValue(d.Config.GUIDAttribute))
	}
	return strings.ToLower(e.GetAttributeValue(d.Config.GUIDAttribute))
}

func ldapTime(t time.Time) string { return t.UTC().Format("20060102150405") + ".0Z" }

func (d *DirectorySync) connect() (*ldap.Conn, error) {
	c, e := ldap.DialURL(d.Config.URL, ldap.DialWithTLSConfig(d.tls))
	if e != nil {
		return nil, fmt.Errorf("directory unavailable: %w", e)
	}
	c.SetTimeout(60 * time.Second)
	if e = c.Bind(d.Config.BindDN, d.password); e != nil {
		c.Close()
		return nil, errors.New("directory bind failed") // без подробностей: ответ сервера может повторять учётку
	}
	return c, nil
}

func (d *DirectorySync) search(c *ldap.Conn, base string, scope int, filter string, attrs []string) ([]*ldap.Entry, error) {
	r, e := c.SearchWithPaging(ldap.NewSearchRequest(base, scope, ldap.NeverDerefAliases, 0, 120, false, filter, attrs, nil), 500)
	if e != nil {
		return nil, e
	}
	return r.Entries, nil
}

// members — значения member с диапазонной выборкой AD (member;range=0-1499) для больших групп.
func (d *DirectorySync) members(c *ldap.Conn, e *ldap.Entry) ([]string, error) {
	out := append([]string{}, e.GetAttributeValues("member")...)
	for _, a := range e.Attributes {
		name := strings.ToLower(a.Name)
		if !strings.HasPrefix(name, "member;range=") {
			continue
		}
		out = append(out, a.Values...)
		next := name
		for !strings.HasSuffix(next, "-*") {
			lo, hi, ok := strings.Cut(strings.TrimPrefix(next, "member;range="), "-")
			from, err1 := strconv.Atoi(lo)
			to, err2 := strconv.Atoi(hi)
			if !ok || err1 != nil || err2 != nil || to < from {
				return nil, errors.New("directory returned malformed member range")
			}
			r, err := d.search(c, e.DN, ldap.ScopeBaseObject, "(objectClass=*)", []string{fmt.Sprintf("member;range=%d-*", to+1)})
			if err != nil || len(r) != 1 {
				return nil, errors.New("directory member range read failed")
			}
			next = ""
			for _, b := range r[0].Attributes {
				if n := strings.ToLower(b.Name); strings.HasPrefix(n, "member;range=") {
					out = append(out, b.Values...)
					next = n
				}
			}
			if next == "" {
				break
			}
		}
	}
	return out, nil
}

// Read — снимок каталога: since==nil — полный, иначе изменённые после since объекты.
func (d *DirectorySync) Read(since *time.Time) (responsibility.Directory, error) {
	cfg := d.Config
	out := responsibility.Directory{Full: since == nil}
	c, e := d.connect()
	if e != nil {
		return out, e
	}
	defer c.Close()
	changed := ""
	if since != nil {
		changed = "(" + cfg.ChangedAttribute + ">=" + ldapTime(*since) + ")"
	}
	attrs := []string{cfg.GUIDAttribute, cfg.LoginAttribute, "displayName", "cn", "mail", "userAccountControl"}
	users, e := d.search(c, cfg.BaseDN, ldap.ScopeWholeSubtree, "(&"+cfg.UserFilter+changed+")", attrs)
	if e != nil {
		return out, fmt.Errorf("directory user search failed: %w", e)
	}
	byDN := map[string]string{}
	for _, u := range users {
		guid := d.guid(u)
		name := u.GetAttributeValue("displayName")
		if name == "" {
			name = u.GetAttributeValue("cn")
		}
		uac, _ := strconv.ParseInt(u.GetAttributeValue("userAccountControl"), 10, 64)
		out.People = append(out.People, responsibility.DirPerson{GUID: guid, Login: u.GetAttributeValue(cfg.LoginAttribute), Name: name, Mail: u.GetAttributeValue("mail"), Disabled: uac&2 != 0})
		byDN[strings.ToLower(u.DN)] = guid
	}
	if cfg.GroupFilter == "" {
		return out, nil
	}
	groups, e := d.search(c, cfg.BaseDN, ldap.ScopeWholeSubtree, "(&"+cfg.GroupFilter+changed+")", []string{cfg.GUIDAttribute, "cn", "displayName", "mail", "member"})
	if e != nil {
		return out, fmt.Errorf("directory group search failed: %w", e)
	}
	for _, g := range groups {
		dns, e := d.members(c, g)
		if e != nil {
			return out, e
		}
		team := responsibility.DirTeam{GUID: d.guid(g), Name: g.GetAttributeValue("displayName"), Mail: g.GetAttributeValue("mail")}
		if team.Name == "" {
			team.Name = g.GetAttributeValue("cn")
		}
		for _, dn := range dns {
			key := strings.ToLower(dn)
			guid, ok := byDN[key]
			if !ok {
				// участник не менялся (инкремент) или не человек: читаем GUID по DN, если он подходит под фильтр людей
				r, err := d.search(c, dn, ldap.ScopeBaseObject, cfg.UserFilter, []string{cfg.GUIDAttribute})
				if err == nil && len(r) == 1 {
					guid = d.guid(r[0])
				}
				byDN[key] = guid
			}
			if guid != "" {
				team.Members = append(team.Members, guid)
			}
		}
		out.Teams = append(out.Teams, team)
	}
	return out, nil
}

// SyncDirectory — один прогон (full принудительно или по расписанию). Ошибка чтения или применения записывается
// в журнал прогонов со статусом failed; изменений тогда нет.
func (r *Registry) SyncDirectory(ctx context.Context, forceFull bool) (responsibility.SyncRun, error) {
	if r.Directory == nil {
		return responsibility.SyncRun{}, errors.New("directory sync not configured")
	}
	return r.syncWith(ctx, r.Directory, forceFull)
}

func (r *Registry) syncWith(ctx context.Context, d *DirectorySync, forceFull bool) (run responsibility.SyncRun, err error) {
	// C35.02: один прогон тенанта на весь контур (несколько worker-процессов не синхронизируют одно и то же дважды)
	e := r.exclusive(ctx, "directory-sync:"+d.Config.TenantID, func(ctx context.Context) error {
		run, err = r.syncLocked(ctx, d, forceFull)
		return nil
	})
	if e != nil {
		return run, e
	}
	return run, err
}

func (r *Registry) syncLocked(ctx context.Context, d *DirectorySync, forceFull bool) (responsibility.SyncRun, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	tenant := d.Config.TenantID
	run := responsibility.SyncRun{ID: identifier.New(), Mode: "full", Started: time.Now().UTC()}
	var since *time.Time
	if !forceFull {
		tx, e := r.Pool.Begin(ctx)
		if e != nil {
			return run, e
		}
		lastFull, e1 := r.Owners.LastSync(ctx, tx, tenant, "full")
		last, e2 := r.Owners.LastSync(ctx, tx, tenant, "")
		tx.Rollback(ctx)
		if e = errors.Join(e1, e2); e != nil {
			return run, e
		}
		if lastFull != nil && time.Since(*lastFull) < time.Duration(d.Config.FullHours)*time.Hour && last != nil {
			t := last.Add(-5 * time.Minute) // запас на расхождение часов и задержку репликации контроллеров
			since, run.Mode = &t, "incremental"
		}
	}
	snapshot, e := d.Read(since)
	var counters responsibility.SyncCounters
	if e == nil {
		counters, e = r.applyDirectory(ctx, tenant, snapshot, &run)
	}
	if e == nil {
		return run, nil
	}
	run.Finished, run.Status = time.Now().UTC(), "failed"
	msg := directoryHint(e)
	run.Error = &msg
	run.Counters, _ = json.Marshal(counters)
	tx, e2 := r.Pool.Begin(ctx)
	if e2 != nil {
		return run, e
	}
	defer tx.Rollback(ctx)
	if e2 = r.Owners.RecordSyncRun(ctx, tx, tenant, run); e2 == nil {
		if e2 = r.Audit.Record(ctx, tx, tenant, DirectoryActor, "responsibility.directory_sync_failed", "directory_sync", run.ID); e2 == nil {
			e2 = tx.Commit(ctx)
		}
	}
	return run, errors.Join(e, e2)
}

func (r *Registry) applyDirectory(ctx context.Context, tenant string, snapshot responsibility.Directory, run *responsibility.SyncRun) (responsibility.SyncCounters, error) {
	tx, e := r.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if e != nil {
		return responsibility.SyncCounters{}, e
	}
	defer tx.Rollback(ctx)
	if e = lockRegistry(ctx, tx, tenant); e != nil {
		return responsibility.SyncCounters{}, e
	}
	counters, changes, e := r.Owners.SyncDirectory(ctx, tx, tenant, snapshot, DirectoryActor)
	if e != nil {
		return counters, e
	}
	id := accessport.Identity{TenantID: tenant, UserID: DirectoryActor}
	for _, c := range changes {
		if e = r.assignmentEvent(ctx, tx, id, c); e != nil {
			return counters, e
		}
	}
	run.Finished, run.Status = time.Now().UTC(), "succeeded"
	if run.Counters, e = json.Marshal(counters); e != nil {
		return counters, e
	}
	if e = r.Owners.RecordSyncRun(ctx, tx, tenant, *run); e != nil {
		return counters, e
	}
	if e = r.Audit.Record(ctx, tx, tenant, DirectoryActor, "responsibility.directory_synced", "directory_sync", run.ID); e != nil {
		return counters, e
	}
	return counters, tx.Commit(ctx)
}

// DirectoryMaintain — фоновая роль центра: каждую минуту проверяет тенанты с синхронизацией (конфигурация центра
// и настройки из Web) и запускает прогон, если прошёл интервал с прошлого прогона (полный — раз в full_sync_hours).
func (r *Registry) DirectoryMaintain(ctx context.Context, log func(string)) {
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		tenants := map[string]bool{}
		if r.Directory != nil {
			tenants[r.Directory.Config.TenantID] = true
		}
		if tx, e := r.Pool.Begin(ctx); e == nil {
			if list, e := r.Owners.DirectoryTenants(ctx, tx); e == nil {
				for t := range list {
					tenants[t] = true
				}
			}
			tx.Rollback(ctx)
		}
		for tenant := range tenants {
			task, done := context.WithTimeout(ctx, 30*time.Minute)
			d, _, e := r.directoryFor(task, tenant)
			if e == nil && d != nil {
				var last *time.Time
				if tx, e2 := r.Pool.Begin(task); e2 == nil {
					last, _ = r.Owners.LastRun(task, tx, tenant)
					tx.Rollback(task)
				}
				if last == nil || time.Since(*last) >= time.Duration(d.Config.IntervalMinutes)*time.Minute {
					run, e := r.syncWith(task, d, false)
					if errors.Is(e, ErrBusy) {
						// прогон тенанта уже ведёт другой процесс центра
					} else if e != nil {
						log(fmt.Sprintf("directory sync %s %s failed: %v", tenant, run.Mode, e))
					} else {
						log(fmt.Sprintf("directory sync %s %s: %s", tenant, run.Mode, run.Counters))
					}
				}
			} else if e != nil {
				log("directory sync " + tenant + " not ready: " + e.Error())
			}
			done()
		}
		timer.Reset(time.Minute)
	}
}

type DirectorySyncStatus struct {
	Tenant     string                   `json:"tenant_id"`
	Configured bool                     `json:"configured"`
	Source     *string                  `json:"source"` // адрес каталога (без учётных данных)
	Interval   int                      `json:"interval_minutes"`
	FullHours  int                      `json:"full_sync_hours"`
	Teams      bool                     `json:"teams_enabled"`
	Runs       []responsibility.SyncRun `json:"runs"`
}

type DirectorySyncRequest struct {
	Mode string `json:"mode"` // full | auto
}

func (r *Registry) DirectoryStatus(ctx context.Context, id accessport.Identity) (DirectorySyncStatus, error) {
	out := DirectorySyncStatus{Tenant: id.TenantID, Runs: []responsibility.SyncRun{}}
	tx, e := r.readTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	if d, _, e := r.directoryFor(ctx, id.TenantID); e == nil && d != nil {
		out.Configured, out.Source, out.Interval, out.FullHours, out.Teams = true, &d.Config.URL, d.Config.IntervalMinutes, d.Config.FullHours, d.Config.GroupFilter != ""
	}
	if out.Runs, e = r.Owners.SyncRuns(ctx, tx, id.TenantID, 20); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}

func (r *Registry) RunDirectorySync(ctx context.Context, id accessport.Identity, req DirectorySyncRequest) (responsibility.SyncRun, error) {
	if req.Mode != "full" && req.Mode != "auto" {
		return responsibility.SyncRun{}, domain.Invalid
	}
	tx, e := r.Pool.Begin(ctx)
	if e != nil {
		return responsibility.SyncRun{}, e
	}
	_, e = r.Auth.Authorize(ctx, tx, id.CredentialID, id.TenantID, "sources:admin")
	if e == nil {
		e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "responsibility.directory_sync_requested", "directory_sync", req.Mode)
	}
	if e == nil {
		e = tx.Commit(ctx)
	}
	tx.Rollback(ctx)
	if e != nil {
		return responsibility.SyncRun{}, e
	}
	d, _, e := r.directoryFor(ctx, id.TenantID)
	if e != nil {
		return responsibility.SyncRun{}, e
	}
	if d == nil {
		return responsibility.SyncRun{}, domain.NotFound
	}
	run, e := r.syncWith(ctx, d, req.Mode == "full")
	if errors.Is(e, ErrBusy) {
		return run, domain.Conflict // синхронизация уже идёт в другом процессе центра
	}
	if run.Status == "failed" {
		return run, nil // итог прогона — в ответе и журнале
	}
	return run, e
}

func (r *Registry) directoryHandlers() map[string]struct {
	permission string
	handler    http.Handler
} {
	type route = struct {
		permission string
		handler    http.Handler
	}
	return map[string]route{
		"GET /api/v1/directory-sync": {"sources:read", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if _, ok := queryOnly(w, req); !ok {
				return
			}
			ctx, cancel, id := cmdbContext(req)
			defer cancel()
			out, e := r.DirectoryStatus(ctx, id)
			if e != nil {
				cmdbError(w, req, e)
				return
			}
			registryJSON(w, out)
		})},
		"POST /api/v1/directory-sync/run": {"sources:admin", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var body DirectorySyncRequest
			if !readOperationBody(w, req, &body) {
				return
			}
			ctx, cancel := assetOperationContext(w, req)
			defer cancel()
			id, _ := access.Identity(req.Context())
			out, e := r.RunDirectorySync(ctx, id, body)
			if e != nil {
				cmdbError(w, req, e)
				return
			}
			registryJSON(w, out)
		})},
	}
}

// directoryHint — текст ошибки с подсказкой администратору для частых причин (стенд R-027: адрес DC по IP).
func directoryHint(e error) string {
	msg := e.Error()
	switch {
	case strings.Contains(msg, "IP SANs"):
		msg += " — сертификат контроллера выписан на имя: укажите в адресе имя контроллера (ldaps://dc01.example.local:636) или заполните «Имя контроллера в сертификате»"
	case strings.Contains(msg, "unknown authority"):
		msg += " — сертификат контроллера выдан неизвестным центром: вставьте сертификат CA (PEM) в настройки"
	case strings.Contains(msg, "certificate is valid for"):
		msg += " — имя в адресе не совпадает с сертификатом: проверьте адрес или «Имя контроллера в сертификате»"
	case strings.Contains(msg, "bind failed"):
		msg += " — проверьте DN учётки и пароль"
	}
	return msg
}
