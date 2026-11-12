package responsibility

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
)

// C31.02 (ADR decisions/C31-integrations.md): оргструктура из каталога (Active Directory, только чтение). Каталог —
// мастер людей и команд с origin='ldap'; SurveyScan их не правит. Идентичность — objectGUID (external_id).

type DirPerson struct {
	GUID, Login, Name, Mail string
	Disabled                bool
}

type DirTeam struct {
	GUID, Name, Mail string
	Members          []string // objectGUID людей; прочие (вложенные группы, чужие объекты) пропускаются
}

// Directory — снимок каталога. Full: снимок полный, отсутствующие в нём субъекты каталога выбывают. Иначе —
// только изменённые объекты (у команды в снимке состав полный).
type Directory struct {
	People []DirPerson
	Teams  []DirTeam
	Full   bool
}

type SyncCounters struct {
	People       int      `json:"people_seen"`
	Teams        int      `json:"teams_seen"`
	Created      int      `json:"created"`
	Updated      int      `json:"updated"`
	Deactivated  int      `json:"deactivated"`
	Reactivated  int      `json:"reactivated"`
	MembersAdded int      `json:"members_added"`
	MembersEnded int      `json:"members_removed"`
	LoginsLinked int      `json:"logins_linked"`
	Reassigned   int      `json:"assignments_reassigned"`
	Problems     []string `json:"problems,omitempty"`
}

func (c *SyncCounters) problem(format string, a ...any) {
	if len(c.Problems) < 50 {
		c.Problems = append(c.Problems, fmt.Sprintf(format, a...))
	}
}

// ErrMassRemoval — полный снимок убрал бы слишком много субъектов (вероятна ошибка фильтра или каталога): прогон
// отклоняется целиком, ничего не меняется.
var ErrMassRemoval = errors.New("directory snapshot would deactivate too many subjects")

func cut(s string, max int) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > max {
		s = string(r[:max])
	}
	return s
}

type dirSubject struct {
	id, kind, name, contact string
	active, fallback        bool
	user                    *string
}

func (Store) dirSubject(ctx context.Context, tx pgx.Tx, tenant, guid string) (*dirSubject, error) {
	var s dirSubject
	e := tx.QueryRow(ctx, `SELECT s.subject_id::text,s.kind,s.name,s.contact,s.active,s.user_id::text,
EXISTS(SELECT 1 FROM scope.sites x WHERE x.tenant_id=s.tenant_id AND x.fallback_subject_id=s.subject_id)
FROM responsibility.subjects s WHERE s.tenant_id=$1 AND s.origin='ldap' AND s.external_id=$2 FOR UPDATE OF s`, tenant, guid).Scan(&s.id, &s.kind, &s.name, &s.contact, &s.active, &s.user, &s.fallback)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil, nil
	}
	return &s, e
}

// freeLogin — учётная запись входа с этим логином (без учёта регистра), ещё не связанная с другим человеком.
func (Store) freeLogin(ctx context.Context, tx pgx.Tx, tenant, login string) (*string, error) {
	if login == "" {
		return nil, nil
	}
	var id string
	e := tx.QueryRow(ctx, `SELECT u.user_id::text FROM access.users u WHERE u.tenant_id=$1 AND lower(u.username)=lower($2)
AND NOT EXISTS(SELECT 1 FROM responsibility.subjects s WHERE s.tenant_id=u.tenant_id AND s.user_id=u.user_id) ORDER BY u.username LIMIT 1`, tenant, login).Scan(&id)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil, nil
	}
	return &id, e
}

func (s Store) upsert(ctx context.Context, tx pgx.Tx, tenant, kind, guid, name, contact string, disabled bool, login string, c *SyncCounters, changes *[]Change, actor string) (string, error) {
	guid = cut(guid, 128)
	name, contact = cut(name, 512), cut(contact, 512)
	if guid == "" || name == "" {
		c.problem("%s without objectGUID or name skipped", kind)
		return "", nil
	}
	if contact == "" {
		contact = name
	}
	cur, e := s.dirSubject(ctx, tx, tenant, guid)
	if e != nil {
		return "", e
	}
	if cur == nil {
		if disabled {
			return "", nil // отключённых в каталоге не заводим
		}
		user, e := s.freeLogin(ctx, tx, tenant, login)
		if e != nil {
			return "", e
		}
		id := identifier.New()
		if _, e = tx.Exec(ctx, "INSERT INTO responsibility.subjects(tenant_id,subject_id,kind,name,contact,user_id,origin,external_id,synced_at) VALUES($1,$2,$3,$4,$5,$6,'ldap',$7,now())", tenant, id, kind, name, contact, user, guid); e != nil {
			return "", e
		}
		c.Created++
		if user != nil {
			c.LoginsLinked++
		}
		return id, nil
	}
	if cur.kind != kind {
		c.problem("objectGUID %s changed kind %s→%s, skipped", guid, cur.kind, kind)
		return "", nil
	}
	if disabled {
		if cur.active {
			if cur.fallback {
				c.problem("%s %q is a site fallback team and cannot be deactivated", kind, cur.name)
			} else {
				moved, e := s.deactivate(ctx, tx, tenant, cur.id, actor)
				if e != nil {
					return "", e
				}
				*changes = append(*changes, moved...)
				c.Deactivated++
				c.Reassigned += len(moved)
			}
		}
		_, e = tx.Exec(ctx, "UPDATE responsibility.subjects SET synced_at=now() WHERE tenant_id=$1 AND subject_id=$2", tenant, cur.id)
		return "", e
	}
	var user *string
	if cur.user == nil && kind == "person" {
		if user, e = s.freeLogin(ctx, tx, tenant, login); e != nil {
			return "", e
		}
	}
	changed := cur.name != name || cur.contact != contact || !cur.active || user != nil
	if _, e = tx.Exec(ctx, `UPDATE responsibility.subjects SET name=$3,contact=$4,active=true,user_id=COALESCE(user_id,$5::uuid),synced_at=now(),
revision=revision+CASE WHEN $6 THEN 1 ELSE 0 END WHERE tenant_id=$1 AND subject_id=$2`, tenant, cur.id, name, contact, user, changed); e != nil {
		return "", e
	}
	switch {
	case !cur.active:
		c.Reactivated++
	case changed:
		c.Updated++
	}
	if user != nil {
		c.LoginsLinked++
	}
	return cur.id, nil
}

// SyncDirectory применяет снимок каталога в одной транзакции вызывающей стороны. Изменения назначений (выбывшие
// ответственные → резервная команда площадки) возвращаются для событий и истории активов.
func (s Store) SyncDirectory(ctx context.Context, tx pgx.Tx, tenant string, d Directory, actor string) (SyncCounters, []Change, error) {
	c := SyncCounters{People: len(d.People), Teams: len(d.Teams), Problems: []string{}}
	changes := []Change{}
	seen := map[string]bool{}
	for _, p := range d.People {
		contact := p.Mail
		if contact == "" {
			contact = p.Login
		}
		name := p.Name
		if strings.TrimSpace(name) == "" {
			name = p.Login
		}
		if _, e := s.upsert(ctx, tx, tenant, "person", p.GUID, name, contact, p.Disabled, p.Login, &c, &changes, actor); e != nil {
			return c, nil, e
		}
		seen[cut(p.GUID, 128)] = true
	}
	for _, t := range d.Teams {
		id, e := s.upsert(ctx, tx, tenant, "team", t.GUID, t.Name, t.Mail, false, "", &c, &changes, actor)
		if e != nil {
			return c, nil, e
		}
		seen[cut(t.GUID, 128)] = true
		if id == "" {
			continue
		}
		if e = s.syncMembers(ctx, tx, tenant, id, t, &c, actor); e != nil {
			return c, nil, e
		}
	}
	if d.Full {
		if e := s.removeAbsent(ctx, tx, tenant, seen, &c, &changes, actor); e != nil {
			return c, nil, e
		}
	}
	return c, changes, nil
}

func (Store) syncMembers(ctx context.Context, tx pgx.Tx, tenant, team string, t DirTeam, c *SyncCounters, actor string) error {
	guids := make([]string, 0, len(t.Members))
	for _, g := range t.Members {
		if g = cut(g, 128); g != "" {
			guids = append(guids, g)
		}
	}
	tag, e := tx.Exec(ctx, `UPDATE responsibility.team_members m SET valid_to=now() WHERE m.tenant_id=$1 AND m.team_id=$2 AND m.valid_to IS NULL
AND m.person_id NOT IN (SELECT subject_id FROM responsibility.subjects WHERE tenant_id=$1 AND origin='ldap' AND kind='person' AND active AND external_id=ANY($3))`, tenant, team, guids)
	if e != nil {
		return e
	}
	c.MembersEnded += int(tag.RowsAffected())
	tag, e = tx.Exec(ctx, `INSERT INTO responsibility.team_members(tenant_id,team_id,person_id,actor_ref)
SELECT $1,$2,s.subject_id,$4 FROM responsibility.subjects s WHERE s.tenant_id=$1 AND s.origin='ldap' AND s.kind='person' AND s.active AND s.external_id=ANY($3)
AND NOT EXISTS(SELECT 1 FROM responsibility.team_members m WHERE m.tenant_id=$1 AND m.team_id=$2 AND m.person_id=s.subject_id AND m.valid_to IS NULL)`, tenant, team, guids, actor)
	if e != nil {
		return e
	}
	c.MembersAdded += int(tag.RowsAffected())
	return nil
}

func (s Store) removeAbsent(ctx context.Context, tx pgx.Tx, tenant string, seen map[string]bool, c *SyncCounters, changes *[]Change, actor string) error {
	rows, e := tx.Query(ctx, `SELECT s.subject_id::text,s.external_id,s.name,EXISTS(SELECT 1 FROM scope.sites x WHERE x.tenant_id=s.tenant_id AND x.fallback_subject_id=s.subject_id)
FROM responsibility.subjects s WHERE s.tenant_id=$1 AND s.origin='ldap' AND s.active ORDER BY s.subject_id FOR UPDATE OF s`, tenant)
	if e != nil {
		return e
	}
	type gone struct {
		id, name string
		fallback bool
	}
	var absent []gone
	active := 0
	for rows.Next() {
		var id, guid, name string
		var fallback bool
		if e = rows.Scan(&id, &guid, &name, &fallback); e != nil {
			rows.Close()
			return e
		}
		active++
		if !seen[guid] {
			absent = append(absent, gone{id, name, fallback})
		}
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return e
	}
	if limit := max(10, active/4); len(absent) > limit {
		c.problem("full snapshot would deactivate %d of %d directory subjects (limit %d)", len(absent), active, limit)
		return ErrMassRemoval
	}
	for _, g := range absent {
		if g.fallback {
			c.problem("site fallback team %q is absent from the directory and stays active", g.name)
			continue
		}
		moved, e := s.deactivate(ctx, tx, tenant, g.id, actor)
		if e != nil {
			return e
		}
		*changes = append(*changes, moved...)
		c.Deactivated++
		c.Reassigned += len(moved)
	}
	return nil
}

// SyncRun — запись журнала синхронизаций.
type SyncRun struct {
	ID       string          `json:"run_id"`
	Mode     string          `json:"mode"`
	Started  time.Time       `json:"started_at"`
	Finished time.Time       `json:"finished_at"`
	Status   string          `json:"status"`
	Counters json.RawMessage `json:"counters"`
	Error    *string         `json:"error"`
}

func (Store) RecordSyncRun(ctx context.Context, tx pgx.Tx, tenant string, run SyncRun) error {
	if len(run.Counters) == 0 {
		run.Counters = json.RawMessage("{}")
	}
	if run.Error != nil {
		v := cut(*run.Error, 1024)
		run.Error = &v
	}
	_, e := tx.Exec(ctx, "INSERT INTO responsibility.directory_sync_runs(tenant_id,run_id,mode,started_at,finished_at,status,counters,error) VALUES($1,$2,$3,$4,$5,$6,$7,$8)", tenant, run.ID, run.Mode, run.Started, run.Finished, run.Status, run.Counters, run.Error)
	return e
}

// LastSync — начало последнего успешного прогона режима (или любого, mode=="").
func (Store) LastSync(ctx context.Context, tx pgx.Tx, tenant, mode string) (*time.Time, error) {
	var t *time.Time
	e := tx.QueryRow(ctx, "SELECT max(started_at) FROM responsibility.directory_sync_runs WHERE tenant_id=$1 AND status='succeeded' AND ($2='' OR mode=$2)", tenant, mode).Scan(&t)
	return t, e
}

func (Store) SyncRuns(ctx context.Context, tx pgx.Tx, tenant string, limit int) ([]SyncRun, error) {
	rows, e := tx.Query(ctx, "SELECT run_id::text,mode,started_at,finished_at,status,counters,error FROM responsibility.directory_sync_runs WHERE tenant_id=$1 ORDER BY started_at DESC,run_id LIMIT $2", tenant, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []SyncRun{}
	for rows.Next() {
		var r SyncRun
		if e = rows.Scan(&r.ID, &r.Mode, &r.Started, &r.Finished, &r.Status, &r.Counters, &r.Error); e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

var errDirectoryManaged = domain.Conflict // субъект ведёт каталог: ручная правка запрещена

// C31.05: настройки синхронизации из Web (несекретные; пароль — в хранилище секретов центра).
type DirectorySettings struct {
	Settings  json.RawMessage `json:"settings"`
	Revision  string          `json:"revision"`
	UpdatedAt time.Time       `json:"updated_at"`
}

func (Store) DirectorySettings(ctx context.Context, tx pgx.Tx, tenant string) (*DirectorySettings, error) {
	var s DirectorySettings
	e := tx.QueryRow(ctx, "SELECT settings,revision::text,updated_at FROM responsibility.directory_settings WHERE tenant_id=$1", tenant).Scan(&s.Settings, &s.Revision, &s.UpdatedAt)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil, nil
	}
	return &s, e
}

// PutDirectorySettings создаёт (revision "") или заменяет настройки при совпадении ревизии.
func (Store) PutDirectorySettings(ctx context.Context, tx pgx.Tx, tenant, revision string, settings json.RawMessage, actor string) error {
	if revision == "" {
		_, e := tx.Exec(ctx, "INSERT INTO responsibility.directory_settings(tenant_id,settings,actor_ref) VALUES($1,$2,$3)", tenant, settings, actor)
		if uniqueViolation(e) {
			return domain.Revision
		}
		return e
	}
	tag, e := tx.Exec(ctx, "UPDATE responsibility.directory_settings SET settings=$3,revision=revision+1,updated_at=now(),actor_ref=$4 WHERE tenant_id=$1 AND revision::text=$2", tenant, revision, settings, actor)
	if e == nil && tag.RowsAffected() != 1 {
		e = domain.Revision
	}
	return e
}

func (Store) DeleteDirectorySettings(ctx context.Context, tx pgx.Tx, tenant, revision string) error {
	tag, e := tx.Exec(ctx, "DELETE FROM responsibility.directory_settings WHERE tenant_id=$1 AND revision::text=$2", tenant, revision)
	if e == nil && tag.RowsAffected() != 1 {
		e = domain.Revision
	}
	return e
}

// DirectoryTenants — тенанты с настройками синхронизации и начало их последнего прогона (любого итога).
func (Store) DirectoryTenants(ctx context.Context, tx pgx.Tx) (map[string]*time.Time, error) {
	rows, e := tx.Query(ctx, `SELECT s.tenant_id::text,(SELECT max(r.started_at) FROM responsibility.directory_sync_runs r WHERE r.tenant_id=s.tenant_id) FROM responsibility.directory_settings s`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := map[string]*time.Time{}
	for rows.Next() {
		var tenant string
		var last *time.Time
		if e = rows.Scan(&tenant, &last); e != nil {
			return nil, e
		}
		out[tenant] = last
	}
	return out, rows.Err()
}

// LastRun — начало последнего прогона любого итога (для расписания: сбой не повторяется чаще интервала).
func (Store) LastRun(ctx context.Context, tx pgx.Tx, tenant string) (*time.Time, error) {
	var t *time.Time
	e := tx.QueryRow(ctx, "SELECT max(started_at) FROM responsibility.directory_sync_runs WHERE tenant_id=$1", tenant).Scan(&t)
	return t, e
}

// PruneSyncRuns оставляет последние keep прогонов каждого тенанта.
func PruneSyncRuns(ctx context.Context, tx pgx.Tx, keep int) (int64, error) {
	tag, e := tx.Exec(ctx, `DELETE FROM responsibility.directory_sync_runs r USING (SELECT tenant_id,run_id,row_number() OVER (PARTITION BY tenant_id ORDER BY started_at DESC,run_id) AS n
FROM responsibility.directory_sync_runs) x WHERE r.tenant_id=x.tenant_id AND r.run_id=x.run_id AND x.n > $1`, keep)
	return tag.RowsAffected(), e
}
