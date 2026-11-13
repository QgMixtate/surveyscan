package responsibility

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// C27 (ADR decisions/C27-ownership.md): субъекты (человек/команда), локальный оргисточник, роли назначения,
// атомарная передача без разрыва ответственности, деактивация с переназначением на резервную команду площадки.

var Roles = map[string]bool{"accountable": true, "business_owner": true, "technical": true, "custodian": true}

type SubjectInfo struct {
	ID       string  `json:"subject_id"`
	Kind     string  `json:"kind"`
	Name     string  `json:"name"`
	Contact  string  `json:"contact"`
	Active   bool    `json:"active"`
	Username *string `json:"username"`
	Revision string  `json:"revision"`
	Fallback bool    `json:"site_fallback"`
	Members  int     `json:"members"`
	// C31.02: local — ведётся в SurveyScan; ldap — из каталога (только чтение), synced_at — последняя синхронизация
	Origin   string     `json:"origin"`
	SyncedAt *time.Time `json:"synced_at"`
	// Логин в каталоге (sAMAccountName) — у субъектов из AD; заполняется синхронизацией
	DirectoryLogin *string `json:"directory_login,omitempty"`
}

type SubjectInput struct {
	Kind     string  `json:"kind,omitempty"`
	Name     *string `json:"name,omitempty"`
	Contact  *string `json:"contact,omitempty"`
	Username *string `json:"username,omitempty"` // "" — снять связь со входом
}

type Assignment struct {
	Role      string     `json:"role"`
	Subject   string     `json:"subject_id"`
	Name      string     `json:"subject_name"`
	Kind      string     `json:"subject_kind"`
	ValidFrom time.Time  `json:"valid_from"`
	ValidTo   *time.Time `json:"valid_to"`
	Reason    string     `json:"reason_code"`
	Note      *string    `json:"note"`
	Actor     string     `json:"actor_ref"`
}

// Change — изменение назначения на активе (для событий и истории вызывающей стороны).
type Change struct {
	Asset, Role, Subject, Reason string
}

func uniqueViolation(e error) bool {
	var pg *pgconn.PgError
	return errors.As(e, &pg) && pg.Code == "23505"
}

func clean(s *string, max int) bool {
	if s == nil {
		return true
	}
	*s = strings.TrimSpace(*s)
	return *s != "" && len([]rune(*s)) <= max
}

func (Store) loginID(ctx context.Context, tx pgx.Tx, tenant string, username *string) (*string, error) {
	if username == nil || *username == "" {
		return nil, nil
	}
	var id string
	e := tx.QueryRow(ctx, "SELECT user_id::text FROM access.users WHERE tenant_id=$1 AND username=$2", tenant, *username).Scan(&id)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil, domain.NotFound
	}
	return &id, e
}

func (s Store) CreateSubject(ctx context.Context, tx pgx.Tx, tenant string, in SubjectInput) (SubjectInfo, error) {
	if in.Kind != "person" && in.Kind != "team" || in.Name == nil || in.Contact == nil || !clean(in.Name, 512) || !clean(in.Contact, 512) {
		return SubjectInfo{}, domain.Invalid
	}
	if in.Kind == "team" && in.Username != nil && *in.Username != "" {
		return SubjectInfo{}, domain.Invalid // вход связывается только с человеком
	}
	user, e := s.loginID(ctx, tx, tenant, in.Username)
	if e != nil {
		return SubjectInfo{}, e
	}
	id := identifier.New()
	if _, e = tx.Exec(ctx, "INSERT INTO responsibility.subjects(tenant_id,subject_id,kind,name,contact,user_id) VALUES($1,$2,$3,$4,$5,$6)", tenant, id, in.Kind, *in.Name, *in.Contact, user); e != nil {
		if uniqueViolation(e) {
			return SubjectInfo{}, domain.Conflict // вход уже связан с другим человеком
		}
		return SubjectInfo{}, e
	}
	return s.SubjectByID(ctx, tx, tenant, id)
}

func (Store) SubjectByID(ctx context.Context, tx pgx.Tx, tenant, id string) (SubjectInfo, error) {
	var out SubjectInfo
	if !identifier.Valid(id) {
		return out, domain.NotFound
	}
	e := tx.QueryRow(ctx, `SELECT s.subject_id::text,s.kind,s.name,s.contact,s.active,u.username,s.revision::text,
EXISTS(SELECT 1 FROM scope.sites x WHERE x.tenant_id=s.tenant_id AND x.fallback_subject_id=s.subject_id),
(SELECT count(*) FROM responsibility.team_members m WHERE m.tenant_id=s.tenant_id AND m.team_id=s.subject_id AND m.valid_to IS NULL)::int,s.origin,s.synced_at,s.directory_login
FROM responsibility.subjects s LEFT JOIN access.users u ON u.tenant_id=s.tenant_id AND u.user_id=s.user_id WHERE s.tenant_id=$1 AND s.subject_id=$2`, tenant, id).Scan(&out.ID, &out.Kind, &out.Name, &out.Contact, &out.Active, &out.Username, &out.Revision, &out.Fallback, &out.Members, &out.Origin, &out.SyncedAt, &out.DirectoryLogin)
	if errors.Is(e, pgx.ErrNoRows) {
		e = domain.NotFound
	}
	return out, e
}

func (Store) Subjects(ctx context.Context, tx pgx.Tx, tenant, kind, after string, inactive bool, limit int) ([]SubjectInfo, error) {
	rows, e := tx.Query(ctx, `SELECT s.subject_id::text,s.kind,s.name,s.contact,s.active,u.username,s.revision::text,
EXISTS(SELECT 1 FROM scope.sites x WHERE x.tenant_id=s.tenant_id AND x.fallback_subject_id=s.subject_id),
(SELECT count(*) FROM responsibility.team_members m WHERE m.tenant_id=s.tenant_id AND m.team_id=s.subject_id AND m.valid_to IS NULL)::int,s.origin,s.synced_at,s.directory_login
FROM responsibility.subjects s LEFT JOIN access.users u ON u.tenant_id=s.tenant_id AND u.user_id=s.user_id
WHERE s.tenant_id=$1 AND ($2='' OR s.kind=$2) AND ($3 OR s.active) AND ($4='' OR s.subject_id>NULLIF($4,'')::uuid) ORDER BY s.subject_id LIMIT $5`, tenant, kind, inactive, after, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []SubjectInfo{}
	for rows.Next() {
		var s SubjectInfo
		if e = rows.Scan(&s.ID, &s.Kind, &s.Name, &s.Contact, &s.Active, &s.Username, &s.Revision, &s.Fallback, &s.Members, &s.Origin, &s.SyncedAt, &s.DirectoryLogin); e != nil {
			return nil, e
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// UpdateSubject меняет имя/контакт/связь со входом при совпадении ревизии.
func (s Store) UpdateSubject(ctx context.Context, tx pgx.Tx, tenant, id, revision string, in SubjectInput) (SubjectInfo, error) {
	if !clean(in.Name, 512) || !clean(in.Contact, 512) || in.Kind != "" {
		return SubjectInfo{}, domain.Invalid
	}
	current, e := s.SubjectByID(ctx, tx, tenant, id)
	if e != nil {
		return current, e
	}
	if !current.Active {
		return current, domain.Conflict
	}
	if current.Origin != "local" && (in.Name != nil || in.Contact != nil) {
		return current, errDirectoryManaged // имя и контакт ведёт каталог; связь со входом — можно
	}
	setLogin := in.Username != nil
	if setLogin && *in.Username != "" && current.Kind != "person" {
		return current, domain.Invalid
	}
	user, e := s.loginID(ctx, tx, tenant, in.Username)
	if e != nil {
		return current, e
	}
	tag, e := tx.Exec(ctx, `UPDATE responsibility.subjects SET name=COALESCE($4,name),contact=COALESCE($5,contact),
user_id=CASE WHEN $6 THEN $7::uuid ELSE user_id END,revision=revision+1 WHERE tenant_id=$1 AND subject_id=$2 AND revision::text=$3`, tenant, id, revision, in.Name, in.Contact, setLogin, user)
	if e != nil {
		if uniqueViolation(e) {
			return current, domain.Conflict
		}
		return current, e
	}
	if tag.RowsAffected() != 1 {
		return current, domain.Revision
	}
	return s.SubjectByID(ctx, tx, tenant, id)
}

// AddMember / RemoveMember — состав команды (интервалы участия).
func (Store) AddMember(ctx context.Context, tx pgx.Tx, tenant, team, person, actor string) error {
	if e := localTeam(ctx, tx, tenant, team); e != nil {
		return e
	}
	var ok bool
	if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM responsibility.subjects WHERE tenant_id=$1 AND subject_id=$2 AND kind='team' AND active)
AND EXISTS(SELECT 1 FROM responsibility.subjects WHERE tenant_id=$1 AND subject_id=$3 AND kind='person' AND active)`, tenant, team, person).Scan(&ok); e != nil {
		return e
	}
	if !ok {
		return domain.NotFound
	}
	if _, e := tx.Exec(ctx, "INSERT INTO responsibility.team_members(tenant_id,team_id,person_id,actor_ref) VALUES($1,$2,$3,$4)", tenant, team, person, actor); e != nil {
		if uniqueViolation(e) {
			return domain.Conflict
		}
		return e
	}
	return nil
}

func (Store) RemoveMember(ctx context.Context, tx pgx.Tx, tenant, team, person string) error {
	if e := localTeam(ctx, tx, tenant, team); e != nil {
		return e
	}
	tag, e := tx.Exec(ctx, "UPDATE responsibility.team_members SET valid_to=now() WHERE tenant_id=$1 AND team_id=$2 AND person_id=$3 AND valid_to IS NULL", tenant, team, person)
	if e == nil && tag.RowsAffected() != 1 {
		e = domain.NotFound
	}
	return e
}

// Transfer — атомарная передача роли на активе: прежний интервал закрывается и новый открывается одним моментом
// (now() транзакции), так что периода без accountable нет. subject=="" снимает необязательную роль. Возвращает false,
// если роль уже у этого субъекта (ничего не меняется).
func (Store) Transfer(ctx context.Context, tx pgx.Tx, tenant, asset, role, subject, reason string, note *string, actor string) (bool, error) {
	if !Roles[role] || subject == "" && role == "accountable" || note != nil && len([]rune(*note)) > 1024 {
		return false, domain.Invalid
	}
	var current *string
	e := tx.QueryRow(ctx, "SELECT subject_id::text FROM responsibility.responsibility_assignments WHERE tenant_id=$1 AND asset_uid=$2 AND role=$3 AND valid_to IS NULL FOR UPDATE", tenant, asset, role).Scan(&current)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return false, e
	}
	if current != nil && *current == subject || current == nil && subject == "" {
		return false, nil
	}
	if subject != "" {
		var ok bool
		if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM responsibility.subjects WHERE tenant_id=$1 AND subject_id=$2 AND active AND ($3<>'custodian' OR kind='person'))", tenant, subject, role).Scan(&ok); e != nil {
			return false, e
		}
		if !ok {
			return false, domain.NotFound // неактивный, чужой или неподходящий субъект
		}
	}
	if current != nil {
		if _, e = tx.Exec(ctx, "UPDATE responsibility.responsibility_assignments SET valid_to=now() WHERE tenant_id=$1 AND asset_uid=$2 AND role=$3 AND valid_to IS NULL", tenant, asset, role); e != nil {
			return false, e
		}
	}
	if subject != "" {
		if _, e = tx.Exec(ctx, "INSERT INTO responsibility.responsibility_assignments(tenant_id,assignment_id,asset_uid,subject_id,role,valid_from,reason_code,actor_ref,note) VALUES($1,$2,$3,$4,$5,now(),$6,$7,$8)", tenant, identifier.New(), asset, subject, role, reason, actor, note); e != nil {
			return false, e
		}
	}
	return true, nil
}

// Assignments — действующие и (history=true) все интервалы назначений актива.
func (Store) Assignments(ctx context.Context, tx pgx.Tx, tenant, asset string, history bool) ([]Assignment, error) {
	rows, e := tx.Query(ctx, `SELECT a.role,a.subject_id::text,s.name,s.kind,a.valid_from,a.valid_to,a.reason_code,a.note,a.actor_ref
FROM responsibility.responsibility_assignments a JOIN responsibility.subjects s ON s.tenant_id=a.tenant_id AND s.subject_id=a.subject_id
WHERE a.tenant_id=$1 AND a.asset_uid=$2 AND ($3 OR a.valid_to IS NULL) ORDER BY a.valid_from DESC,a.role LIMIT 500`, tenant, asset, history)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Assignment{}
	for rows.Next() {
		var a Assignment
		if e = rows.Scan(&a.Role, &a.Subject, &a.Name, &a.Kind, &a.ValidFrom, &a.ValidTo, &a.Reason, &a.Note, &a.Actor); e != nil {
			return nil, e
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AssignmentsMany — действующие назначения активов страницы (C30, пакетное чтение «Моих задач»).
func (Store) AssignmentsMany(ctx context.Context, tx pgx.Tx, tenant string, assets []string) (map[string][]Assignment, error) {
	rows, e := tx.Query(ctx, `SELECT a.asset_uid::text,a.role,a.subject_id::text,s.name,s.kind,a.valid_from,a.valid_to,a.reason_code,a.note,a.actor_ref
FROM responsibility.responsibility_assignments a JOIN responsibility.subjects s ON s.tenant_id=a.tenant_id AND s.subject_id=a.subject_id
WHERE a.tenant_id=$1 AND a.asset_uid=ANY($2::uuid[]) AND a.valid_to IS NULL ORDER BY a.asset_uid,a.valid_from DESC,a.role`, tenant, assets)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := map[string][]Assignment{}
	for rows.Next() {
		var uid string
		var a Assignment
		if e = rows.Scan(&uid, &a.Role, &a.Subject, &a.Name, &a.Kind, &a.ValidFrom, &a.ValidTo, &a.Reason, &a.Note, &a.Actor); e != nil {
			return nil, e
		}
		out[uid] = append(out[uid], a)
	}
	return out, rows.Err()
}

// Deactivate — уход сотрудника/расформирование команды: accountable его активов переходит на резервную команду
// площадки актива, прочие роли закрываются, участие в командах закрывается, субъект становится неактивным.
// Резервную команду площадки деактивировать нельзя (Conflict). Возвращает изменения назначений.
func (s Store) Deactivate(ctx context.Context, tx pgx.Tx, tenant, id, revision, actor string) ([]Change, error) {
	subject, e := s.SubjectByID(ctx, tx, tenant, id)
	if e != nil {
		return nil, e
	}
	if !subject.Active || subject.Fallback || subject.Origin != "local" {
		return nil, domain.Conflict // выбытие субъекта каталога — только из каталога
	}
	if subject.Revision != revision {
		return nil, domain.Revision
	}
	return s.deactivate(ctx, tx, tenant, id, actor)
}

// localTeam — состав команды каталога ведёт каталог.
func localTeam(ctx context.Context, tx pgx.Tx, tenant, team string) error {
	var origin string
	e := tx.QueryRow(ctx, "SELECT origin FROM responsibility.subjects WHERE tenant_id=$1 AND subject_id=$2", tenant, team).Scan(&origin)
	if errors.Is(e, pgx.ErrNoRows) {
		return domain.NotFound
	}
	if e == nil && origin != "local" {
		e = errDirectoryManaged
	}
	return e
}

// deactivate — выбытие: роли переходят резервной команде площадки (accountable) или снимаются, участие закрывается.
func (s Store) deactivate(ctx context.Context, tx pgx.Tx, tenant, id, actor string) ([]Change, error) {
	rows, e := tx.Query(ctx, `SELECT a.asset_uid::text,a.role,x.fallback_subject_id::text FROM responsibility.responsibility_assignments a
JOIN assets.assets t ON t.tenant_id=a.tenant_id AND t.asset_uid=a.asset_uid JOIN scope.sites x ON x.tenant_id=t.tenant_id AND x.site_id=t.site_id
WHERE a.tenant_id=$1 AND a.subject_id=$2 AND a.valid_to IS NULL ORDER BY a.asset_uid,a.role FOR UPDATE OF a`, tenant, id)
	if e != nil {
		return nil, e
	}
	type item struct{ asset, role, fallback string }
	var items []item
	for rows.Next() {
		var it item
		if e = rows.Scan(&it.asset, &it.role, &it.fallback); e != nil {
			rows.Close()
			return nil, e
		}
		items = append(items, it)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return nil, e
	}
	changes := []Change{}
	for _, it := range items {
		next := ""
		if it.role == "accountable" {
			next = it.fallback
		}
		if _, e = s.Transfer(ctx, tx, tenant, it.asset, it.role, next, "SUBJECT_DEACTIVATED", nil, actor); e != nil {
			return nil, e
		}
		changes = append(changes, Change{Asset: it.asset, Role: it.role, Subject: next, Reason: "SUBJECT_DEACTIVATED"})
	}
	if _, e = tx.Exec(ctx, "UPDATE responsibility.team_members SET valid_to=now() WHERE tenant_id=$1 AND (team_id=$2 OR person_id=$2) AND valid_to IS NULL", tenant, id); e != nil {
		return nil, e
	}
	if _, e = tx.Exec(ctx, "UPDATE responsibility.subjects SET active=false,revision=revision+1 WHERE tenant_id=$1 AND subject_id=$2", tenant, id); e != nil {
		return nil, e
	}
	return changes, nil
}

// Worklist — активы рабочего списка пользователя: mine (роль у моего человека), team (accountable/technical у моих
// команд), unassigned (accountable — резервная команда площадки), attention (ответственный неактивен или его вход
// отключён). Курсор — asset_uid.
func (Store) Worklist(ctx context.Context, tx pgx.Tx, tenant, user, scope, after string, limit int) ([]string, error) {
	var rows pgx.Rows
	var e error
	switch scope {
	case "mine":
		rows, e = tx.Query(ctx, `SELECT DISTINCT a.asset_uid::text FROM responsibility.responsibility_assignments a JOIN responsibility.subjects s ON s.tenant_id=a.tenant_id AND s.subject_id=a.subject_id
JOIN assets.assets t ON t.tenant_id=a.tenant_id AND t.asset_uid=a.asset_uid
WHERE a.tenant_id=$1 AND a.valid_to IS NULL AND s.user_id=$2 AND t.merged_into IS NULL AND ($3='' OR a.asset_uid>NULLIF($3,'')::uuid) ORDER BY 1 LIMIT $4`, tenant, user, after, limit)
	case "team":
		rows, e = tx.Query(ctx, `SELECT DISTINCT a.asset_uid::text FROM responsibility.responsibility_assignments a
JOIN responsibility.team_members m ON m.tenant_id=a.tenant_id AND m.team_id=a.subject_id AND m.valid_to IS NULL
JOIN responsibility.subjects p ON p.tenant_id=m.tenant_id AND p.subject_id=m.person_id
JOIN assets.assets t ON t.tenant_id=a.tenant_id AND t.asset_uid=a.asset_uid
WHERE a.tenant_id=$1 AND a.valid_to IS NULL AND p.user_id=$2 AND t.merged_into IS NULL AND ($3='' OR a.asset_uid>NULLIF($3,'')::uuid) ORDER BY 1 LIMIT $4`, tenant, user, after, limit)
	case "unassigned":
		rows, e = tx.Query(ctx, `SELECT a.asset_uid::text FROM responsibility.responsibility_assignments a
JOIN assets.assets t ON t.tenant_id=a.tenant_id AND t.asset_uid=a.asset_uid JOIN scope.sites x ON x.tenant_id=t.tenant_id AND x.site_id=t.site_id
WHERE a.tenant_id=$1 AND a.role='accountable' AND a.valid_to IS NULL AND a.subject_id=x.fallback_subject_id AND t.merged_into IS NULL
AND ($3='' OR a.asset_uid>NULLIF($3,'')::uuid) AND $2<>'' ORDER BY 1 LIMIT $4`, tenant, user, after, limit)
	case "attention":
		rows, e = tx.Query(ctx, `SELECT a.asset_uid::text FROM responsibility.responsibility_assignments a JOIN responsibility.subjects s ON s.tenant_id=a.tenant_id AND s.subject_id=a.subject_id
LEFT JOIN access.users u ON u.tenant_id=s.tenant_id AND u.user_id=s.user_id JOIN assets.assets t ON t.tenant_id=a.tenant_id AND t.asset_uid=a.asset_uid
WHERE a.tenant_id=$1 AND a.role='accountable' AND a.valid_to IS NULL AND t.merged_into IS NULL AND (NOT s.active OR u.enabled IS FALSE)
AND ($3='' OR a.asset_uid>NULLIF($3,'')::uuid) AND $2<>'' ORDER BY 1 LIMIT $4`, tenant, user, after, limit)
	default:
		return nil, domain.Invalid
	}
	if e != nil {
		return nil, e
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}
