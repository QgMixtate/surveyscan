package sources

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
)

// C51.03: учётки сбора — только описание (название, тип, логин); секрет хранится в хранилище секретов центра.

type CollectCredential struct {
	ID            string    `json:"credential_id"`
	Name          string    `json:"name"`
	Kind          string    `json:"kind"`
	Username      string    `json:"username"`
	Active        bool      `json:"active"`
	Revision      string    `json:"revision"`
	SecretChanged time.Time `json:"secret_changed_at"`
	Targets       int       `json:"targets"`
}

func validKind(k string) bool { return k == "ssh" || k == "winrm" || k == "snmp" }

func cleanText(s string, max int) (string, bool) {
	s = strings.TrimSpace(s)
	return s, s != "" && len([]rune(s)) <= max && !strings.ContainsAny(s, "\x00\r\n")
}

// CredentialSecretKey — имя секрета учётки в хранилище секретов.
func CredentialSecretKey(id string) string { return "collect-" + id }

func (Store) CreateCredential(ctx context.Context, tx pgx.Tx, tenant, id, name, kind, username string) (CollectCredential, error) {
	n, ok1 := cleanText(name, 128)
	u, ok2 := cleanText(username, 256)
	if !ok1 || !ok2 || !validKind(kind) || !identifier.Valid(id) {
		return CollectCredential{}, domain.Invalid
	}
	if _, e := tx.Exec(ctx, "INSERT INTO sources.collect_credentials(tenant_id,credential_id,name,kind,username) VALUES($1,$2,$3,$4,$5)", tenant, id, n, kind, u); e != nil {
		return CollectCredential{}, discoveryConflict(e)
	}
	return (Store{}).Credential(ctx, tx, tenant, id)
}

// PatchCredential меняет описание; secretChanged — секрет перезаписан (отметка времени смены).
func (Store) PatchCredential(ctx context.Context, tx pgx.Tx, tenant, id, revision string, name, username *string, active *bool, secretChanged bool) (CollectCredential, error) {
	if !identifier.Valid(id) {
		return CollectCredential{}, domain.NotFound
	}
	if name != nil {
		n, ok := cleanText(*name, 128)
		if !ok {
			return CollectCredential{}, domain.Invalid
		}
		name = &n
	}
	if username != nil {
		u, ok := cleanText(*username, 256)
		if !ok {
			return CollectCredential{}, domain.Invalid
		}
		username = &u
	}
	tag, e := tx.Exec(ctx, `UPDATE sources.collect_credentials SET name=COALESCE($4,name),username=COALESCE($5,username),active=COALESCE($6,active),
secret_changed_at=CASE WHEN $7 THEN now() ELSE secret_changed_at END,revision=revision+1 WHERE tenant_id=$1 AND credential_id=$2 AND revision::text=$3`, tenant, id, revision, name, username, active, secretChanged)
	if e != nil {
		return CollectCredential{}, discoveryConflict(e)
	}
	if tag.RowsAffected() == 0 {
		if _, e = (Store{}).Credential(ctx, tx, tenant, id); e != nil {
			return CollectCredential{}, e
		}
		return CollectCredential{}, domain.Revision
	}
	return (Store{}).Credential(ctx, tx, tenant, id)
}

func (Store) Credential(ctx context.Context, tx pgx.Tx, tenant, id string) (CollectCredential, error) {
	var c CollectCredential
	if !identifier.Valid(id) {
		return c, domain.NotFound
	}
	e := tx.QueryRow(ctx, `SELECT c.credential_id::text,c.name,c.kind,c.username,c.active,c.revision::text,c.secret_changed_at,
(SELECT count(*) FROM sources.remote_targets t WHERE t.tenant_id=c.tenant_id AND t.credential_id=c.credential_id AND t.state<>'disabled')::int
FROM sources.collect_credentials c WHERE c.tenant_id=$1 AND c.credential_id=$2`, tenant, id).Scan(&c.ID, &c.Name, &c.Kind, &c.Username, &c.Active, &c.Revision, &c.SecretChanged, &c.Targets)
	if errors.Is(e, pgx.ErrNoRows) {
		return c, domain.NotFound
	}
	return c, e
}

func (Store) Credentials(ctx context.Context, tx pgx.Tx, tenant string) ([]CollectCredential, error) {
	rows, e := tx.Query(ctx, `SELECT c.credential_id::text,c.name,c.kind,c.username,c.active,c.revision::text,c.secret_changed_at,
(SELECT count(*) FROM sources.remote_targets t WHERE t.tenant_id=c.tenant_id AND t.credential_id=c.credential_id AND t.state<>'disabled')::int
FROM sources.collect_credentials c WHERE c.tenant_id=$1 ORDER BY c.active DESC, lower(c.name), c.credential_id`, tenant)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []CollectCredential{}
	for rows.Next() {
		var c CollectCredential
		if e = rows.Scan(&c.ID, &c.Name, &c.Kind, &c.Username, &c.Active, &c.Revision, &c.SecretChanged, &c.Targets); e != nil {
			return nil, e
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
