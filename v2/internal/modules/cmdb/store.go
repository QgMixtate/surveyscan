// Package cmdb — бизнес-сервисы (CI без актива) и типизированные связи между CI (C26, ADR C26-cmdb-model).
// Модуль пишет только в схему cmdb; активы читаются через FK и проверки существования в том же тенанте.
package cmdb

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type Store struct{}

var criticalities = map[string]bool{"unknown": true, "low": true, "medium": true, "high": true, "critical": true}

type Service struct {
	UID         string     `json:"service_uid"`
	Name        string     `json:"name"`
	Description *string    `json:"description"`
	Criticality string     `json:"criticality"`
	Revision    string     `json:"revision"`
	CreatedAt   time.Time  `json:"created_at"`
	RetiredAt   *time.Time `json:"retired_at"`
}

type ServiceInput struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
	Criticality *string `json:"criticality,omitempty"`
}

func validService(in ServiceInput, create bool) bool {
	if create && in.Name == nil {
		return false
	}
	if in.Name != nil {
		n := strings.TrimSpace(*in.Name)
		if n == "" || len([]rune(n)) > 256 {
			return false
		}
		*in.Name = n
	}
	if in.Description != nil && len([]rune(*in.Description)) > 4096 {
		return false
	}
	return in.Criticality == nil || criticalities[*in.Criticality]
}

func uniqueViolation(e error) bool {
	var pg *pgconn.PgError
	return errors.As(e, &pg) && pg.Code == "23505"
}

func (Store) change(ctx context.Context, tx pgx.Tx, tenant, objectType, object, action, actor string, detail any) error {
	raw, e := json.Marshal(detail)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, "INSERT INTO cmdb.changes(tenant_id,change_id,object_type,object_id,action,detail,actor_ref) VALUES($1,$2,$3,$4,$5,$6,$7)", tenant, identifier.New(), objectType, object, action, raw, actor)
	return e
}

func (s Store) CreateService(ctx context.Context, tx pgx.Tx, tenant, actor string, in ServiceInput) (Service, error) {
	if !validService(in, true) {
		return Service{}, domain.Invalid
	}
	criticality := "unknown"
	if in.Criticality != nil {
		criticality = *in.Criticality
	}
	uid := identifier.New()
	if _, e := tx.Exec(ctx, "INSERT INTO cmdb.services(tenant_id,service_uid,name,description,criticality) VALUES($1,$2,$3,$4,$5)", tenant, uid, *in.Name, in.Description, criticality); e != nil {
		if uniqueViolation(e) {
			return Service{}, domain.Conflict
		}
		return Service{}, e
	}
	if e := s.change(ctx, tx, tenant, "service", uid, "created", actor, in); e != nil {
		return Service{}, e
	}
	return s.Service(ctx, tx, tenant, uid)
}

func (Store) Service(ctx context.Context, tx pgx.Tx, tenant, uid string) (Service, error) {
	var out Service
	if !identifier.Valid(uid) {
		return out, domain.NotFound
	}
	e := tx.QueryRow(ctx, "SELECT service_uid::text,name,description,criticality,revision::text,created_at,retired_at FROM cmdb.services WHERE tenant_id=$1 AND service_uid=$2", tenant, uid).Scan(&out.UID, &out.Name, &out.Description, &out.Criticality, &out.Revision, &out.CreatedAt, &out.RetiredAt)
	if errors.Is(e, pgx.ErrNoRows) {
		e = domain.NotFound
	}
	return out, e
}

// UpdateService — оптимистичная конкурентность: изменение только при совпадении ревизии.
func (s Store) UpdateService(ctx context.Context, tx pgx.Tx, tenant, uid, revision, actor string, in ServiceInput, retire bool) (Service, error) {
	if !validService(in, false) {
		return Service{}, domain.Invalid
	}
	current, e := s.Service(ctx, tx, tenant, uid)
	if e != nil {
		return current, e
	}
	if current.RetiredAt != nil {
		return current, domain.Conflict
	}
	tag, e := tx.Exec(ctx, `UPDATE cmdb.services SET name=COALESCE($4,name),description=COALESCE($5,description),criticality=COALESCE($6,criticality),
retired_at=CASE WHEN $7 THEN now() ELSE retired_at END,revision=revision+1 WHERE tenant_id=$1 AND service_uid=$2 AND revision::text=$3`, tenant, uid, revision, in.Name, in.Description, in.Criticality, retire)
	if e != nil {
		if uniqueViolation(e) {
			return current, domain.Conflict
		}
		return current, e
	}
	if tag.RowsAffected() != 1 {
		return current, domain.Revision
	}
	action := "updated"
	if retire {
		action = "retired"
		// связи выведенного сервиса закрываются вместе с ним
		if _, e = tx.Exec(ctx, "UPDATE cmdb.relations SET valid_to=now() WHERE tenant_id=$1 AND valid_to IS NULL AND (from_service_uid=$2 OR to_service_uid=$2)", tenant, uid); e != nil {
			return current, e
		}
	}
	if e = s.change(ctx, tx, tenant, "service", uid, action, actor, in); e != nil {
		return current, e
	}
	return s.Service(ctx, tx, tenant, uid)
}

func (Store) Services(ctx context.Context, tx pgx.Tx, tenant, after string, limit int, retired bool) ([]Service, error) {
	rows, e := tx.Query(ctx, `SELECT service_uid::text,name,description,criticality,revision::text,created_at,retired_at FROM cmdb.services
WHERE tenant_id=$1 AND ($2 OR retired_at IS NULL) AND ($3='' OR service_uid>NULLIF($3,'')::uuid) ORDER BY service_uid LIMIT $4`, tenant, retired, after, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Service{}
	for rows.Next() {
		var s Service
		if e = rows.Scan(&s.UID, &s.Name, &s.Description, &s.Criticality, &s.Revision, &s.CreatedAt, &s.RetiredAt); e != nil {
			return nil, e
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// End — конец связи: актив или сервис.
type End struct {
	Kind string `json:"kind"` // asset | service
	ID   string `json:"id"`
}

type Relation struct {
	ID         string     `json:"relation_id"`
	Type       string     `json:"relation_type"`
	From       End        `json:"from"`
	To         End        `json:"to"`
	Origin     string     `json:"origin"`
	Confidence string     `json:"confidence"`
	Note       *string    `json:"note"`
	ValidFrom  time.Time  `json:"valid_from"`
	ValidTo    *time.Time `json:"valid_to"`
	Actor      string     `json:"actor_ref"`
}

// Допустимые сочетания концов по типу связи (ADR C26.01).
var allowed = map[string]map[[2]string]bool{
	"runs_on":      {{"service", "asset"}: true},
	"uses":         {{"service", "service"}: true, {"service", "asset"}: true},
	"depends_on":   {{"service", "service"}: true},
	"hosts":        {{"asset", "asset"}: true},
	"connected_to": {{"asset", "asset"}: true},
}

type RelationInput struct {
	Type       string  `json:"relation_type"`
	From       End     `json:"from"`
	To         End     `json:"to"`
	Confidence string  `json:"confidence,omitempty"`
	Note       *string `json:"note,omitempty"`
}

func ends(e End) (asset, service *string) {
	id := e.ID
	if e.Kind == "asset" {
		return &id, nil
	}
	return nil, &id
}

// CreateRelation — ручная связь. Концы обязаны существовать в тенанте (FK по tenant_id; актив — не слитый,
// сервис — не выведенный); повтор активной связи того же типа между теми же концами — конфликт.
func (s Store) CreateRelation(ctx context.Context, tx pgx.Tx, tenant, actor string, in RelationInput) (Relation, error) {
	if !allowed[in.Type][[2]string{in.From.Kind, in.To.Kind}] || !identifier.Valid(in.From.ID) || !identifier.Valid(in.To.ID) || in.From == in.To || in.Note != nil && len([]rune(*in.Note)) > 1024 {
		return Relation{}, domain.Invalid
	}
	if in.Confidence == "" {
		in.Confidence = "confirmed"
	}
	if in.Confidence != "confirmed" && in.Confidence != "probable" && in.Confidence != "weak" {
		return Relation{}, domain.Invalid
	}
	for _, end := range []End{in.From, in.To} {
		var ok bool
		var e error
		if end.Kind == "asset" {
			e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM assets.assets WHERE tenant_id=$1 AND asset_uid=$2 AND merged_into IS NULL)", tenant, end.ID).Scan(&ok)
		} else {
			e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM cmdb.services WHERE tenant_id=$1 AND service_uid=$2 AND retired_at IS NULL)", tenant, end.ID).Scan(&ok)
		}
		if e != nil {
			return Relation{}, e
		}
		if !ok {
			return Relation{}, domain.NotFound
		}
	}
	id := identifier.New()
	fa, fs := ends(in.From)
	ta, ts := ends(in.To)
	if _, e := tx.Exec(ctx, `INSERT INTO cmdb.relations(tenant_id,relation_id,relation_type,from_asset_uid,from_service_uid,to_asset_uid,to_service_uid,origin,confidence,note,actor_ref)
VALUES($1,$2,$3,$4,$5,$6,$7,'manual',$8,$9,$10)`, tenant, id, in.Type, fa, fs, ta, ts, in.Confidence, in.Note, actor); e != nil {
		if uniqueViolation(e) {
			return Relation{}, domain.Conflict
		}
		return Relation{}, e
	}
	if e := s.change(ctx, tx, tenant, "relation", id, "created", actor, in); e != nil {
		return Relation{}, e
	}
	return s.Relation(ctx, tx, tenant, id)
}

func scanRelation(row pgx.Row) (Relation, error) {
	var r Relation
	var fa, fs, ta, ts *string
	if e := row.Scan(&r.ID, &r.Type, &fa, &fs, &ta, &ts, &r.Origin, &r.Confidence, &r.Note, &r.ValidFrom, &r.ValidTo, &r.Actor); e != nil {
		return r, e
	}
	r.From, r.To = end(fa, fs), end(ta, ts)
	return r, nil
}

func end(asset, service *string) End {
	if asset != nil {
		return End{"asset", *asset}
	}
	return End{"service", *service}
}

func (Store) Relation(ctx context.Context, tx pgx.Tx, tenant, id string) (Relation, error) {
	if !identifier.Valid(id) {
		return Relation{}, domain.NotFound
	}
	r, e := scanRelation(tx.QueryRow(ctx, "SELECT relation_id::text,relation_type,from_asset_uid::text,from_service_uid::text,to_asset_uid::text,to_service_uid::text,origin,confidence,note,valid_from,valid_to,actor_ref FROM cmdb.relations WHERE tenant_id=$1 AND relation_id=$2", tenant, id))
	if errors.Is(e, pgx.ErrNoRows) {
		e = domain.NotFound
	}
	return r, e
}

// RetireRelation закрывает связь (история сохраняется: valid_to + запись в cmdb.changes).
func (s Store) RetireRelation(ctx context.Context, tx pgx.Tx, tenant, id, actor string) (Relation, error) {
	if !identifier.Valid(id) {
		return Relation{}, domain.NotFound
	}
	tag, e := tx.Exec(ctx, "UPDATE cmdb.relations SET valid_to=now() WHERE tenant_id=$1 AND relation_id=$2 AND valid_to IS NULL", tenant, id)
	if e != nil {
		return Relation{}, e
	}
	if tag.RowsAffected() != 1 {
		if _, e = s.Relation(ctx, tx, tenant, id); e != nil {
			return Relation{}, e
		}
		return Relation{}, domain.Conflict // уже закрыта
	}
	if e = s.change(ctx, tx, tenant, "relation", id, "retired", actor, nil); e != nil {
		return Relation{}, e
	}
	return s.Relation(ctx, tx, tenant, id)
}

// RelationsOf — действующие связи, где CI является любым концом (до 500).
func (Store) RelationsOf(ctx context.Context, tx pgx.Tx, tenant string, ci End) ([]Relation, error) {
	var rows pgx.Rows
	var e error
	if ci.Kind == "service" {
		rows, e = tx.Query(ctx, "SELECT relation_id::text,relation_type,from_asset_uid::text,from_service_uid::text,to_asset_uid::text,to_service_uid::text,origin,confidence,note,valid_from,valid_to,actor_ref FROM cmdb.relations WHERE tenant_id=$1 AND valid_to IS NULL AND (from_service_uid=$2 OR to_service_uid=$2) ORDER BY relation_type,valid_from,relation_id LIMIT 500", tenant, ci.ID)
	} else {
		rows, e = tx.Query(ctx, "SELECT relation_id::text,relation_type,from_asset_uid::text,from_service_uid::text,to_asset_uid::text,to_service_uid::text,origin,confidence,note,valid_from,valid_to,actor_ref FROM cmdb.relations WHERE tenant_id=$1 AND valid_to IS NULL AND (from_asset_uid=$2 OR to_asset_uid=$2) ORDER BY relation_type,valid_from,relation_id LIMIT 500", tenant, ci.ID)
	}
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Relation{}
	for rows.Next() {
		r, e := scanRelation(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RetargetAsset переносит действующие связи поглощённого актива на канонический (C25.03 + C26): связь, которая
// после переноса совпала бы с уже существующей или стала бы петлёй, закрывается; перенос — в истории.
func (s Store) RetargetAsset(ctx context.Context, tx pgx.Tx, tenant, from, to, actor string) (int, error) {
	rows, e := tx.Query(ctx, "SELECT relation_id::text,relation_type,from_asset_uid::text,from_service_uid::text,to_asset_uid::text,to_service_uid::text,origin,confidence,note,valid_from,valid_to,actor_ref FROM cmdb.relations WHERE tenant_id=$1 AND valid_to IS NULL AND (from_asset_uid=$2 OR to_asset_uid=$2) FOR UPDATE", tenant, from)
	if e != nil {
		return 0, e
	}
	var list []Relation
	for rows.Next() {
		r, e := scanRelation(rows)
		if e != nil {
			rows.Close()
			return 0, e
		}
		list = append(list, r)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return 0, e
	}
	moved := 0
	for _, r := range list {
		if _, e = tx.Exec(ctx, "UPDATE cmdb.relations SET valid_to=now() WHERE tenant_id=$1 AND relation_id=$2", tenant, r.ID); e != nil {
			return moved, e
		}
		next := r
		if next.From.Kind == "asset" && next.From.ID == from {
			next.From.ID = to
		}
		if next.To.Kind == "asset" && next.To.ID == from {
			next.To.ID = to
		}
		detail := map[string]string{"from_asset_uid": from, "to_asset_uid": to}
		if next.From == next.To {
			detail["result"] = "retired_loop"
		} else {
			fa, fs := ends(next.From)
			ta, ts := ends(next.To)
			id := identifier.New()
			tag, e := tx.Exec(ctx, `INSERT INTO cmdb.relations(tenant_id,relation_id,relation_type,from_asset_uid,from_service_uid,to_asset_uid,to_service_uid,origin,confidence,note,actor_ref)
SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11 WHERE NOT EXISTS(SELECT 1 FROM cmdb.relations WHERE tenant_id=$1 AND valid_to IS NULL AND relation_type=$3
AND COALESCE(from_asset_uid,from_service_uid)=COALESCE($4::uuid,$5::uuid) AND COALESCE(to_asset_uid,to_service_uid)=COALESCE($6::uuid,$7::uuid))`, tenant, id, r.Type, fa, fs, ta, ts, r.Origin, r.Confidence, r.Note, actor)
			if e != nil {
				return moved, e
			}
			if tag.RowsAffected() == 1 {
				detail["new_relation_id"], moved = id, moved+1
			} else {
				detail["result"] = "retired_duplicate"
			}
		}
		if e = s.change(ctx, tx, tenant, "relation", r.ID, "retargeted", actor, detail); e != nil {
			return moved, e
		}
	}
	return moved, nil
}
