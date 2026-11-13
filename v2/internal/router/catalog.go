// Package router — маршрутизатор ячеек (шардов) и каталог организаций (C37, ADR decisions/C37-shards.md).
// Каталог — отдельная БД; ячейки — обычные центры SurveyScan. Маршрутизация закрыта при отказе: нет маршрута по
// умолчанию.
package router

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const catalogSchema = `
CREATE SCHEMA IF NOT EXISTS catalog;
CREATE TABLE IF NOT EXISTS catalog.shards (
 shard_id text PRIMARY KEY CHECK (shard_id ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
 region text NOT NULL CHECK (length(region) BETWEEN 1 AND 64),
 state text NOT NULL DEFAULT 'active' CHECK (state IN ('active','draining'))
);
CREATE TABLE IF NOT EXISTS catalog.tenants (
 tenant_id uuid PRIMARY KEY,
 shard_id text NOT NULL REFERENCES catalog.shards(shard_id),
 epoch bigint NOT NULL DEFAULT 1 CHECK (epoch >= 1),
 state text NOT NULL DEFAULT 'active' CHECK (state IN ('active','migrating')),
 home_region text NOT NULL,
 dr_region text,
 residency text,
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS catalog.logins (
 username text PRIMARY KEY,
 tenant_id uuid NOT NULL,
 shard_id text NOT NULL REFERENCES catalog.shards(shard_id),
 conflict boolean NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS catalog.events (
 event_id bigserial PRIMARY KEY,
 at timestamptz NOT NULL DEFAULT now(),
 actor text NOT NULL,
 action text NOT NULL,
 tenant_id uuid,
 detail jsonb NOT NULL DEFAULT '{}'::jsonb
);`

var (
	ErrUnknown   = errors.New("tenant or login is not in the catalog")
	ErrMigrating = errors.New("tenant is being migrated")
	ErrConflict  = errors.New("login exists in more than one shard")
)

type Placement struct {
	Tenant, Shard string
	Epoch         int64
	State         string
}

type Catalog struct{ Pool *pgxpool.Pool }

func (c Catalog) Init(ctx context.Context) error {
	_, e := c.Pool.Exec(ctx, catalogSchema)
	return e
}

func record(ctx context.Context, tx pgx.Tx, actor, action string, tenant *string, detail string) error {
	_, e := tx.Exec(ctx, "INSERT INTO catalog.events(actor,action,tenant_id,detail) VALUES($1,$2,$3,$4::jsonb)", actor, action, tenant, detail)
	return e
}

// AddShard регистрирует ячейку.
func (c Catalog) AddShard(ctx context.Context, shard, region, actor string) error {
	tx, e := c.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "INSERT INTO catalog.shards(shard_id,region) VALUES($1,$2) ON CONFLICT(shard_id) DO UPDATE SET region=excluded.region", shard, region); e != nil {
		return e
	}
	if e = record(ctx, tx, actor, "shard.registered", nil, `{"shard":"`+shard+`"}`); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

// Place — первичное размещение организации в шарде (организация уже создана в ячейке).
func (c Catalog) Place(ctx context.Context, tenant, shard, home string, dr, residency *string, actor string) error {
	tx, e := c.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "INSERT INTO catalog.tenants(tenant_id,shard_id,home_region,dr_region,residency) VALUES($1,$2,$3,$4,$5)", tenant, shard, home, dr, residency); e != nil {
		return e
	}
	if e = record(ctx, tx, actor, "tenant.placed", &tenant, `{"shard":"`+shard+`"}`); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

func (c Catalog) Placement(ctx context.Context, tenant string) (Placement, error) {
	p := Placement{Tenant: tenant}
	e := c.Pool.QueryRow(ctx, "SELECT shard_id,epoch,state FROM catalog.tenants WHERE tenant_id=$1", tenant).Scan(&p.Shard, &p.Epoch, &p.State)
	if errors.Is(e, pgx.ErrNoRows) {
		return p, ErrUnknown
	}
	return p, e
}

// Login — организация и шард по логину (вход).
func (c Catalog) Login(ctx context.Context, username string) (Placement, error) {
	var tenant string
	var conflict bool
	e := c.Pool.QueryRow(ctx, "SELECT tenant_id::text,conflict FROM catalog.logins WHERE username=$1", username).Scan(&tenant, &conflict)
	if errors.Is(e, pgx.ErrNoRows) {
		return Placement{}, ErrUnknown
	}
	if e != nil {
		return Placement{}, e
	}
	if conflict {
		return Placement{}, ErrConflict
	}
	return c.Placement(ctx, tenant)
}

// SetState меняет состояние организации (заморозка переноса) и возвращает новую запись.
func (c Catalog) setState(ctx context.Context, tx pgx.Tx, tenant, from, to, actor string) error {
	tag, e := tx.Exec(ctx, "UPDATE catalog.tenants SET state=$3,updated_at=now() WHERE tenant_id=$1 AND state=$2", tenant, from, to)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return errors.New("catalog state changed concurrently")
	}
	return record(ctx, tx, actor, "tenant.state."+to, &tenant, "{}")
}

// Fence — организация в состоянии переноса: маршрутизатор перестаёт пропускать её запросы.
func (c Catalog) Fence(ctx context.Context, tenant, actor string) error {
	return c.tx(ctx, func(tx pgx.Tx) error { return c.setState(ctx, tx, tenant, "active", "migrating", actor) })
}

// Unfence — откат переноса: организация снова активна в прежнем шарде.
func (c Catalog) Unfence(ctx context.Context, tenant, actor string) error {
	return c.tx(ctx, func(tx pgx.Tx) error { return c.setState(ctx, tx, tenant, "migrating", "active", actor) })
}

// Cutover — переключение на новый шард: shard, epoch+1, active и перенос логинов организации — одной транзакцией.
func (c Catalog) Cutover(ctx context.Context, tenant, from, to, actor string) (int64, error) {
	var epoch int64
	e := c.tx(ctx, func(tx pgx.Tx) error {
		if e := tx.QueryRow(ctx, "UPDATE catalog.tenants SET shard_id=$3,epoch=epoch+1,state='active',updated_at=now() WHERE tenant_id=$1 AND shard_id=$2 AND state='migrating' RETURNING epoch", tenant, from, to).Scan(&epoch); e != nil {
			return errors.New("catalog cutover precondition failed")
		}
		if _, e := tx.Exec(ctx, "UPDATE catalog.logins SET shard_id=$2 WHERE tenant_id=$1", tenant, to); e != nil {
			return e
		}
		return record(ctx, tx, actor, "tenant.cutover", &tenant, `{"from":"`+from+`","to":"`+to+`"}`)
	})
	return epoch, e
}

func (c Catalog) tx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, e := c.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if e = fn(tx); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

// LoginRow — логин из ячейки для синхронизации.
type LoginRow struct{ Username, Tenant string }

// SyncLogins заменяет индекс логинов по данным ячеек. Шард логина — из каталога (домашний шард организации), поэтому
// отключённая копия организации в прежнем шарде после переноса ничего не меняет. Логин, принадлежащий разным
// организациям, помечается конфликтом — вход по нему закрыт до разбора. Логины неразмещённых организаций пропускаются.
func (c Catalog) SyncLogins(ctx context.Context, rows []LoginRow, actor string) (int, int, error) {
	tenants := map[string]map[string]bool{}
	for _, r := range rows {
		if tenants[r.Username] == nil {
			tenants[r.Username] = map[string]bool{}
		}
		tenants[r.Username][r.Tenant] = true
	}
	n, conflicts := 0, 0
	e := c.tx(ctx, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, "DELETE FROM catalog.logins"); e != nil {
			return e
		}
		for name, set := range tenants {
			conflict := len(set) > 1
			for tenant := range set {
				var shard string
				e := tx.QueryRow(ctx, "SELECT shard_id FROM catalog.tenants WHERE tenant_id=$1", tenant).Scan(&shard)
				if errors.Is(e, pgx.ErrNoRows) {
					continue
				}
				if e != nil {
					return e
				}
				if _, e = tx.Exec(ctx, "INSERT INTO catalog.logins(username,tenant_id,shard_id,conflict) VALUES($1,$2,$3,$4) ON CONFLICT(username) DO UPDATE SET conflict=true", name, tenant, shard, conflict); e != nil {
					return e
				}
				if !conflict {
					n++
				}
				break
			}
			if conflict {
				conflicts++
			}
		}
		return record(ctx, tx, actor, "logins.synced", nil, "{}")
	})
	return n, conflicts, e
}
