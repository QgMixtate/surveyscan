package router

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Перенос организации между ячейками (C37.03, ADR C37-shards): проверка → (пробная копия) → заморозка → копия →
// сверка → переключение каталога; любой сбой до переключения — откат. Строки копируются как есть (UID и история не
// меняются). Подключения — административные (нужно право session_replication_role для копии неизменяемых записей).

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type table struct {
	name    string // schema.table (кавычки)
	columns string // явный список копируемых столбцов (без вычисляемых)
}

// TableCheck — сверка одной таблицы.
type TableCheck struct {
	Table  string `json:"table"`
	Rows   int64  `json:"rows"`
	Digest string `json:"digest"`
}

type MoveReport struct {
	Tenant   string        `json:"tenant_id"`
	From     string        `json:"from_shard"`
	To       string        `json:"to_shard"`
	DryRun   bool          `json:"dry_run"`
	Tables   []TableCheck  `json:"tables"`
	Rows     int64         `json:"rows_copied"`
	Window   time.Duration `json:"fence_window_ns"`
	Epoch    int64         `json:"epoch"`
	Outcome  string        `json:"outcome"` // moved | dry_run_ok | rolled_back
	Problems []string      `json:"problems"`
}

func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// cellLocal — таблицы с tenant_id, принадлежащие ячейке, а не организации (запись о первичной настройке ячейки).
var cellLocal = map[string]bool{`"access"."bootstrap_state"`: true}

// tenantTables — все базовые таблицы с колонкой tenant_id (служебные таблицы без неё не переносятся).
func tenantTables(ctx context.Context, c *pgx.Conn) ([]table, error) {
	rows, e := c.Query(ctx, `SELECT t.table_schema,t.table_name,string_agg(quote_ident(c.column_name),',' ORDER BY c.ordinal_position)
FROM information_schema.tables t JOIN information_schema.columns c ON c.table_schema=t.table_schema AND c.table_name=t.table_name
WHERE t.table_type='BASE TABLE' AND t.table_schema NOT IN ('pg_catalog','information_schema','platform') AND c.is_generated='NEVER'
AND EXISTS(SELECT 1 FROM information_schema.columns k WHERE k.table_schema=t.table_schema AND k.table_name=t.table_name AND k.column_name='tenant_id')
GROUP BY t.table_schema,t.table_name ORDER BY 1,2`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []table
	for rows.Next() {
		var schema, name, cols string
		if e = rows.Scan(&schema, &name, &cols); e != nil {
			return nil, e
		}
		if t := (table{quoteIdent(schema) + "." + quoteIdent(name), cols}); !cellLocal[t.name] {
			out = append(out, t)
		}
	}
	return out, rows.Err()
}

func migrations(ctx context.Context, c *pgx.Conn) ([]string, error) {
	rows, e := c.Query(ctx, "SELECT id::text FROM platform.schema_migrations ORDER BY id")
	if e != nil {
		return nil, e
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

func checks(ctx context.Context, c *pgx.Conn, tables []table, tenant string) ([]TableCheck, error) {
	out := make([]TableCheck, 0, len(tables))
	for _, t := range tables {
		var ck TableCheck
		ck.Table = t.name
		q := fmt.Sprintf(`SELECT count(*),md5(coalesce(string_agg(x::text,E'\n' ORDER BY x::text),'')) FROM (SELECT %s FROM %s WHERE tenant_id='%s') x`, t.columns, t.name, tenant)
		if e := c.QueryRow(ctx, q).Scan(&ck.Rows, &ck.Digest); e != nil {
			return nil, fmt.Errorf("%s: %w", t.name, e)
		}
		out = append(out, ck)
	}
	return out, nil
}

// copyTenant копирует строки организации из src в dst одной транзакцией dst (триггеры неизменяемости и FK
// отключены только в ней: строки уже согласованы в источнике и сверяются после копии).
func copyTenant(ctx context.Context, src, dst *pgx.Conn, tables []table, tenant string) (int64, error) {
	tx, e := dst.Begin(ctx)
	if e != nil {
		return 0, e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SET LOCAL session_replication_role = replica"); e != nil {
		return 0, errors.New("target role cannot copy immutable rows (need session_replication_role)")
	}
	var total int64
	for _, t := range tables {
		pr, pw := io.Pipe()
		errc := make(chan error, 1)
		go func() {
			_, err := src.PgConn().CopyTo(ctx, pw, fmt.Sprintf("COPY (SELECT %s FROM %s WHERE tenant_id='%s') TO STDOUT", t.columns, t.name, tenant))
			pw.CloseWithError(err)
			errc <- err
		}()
		tag, err := tx.Conn().PgConn().CopyFrom(ctx, pr, fmt.Sprintf("COPY %s (%s) FROM STDIN", t.name, t.columns))
		pr.Close()
		if srcErr := <-errc; srcErr != nil {
			return 0, fmt.Errorf("%s: source: %w", t.name, srcErr)
		}
		if err != nil {
			return 0, fmt.Errorf("%s: target: %w", t.name, err)
		}
		total += tag.RowsAffected()
	}
	return total, tx.Commit(ctx)
}

// deleteTenant удаляет строки организации из ячейки (откат копии; только в цели).
func deleteTenant(ctx context.Context, c *pgx.Conn, tables []table, tenant string) error {
	tx, e := c.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SET LOCAL session_replication_role = replica"); e != nil {
		return e
	}
	for _, t := range tables {
		if _, e = tx.Exec(ctx, fmt.Sprintf("DELETE FROM %s WHERE tenant_id='%s'", t.name, tenant)); e != nil {
			return fmt.Errorf("%s: %w", t.name, e)
		}
	}
	return tx.Commit(ctx)
}

func tenantStatus(ctx context.Context, c *pgx.Conn, tenant string) (string, error) {
	var s string
	e := c.QueryRow(ctx, "SELECT status FROM access.tenants WHERE tenant_id=$1", tenant).Scan(&s)
	return s, e
}

func setStatus(ctx context.Context, c *pgx.Conn, tenant, status string) error {
	tag, e := c.Exec(ctx, "UPDATE access.tenants SET status=$2 WHERE tenant_id=$1", tenant, status)
	if e == nil && tag.RowsAffected() != 1 {
		e = errors.New("tenant row missing")
	}
	return e
}

// Move переносит организацию tenant из ячейки src (шард from) в dst (шард to).
func Move(ctx context.Context, cat Catalog, src, dst *pgx.Conn, tenant, from, to string, dryRun bool, actor string) (MoveReport, error) {
	rep := MoveReport{Tenant: tenant, From: from, To: to, DryRun: dryRun, Problems: []string{}}
	if !uuidRe.MatchString(tenant) || from == to {
		return rep, errors.New("invalid tenant or shards")
	}
	// 1. проверка
	p, e := cat.Placement(ctx, tenant)
	if e != nil {
		return rep, e
	}
	if p.Shard != from || p.State != "active" {
		return rep, fmt.Errorf("catalog: tenant is in shard %s (%s), expected active in %s", p.Shard, p.State, from)
	}
	a, e := migrations(ctx, src)
	if e != nil {
		return rep, e
	}
	b, e := migrations(ctx, dst)
	if e != nil {
		return rep, e
	}
	if !slices.Equal(a, b) {
		return rep, errors.New("schema versions of the shards differ: migrate both first")
	}
	tables, e := tenantTables(ctx, src)
	if e != nil {
		return rep, e
	}
	var present bool
	if e = dst.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM access.tenants WHERE tenant_id=$1)", tenant).Scan(&present); e != nil {
		return rep, e
	}
	if present {
		return rep, errors.New("target shard already holds this tenant")
	}
	if dryRun {
		// 2. пробная копия без заморозки: оценка окна и проверка прав; затем удаляется
		started := time.Now()
		if rep.Rows, e = copyTenant(ctx, src, dst, tables, tenant); e != nil {
			return rep, e
		}
		rep.Window = time.Since(started)
		e = deleteTenant(context.WithoutCancel(ctx), dst, tables, tenant)
		rep.Outcome = "dry_run_ok"
		return rep, e
	}
	// 3. заморозка
	previous, e := tenantStatus(ctx, src, tenant)
	if e != nil {
		return rep, e
	}
	if e = cat.Fence(ctx, tenant, actor); e != nil {
		return rep, e
	}
	started := time.Now()
	rollback := func(cause error) (MoveReport, error) {
		bg := context.WithoutCancel(ctx)
		rep.Problems = append(rep.Problems, cause.Error())
		if err := deleteTenant(bg, dst, tables, tenant); err != nil {
			rep.Problems = append(rep.Problems, "rollback delete: "+err.Error())
		}
		if err := setStatus(bg, src, tenant, previous); err != nil {
			rep.Problems = append(rep.Problems, "rollback status: "+err.Error())
		}
		if err := cat.Unfence(bg, tenant, actor); err != nil {
			rep.Problems = append(rep.Problems, "rollback catalog: "+err.Error())
		}
		rep.Outcome = "rolled_back"
		return rep, cause
	}
	if e = setStatus(ctx, src, tenant, "disabled"); e != nil {
		return rollback(e)
	}
	// 4. копия
	if rep.Rows, e = copyTenant(ctx, src, dst, tables, tenant); e != nil {
		return rollback(e)
	}
	// 5. сверка (статус организации в цели — тот же disabled, что в источнике под заморозкой)
	left, e := checks(ctx, src, tables, tenant)
	if e != nil {
		return rollback(e)
	}
	right, e := checks(ctx, dst, tables, tenant)
	if e != nil {
		return rollback(e)
	}
	for i := range left {
		if left[i] != right[i] {
			return rollback(fmt.Errorf("verification mismatch in %s: %d/%s vs %d/%s", left[i].Table, left[i].Rows, left[i].Digest, right[i].Rows, right[i].Digest))
		}
	}
	rep.Tables = left
	// 6. переключение
	if e = setStatus(ctx, dst, tenant, previous); e != nil {
		return rollback(e)
	}
	if rep.Epoch, e = cat.Cutover(ctx, tenant, from, to, actor); e != nil {
		_ = setStatus(context.WithoutCancel(ctx), dst, tenant, "disabled")
		return rollback(e)
	}
	rep.Window = time.Since(started)
	rep.Outcome = "moved"
	return rep, nil
}
