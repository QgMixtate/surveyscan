// Package migrate applies a checksum-verified, forward-only schema under a PG advisory lock.
package migrate

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

type Migration struct{ ID, Owner, SQL string }

var ErrDrift = errors.New("migration history differs from this binary")

func FromFS(owner string, files fs.FS) ([]Migration, error) {
	paths, err := fs.Glob(files, "schema/*.sql")
	if err != nil {
		return nil, err
	}
	result := make([]Migration, 0, len(paths))
	for _, path := range paths {
		b, err := fs.ReadFile(files, path)
		if err != nil {
			return nil, err
		}
		result = append(result, Migration{ID: strings.TrimSuffix(strings.TrimPrefix(path, "schema/"), ".sql"), Owner: owner, SQL: string(b)})
	}
	return result, nil
}
func checksum(m Migration) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(m.SQL))) }
func ordered(ms []Migration) ([]Migration, error) {
	out := append([]Migration(nil), ms...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	for i, m := range out {
		if m.ID == "" || m.Owner == "" || strings.TrimSpace(m.SQL) == "" {
			return nil, errors.New("invalid migration")
		}
		if i > 0 && out[i-1].ID == m.ID {
			return nil, errors.New("duplicate migration ID")
		}
	}
	if len(out) == 0 {
		return nil, errors.New("empty migration catalog")
	}
	return out, nil
}

type queryer interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func verify(ctx context.Context, q queryer, ms []Migration, allowPending bool) (map[string]bool, error) {
	rows, err := q.Query(ctx, "SELECT id, owner, sha256 FROM platform.schema_migrations ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	expected := map[string]Migration{}
	for _, m := range ms {
		expected[m.ID] = m
	}
	applied := map[string]bool{}
	for rows.Next() {
		var id, owner, hash string
		if err := rows.Scan(&id, &owner, &hash); err != nil {
			return nil, err
		}
		m, ok := expected[id]
		if !ok || m.Owner != owner || checksum(m) != hash {
			return nil, ErrDrift
		}
		applied[id] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	pending := false
	for _, m := range ms {
		if !applied[m.ID] {
			pending = true
		} else if pending {
			return nil, ErrDrift
		}
	}
	if !allowPending && len(applied) != len(ms) {
		return nil, ErrDrift
	}
	return applied, nil
}

func Apply(ctx context.Context, conn *pgx.Conn, ms []Migration) (int, error) {
	catalog, err := ordered(ms)
	if err != nil {
		return 0, err
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(context.Background())
	// Acquire before creating the metadata schema, so concurrent initial bootstraps serialize.
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(734933405)"); err != nil {
		return 0, err
	}
	if _, err = tx.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS platform;
 CREATE TABLE IF NOT EXISTS platform.schema_migrations (
 id text PRIMARY KEY, owner text NOT NULL, sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'), applied_at timestamptz NOT NULL DEFAULT now());`); err != nil {
		return 0, err
	}
	applied, err := verify(ctx, tx, catalog, true)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, m := range catalog {
		if applied[m.ID] {
			continue
		}
		if _, err = tx.Exec(ctx, m.SQL); err != nil {
			return 0, fmt.Errorf("migration %s: %w", m.ID, err)
		}
		if _, err = tx.Exec(ctx, "INSERT INTO platform.schema_migrations(id,owner,sha256) VALUES($1,$2,$3)", m.ID, m.Owner, checksum(m)); err != nil {
			return 0, err
		}
		count++
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, err
	}
	return count, nil
}
func Check(ctx context.Context, conn *pgx.Conn, ms []Migration) error {
	catalog, err := ordered(ms)
	if err != nil {
		return err
	}
	_, err = verify(ctx, conn, catalog, false)
	return err
}
