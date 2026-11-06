//go:build integration

package app_test

import (
	"errors"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/migrate"
)

func TestC15AppendOnlyUpgradePreservesLegacyEvidence(t *testing.T) {
	ctx, c, catalog := database(t)
	current := []migrate.Migration{}
	for _, m := range catalog {
		if m.ID <= "0033_records12" {
			current = append(current, m)
		}
	}
	old := []migrate.Migration{}
	for _, m := range current {
		if m.ID != "0033_records12" {
			old = append(old, m)
		}
	}
	if len(old) != 33 || len(current) != 34 {
		t.Fatal("unexpected upgrade catalogs", len(old), len(current))
	}
	apply(t, ctx, c, old)
	// Populate the genuine old schema using its existing deferred commit guards.
	exec(t, ctx, c, "BEGIN;"+seed+insertAsset+assign+evidence+"COMMIT;")
	const snapshot = `SELECT jsonb_build_object('observations',(SELECT jsonb_agg(to_jsonb(o) ORDER BY observation_id) FROM inventory.observations o),'facts',(SELECT jsonb_agg(to_jsonb(f) ORDER BY fact_key) FROM inventory.current_facts f),'assets',(SELECT jsonb_agg(to_jsonb(a) ORDER BY asset_uid) FROM assets.assets a),'ledger',(SELECT jsonb_agg(to_jsonb(m) ORDER BY id) FROM platform.schema_migrations m WHERE id<>'0033_records12'))::text`
	var before, after string
	if err := c.QueryRow(ctx, snapshot).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if n, err := migrate.Apply(ctx, c, current); err != nil || n != 1 {
		t.Fatal("expected exactly one appended migration", n, err)
	}
	if err := c.QueryRow(ctx, snapshot).Scan(&after); err != nil || after != before {
		t.Fatal("old evidence or applied migration bytes changed", err)
	}
	if n, err := migrate.Apply(ctx, c, current); err != nil || n != 0 {
		t.Fatal("migration not idempotent", n, err)
	}
	if err := migrate.Check(ctx, c, old); !errors.Is(err, migrate.ErrDrift) {
		t.Fatal("old catalog unexpectedly accepts upgraded schema", err)
	}
}
