//go:build integration

package app_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/migrate"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func database(t *testing.T) (context.Context, *pgx.Conn, []migrate.Migration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	raw := os.Getenv("SURVEYSCAN_TEST_DATABASE_URL")
	if raw == "" {
		t.Fatal("integration requires an explicit isolated test database URL")
	}
	cfg, e := pgx.ParseConfig(raw)
	if e != nil {
		t.Fatal("invalid test configuration")
	}
	if f := os.Getenv("SURVEYSCAN_TEST_DATABASE_PASSWORD_FILE"); f != "" {
		b, e := os.ReadFile(f)
		if e != nil {
			t.Fatal("test password file unavailable")
		}
		cfg.Password = strings.TrimSpace(string(b))
	}
	admin, e := pgx.ConnectConfig(ctx, cfg)
	if e != nil {
		t.Fatal("test DB unavailable")
	}
	var random [8]byte
	if _, e = rand.Read(random[:]); e != nil {
		t.Fatal(e)
	}
	name := fmt.Sprintf("ssv2test_%x", random)
	_, e = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize())
	if e != nil {
		admin.Close(ctx)
		t.Fatal(e)
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		_, e := admin.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
		admin.Close(cleanup)
		if e != nil {
			t.Error("isolated test database cleanup failed")
		}
	})
	cfg.Database = name
	conn, e := pgx.ConnectConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	ms, e := app.Migrations()
	if e != nil {
		t.Fatal(e)
	}
	return ctx, conn, ms
}
func apply(t *testing.T, ctx context.Context, c *pgx.Conn, ms []migrate.Migration) {
	t.Helper()
	n, e := migrate.Apply(ctx, c, ms)
	if e != nil || n != len(ms) {
		t.Fatalf("initial migration: %d %v", n, e)
	}
}
func exec(t *testing.T, ctx context.Context, c *pgx.Conn, q string) {
	t.Helper()
	if _, e := c.Exec(ctx, q); e != nil {
		t.Fatal(e)
	}
}
func reject(t *testing.T, ctx context.Context, c *pgx.Conn, q, code string) {
	t.Helper()
	_, e := c.Exec(ctx, q)
	var pg *pgconn.PgError
	if !errors.As(e, &pg) || pg.Code != code {
		t.Fatalf("expected SQLSTATE %s, got %v", code, e)
	}
}

const tenant = "00000000-0000-4000-8000-000000000001"
const seed = `INSERT INTO access.tenants(tenant_id,name,status) VALUES ('00000000-0000-4000-8000-000000000001','test','active'),('00000000-0000-4000-8000-000000000099','other','active');
INSERT INTO responsibility.subjects(tenant_id,subject_id,kind,name,contact) VALUES ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000002','team','fallback','test@example.invalid');
INSERT INTO scope.sites(tenant_id,site_id,name,fallback_subject_id) VALUES ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000003','test','00000000-0000-4000-8000-000000000002');
INSERT INTO scope.network_scopes(tenant_id,scope_id,site_id,namespace) VALUES ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000004','00000000-0000-4000-8000-000000000003','local');`
const insertAsset = `INSERT INTO assets.assets(tenant_id,asset_uid,site_id,scope_id) VALUES ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000005','00000000-0000-4000-8000-000000000003','00000000-0000-4000-8000-000000000004');INSERT INTO assets.asset_changes(tenant_id,change_id,asset_uid,aggregate_version,reason_code,actor_ref) VALUES ('00000000-0000-4000-8000-000000000001',gen_random_uuid(),'00000000-0000-4000-8000-000000000005',1,'FIXTURE','test');
INSERT INTO messaging.outbox_events(tenant_id,event_id,producer_module,aggregate_type,aggregate_id,aggregate_version,event_type,correlation_id,payload) VALUES ('00000000-0000-4000-8000-000000000001',gen_random_uuid(),'Assets','asset','00000000-0000-4000-8000-000000000005',1,'asset.facts_changed.v1',gen_random_uuid(),'{"asset_uid":"00000000-0000-4000-8000-000000000005"}');
INSERT INTO audit.audit_events(tenant_id,audit_id,actor_ref,action,object_type,object_id) VALUES ('00000000-0000-4000-8000-000000000001',gen_random_uuid(),'test','fixture','asset','00000000-0000-4000-8000-000000000005');`
const assign = `INSERT INTO responsibility.responsibility_assignments(tenant_id,assignment_id,asset_uid,subject_id,role,reason_code,actor_ref) VALUES ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000006','00000000-0000-4000-8000-000000000005','00000000-0000-4000-8000-000000000002','accountable','fallback','test');`
const evidence = `INSERT INTO sources.sources(tenant_id,source_id,source_kind,site_id,state,generation_id) VALUES ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000007','portable','00000000-0000-4000-8000-000000000003','active','00000000-0000-4000-8000-000000000008');
INSERT INTO assets.source_records(tenant_id,source_record_key,source_id,namespace,source_local_id,resolution_state,asset_uid) VALUES ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000009','00000000-0000-4000-8000-000000000007','local','host','resolved','00000000-0000-4000-8000-000000000005');
INSERT INTO inventory.observations(tenant_id,observation_id,source_record_key,source_id,generation_id,source_sequence,clock_quality,digest,payload,origin_key_id,origin_signature,canonical_payload) VALUES ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000010','00000000-0000-4000-8000-000000000009','00000000-0000-4000-8000-000000000007','00000000-0000-4000-8000-000000000008',18446744073709551615,'unknown',encode(sha256(convert_to('{}','UTF8')),'hex'),'{}','00000000-0000-4000-8000-000000000011',decode(repeat('00',64),'hex'),convert_to('{}','UTF8'));
INSERT INTO inventory.observation_sections(tenant_id,observation_id,section_name,status,collection_complete,reason_code,record_count,facts) VALUES ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000010','os','ok',true,'test',1,'[{"name":"test"}]');
INSERT INTO assets.observation_links(tenant_id,link_id,observation_id,asset_uid,reason_code) VALUES ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000012','00000000-0000-4000-8000-000000000010','00000000-0000-4000-8000-000000000005','test');
INSERT INTO inventory.current_facts(tenant_id,asset_uid,section_name,fact_key,value,observation_id,link_id) VALUES ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000005','os','name','test','00000000-0000-4000-8000-000000000010','00000000-0000-4000-8000-000000000012');INSERT INTO inventory.observation_results(tenant_id,observation_id,asset_uid,disposition,reason_code) VALUES ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000010','00000000-0000-4000-8000-000000000005','applied','FIXTURE');
INSERT INTO messaging.outbox_events(tenant_id,event_id,producer_module,aggregate_type,aggregate_id,aggregate_version,event_type,correlation_id,payload) VALUES ('00000000-0000-4000-8000-000000000001',gen_random_uuid(),'Inventory','observation','00000000-0000-4000-8000-000000000010',1,'observation.recorded.v1',gen_random_uuid(),'{"observation_id":"00000000-0000-4000-8000-000000000010"}');
INSERT INTO audit.audit_events(tenant_id,audit_id,actor_ref,action,object_type,object_id) VALUES ('00000000-0000-4000-8000-000000000001',gen_random_uuid(),'test','fixture','observation','00000000-0000-4000-8000-000000000010');
UPDATE assets.assets SET aggregate_version=2 WHERE asset_uid='00000000-0000-4000-8000-000000000005';INSERT INTO assets.asset_changes(tenant_id,change_id,asset_uid,aggregate_version,reason_code,actor_ref) VALUES ('00000000-0000-4000-8000-000000000001',gen_random_uuid(),'00000000-0000-4000-8000-000000000005',2,'FIXTURE','test');
INSERT INTO messaging.outbox_events(tenant_id,event_id,producer_module,aggregate_type,aggregate_id,aggregate_version,event_type,correlation_id,payload) VALUES ('00000000-0000-4000-8000-000000000001',gen_random_uuid(),'Assets','asset','00000000-0000-4000-8000-000000000005',2,'asset.facts_changed.v1',gen_random_uuid(),'{"asset_uid":"00000000-0000-4000-8000-000000000005"}');
INSERT INTO audit.audit_events(tenant_id,audit_id,actor_ref,action,object_type,object_id) VALUES ('00000000-0000-4000-8000-000000000001',gen_random_uuid(),'test','fixture','asset','00000000-0000-4000-8000-000000000005');`

func TestMigrationRepeatPersistenceAndDrift(t *testing.T) {
	ctx, c, ms := database(t)
	apply(t, ctx, c, ms)
	n, e := migrate.Apply(ctx, c, ms)
	if n != 0 || e != nil {
		t.Fatal(n, e)
	}
	exec(t, ctx, c, seed)
	cfg := c.Config().Copy()
	other, e := pgx.ConnectConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close(ctx)
	var count int
	if e = other.QueryRow(ctx, "SELECT count(*) FROM access.tenants").Scan(&count); e != nil || count != 2 {
		t.Fatal(count, e)
	}
	if e = migrate.Check(ctx, other, ms); e != nil {
		t.Fatal(e)
	}
	if e = c.QueryRow(ctx, "SELECT count(*) FROM information_schema.tables WHERE table_schema IN ('access','responsibility','scope','sources','assets','inventory','cmdb','imports','audit','messaging') AND table_type='BASE TABLE'").Scan(&count); e != nil || count != 59 { // 59: +messaging.work_leases (0046, C35/C36); +responsibility.directory_settings (0045, C31.05); +messaging.webhook_subscriptions/webhook_deliveries (0044, C31.03); +responsibility.directory_sync_runs (0043, C31); +responsibility.team_members (0042, C27); +inventory.record_section_source_state12 (0037, R-027), +assets.asset_operations (0038, C25.03), +cmdb.services/relations/changes (0041, C26)
		t.Fatal(count, e)
	}
	exec(t, ctx, c, "UPDATE platform.schema_migrations SET sha256=repeat('0',64) WHERE id=(SELECT min(id) FROM platform.schema_migrations)")
	if _, e = migrate.Apply(ctx, c, ms); !errors.Is(e, migrate.ErrDrift) {
		t.Fatalf("drift accepted: %v", e)
	}
}
func TestMigrationAtomicFailure(t *testing.T) {
	ctx, c, ms := database(t)
	ms = append(ms, migrate.Migration{ID: "9999_failure", Owner: "test", SQL: "CREATE TABLE public.must_rollback(id int); SELECT 1/0;"})
	if _, e := migrate.Apply(ctx, c, ms); e == nil {
		t.Fatal("failed migration accepted")
	}
	var absent bool
	if e := c.QueryRow(ctx, "SELECT to_regclass('public.must_rollback') IS NULL AND to_regclass('platform.schema_migrations') IS NULL").Scan(&absent); e != nil || !absent {
		t.Fatal("bootstrap was not atomic", e)
	}
	ms = ms[:len(ms)-1]
	apply(t, ctx, c, ms)
}
func TestConcurrentMigration(t *testing.T) {
	ctx, c, ms := database(t)
	other, e := pgx.ConnectConfig(ctx, c.Config().Copy())
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close(ctx)
	var wg sync.WaitGroup
	counts := make(chan int, 2)
	errs := make(chan error, 2)
	for _, conn := range []*pgx.Conn{c, other} {
		wg.Add(1)
		go func(conn *pgx.Conn) { defer wg.Done(); n, e := migrate.Apply(ctx, conn, ms); counts <- n; errs <- e }(conn)
	}
	wg.Wait()
	close(counts)
	close(errs)
	sum := 0
	for n := range counts {
		sum += n
	}
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	if sum != len(ms) {
		t.Fatal(sum)
	}
}
func TestIdentityResponsibilityTenantConstraints(t *testing.T) {
	ctx, c, ms := database(t)
	apply(t, ctx, c, ms)
	exec(t, ctx, c, seed)
	reject(t, ctx, c, insertAsset, "23514")
	exec(t, ctx, c, "BEGIN;"+insertAsset+assign+"COMMIT;")
	reject(t, ctx, c, "DELETE FROM responsibility.responsibility_assignments", "23514")
	reject(t, ctx, c, "UPDATE assets.assets SET asset_uid='00000000-0000-4000-8000-000000000088'", "23514")
	reject(t, ctx, c, "DELETE FROM assets.assets", "23514")
	reject(t, ctx, c, "UPDATE responsibility.subjects SET active=false", "23514")
	reject(t, ctx, c, "UPDATE scope.sites SET tenant_id='00000000-0000-4000-8000-000000000099'", "23514")
	reject(t, ctx, c, "INSERT INTO scope.network_scopes(tenant_id,scope_id,site_id,namespace) VALUES ('00000000-0000-4000-8000-000000000099','00000000-0000-4000-8000-000000000090','00000000-0000-4000-8000-000000000003','cross-tenant')", "23503")
}
func TestEvidenceAndProjectionConstraints(t *testing.T) {
	ctx, c, ms := database(t)
	apply(t, ctx, c, ms)
	exec(t, ctx, c, seed)
	exec(t, ctx, c, "BEGIN;"+insertAsset+assign+"COMMIT;")
	exec(t, ctx, c, evidence)
	reject(t, ctx, c, "UPDATE inventory.observations SET clock_quality='trusted'", "23514")
	reject(t, ctx, c, "DELETE FROM inventory.observation_sections", "23514")
	reject(t, ctx, c, "UPDATE assets.observation_links SET valid_to=now()", "23514")
	reject(t, ctx, c, "INSERT INTO sources.collectors(tenant_id,collector_id,source_id) VALUES ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000077','00000000-0000-4000-8000-000000000007')", "23503")
	reject(t, ctx, c, "UPDATE access.tenants SET revision=18446744073709551616", "23514")
	exec(t, ctx, c, `BEGIN; DELETE FROM inventory.current_facts; UPDATE assets.observation_links SET valid_to=now(); UPDATE assets.assets SET aggregate_version=3;`+fixtureV3+`COMMIT;`)
}

const fixtureV3 = `INSERT INTO assets.asset_changes(tenant_id,change_id,asset_uid,aggregate_version,reason_code,actor_ref) VALUES ('00000000-0000-4000-8000-000000000001',gen_random_uuid(),'00000000-0000-4000-8000-000000000005',3,'FIXTURE','test');
INSERT INTO messaging.outbox_events(tenant_id,event_id,producer_module,aggregate_type,aggregate_id,aggregate_version,event_type,correlation_id,payload) VALUES ('00000000-0000-4000-8000-000000000001',gen_random_uuid(),'Assets','asset','00000000-0000-4000-8000-000000000005',3,'asset.facts_changed.v1',gen_random_uuid(),'{"asset_uid":"00000000-0000-4000-8000-000000000005"}');
INSERT INTO audit.audit_events(tenant_id,audit_id,actor_ref,action,object_type,object_id) VALUES ('00000000-0000-4000-8000-000000000001',gen_random_uuid(),'test','fixture','asset','00000000-0000-4000-8000-000000000005');`
