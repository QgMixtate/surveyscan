//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	accessport "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/inventory"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/health"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/messaging"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const sourceID = "00000000-0000-4000-8000-000000000007"
const generationID = "00000000-0000-4000-8000-000000000008"
const siteID = "00000000-0000-4000-8000-000000000003"
const scopeID = "00000000-0000-4000-8000-000000000004"

type registryFixture struct {
	ctx      context.Context
	registry *app.Registry
	users    *access.Service
	pool     *pgxpool.Pool
	key      ed25519.PrivateKey
	keyID    string
	identity accessport.Identity
}

func registrySetup(t *testing.T) *registryFixture {
	t.Helper()
	ctx, users, pool := authService(t)
	bootstrap(t, ctx, users)
	if _, e := pool.Exec(ctx, strings.SplitN(seed, ";\n", 2)[1]); e != nil {
		t.Fatal(e)
	}
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	keyID := identifier.New()
	_, e = pool.Exec(ctx, "INSERT INTO sources.sources(tenant_id,source_id,source_kind,site_id,state,generation_id) VALUES($1,$2,'portable',$3,'active',$4)", tenant, sourceID, siteID, generationID)
	if e != nil {
		t.Fatal(e)
	}
	_, e = pool.Exec(ctx, "INSERT INTO sources.ingest_bindings(tenant_id,source_id,generation_id,key_id,namespace,scope_id,public_key) VALUES($1,$2,$3,$4,'host',$5,$6)", tenant, sourceID, generationID, keyID, scopeID, []byte(pub))
	if e != nil {
		t.Fatal(e)
	}
	reg, e := app.NewRegistry(pool, users)
	if e != nil {
		t.Fatal(e)
	}
	session, raw, e := users.Login(ctx, "admin", password)
	if e != nil {
		t.Fatal(e)
	}
	id, e := users.Authenticate(ctx, raw, "session", session.CSRFToken, true)
	if e != nil {
		t.Fatal(e)
	}
	return &registryFixture{ctx, reg, users, pool, key, keyID, id}
}
func (f *registryFixture) observation(sequence string) contracts.Observation {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return contracts.Observation{Version: contracts.Version{Major: 1}, ID: identifier.New(), TenantID: tenant, Origin: contracts.Origin{SourceID: sourceID, SourceKind: "portable", GenerationID: generationID}, Record: contracts.SourceRecord{Namespace: "host", LocalID: "host-1"}, Scope: contracts.Scope{SiteID: siteID, ScopeID: scopeID}, Sequence: sequence, CollectedAt: now, Clock: "trusted", Candidates: []contracts.Candidate{{Kind: "machine_uuid", Namespace: "host", Value: "00000000-0000-4000-8000-000000000090"}, {Kind: "hostname", Namespace: "dns", Value: "host-one"}}, Sections: []contracts.Section{
		{Name: "identity", CollectedAt: now, Status: "ok", Complete: true, Reason: "COLLECTED", Count: 1, Records: []map[string]any{{"hostname": "host-one", "machine_uuid": "00000000-0000-4000-8000-000000000090"}}},
		{Name: "os", CollectedAt: now, Status: "ok", Complete: true, Reason: "COLLECTED", Count: 1, Records: []map[string]any{{"name": "Linux", "version": "6", "architecture": "amd64"}}},
		{Name: "network", CollectedAt: now, Status: "ok", Complete: true, Reason: "COLLECTED", Count: 1, Records: []map[string]any{{"name": "eth0", "mac": "aa:bb:cc:dd:ee:ff", "addresses": []any{map[string]any{"ip": "192.0.2.1", "prefix": 24}}}}},
	}}
}
func (f *registryFixture) signed(t *testing.T, o contracts.Observation) []byte {
	t.Helper()
	payload, e := json.Marshal(o)
	if e != nil {
		t.Fatal(e)
	}
	canonical, e := wire.Canonical(payload)
	if e != nil {
		t.Fatal(e)
	}
	digest := sha256.Sum256(canonical)
	sig := ed25519.Sign(f.key, append([]byte("SURVEYSCAN-OBSERVATION-V1\n"), canonical...))
	raw, e := json.Marshal(contracts.SignedObservation{Payload: payload, Digest: hex.EncodeToString(digest[:]), KeyID: f.keyID, Signature: base64.RawURLEncoding.EncodeToString(sig)})
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func (f *registryFixture) ingest(t *testing.T, o contracts.Observation) inventory.Result {
	t.Helper()
	result, e := f.registry.Ingest(f.ctx, tenant, sourceID, f.signed(t, o))
	if e != nil {
		t.Fatal(e)
	}
	return result
}
func count(t *testing.T, f *registryFixture, table string, want int) {
	t.Helper()
	var n int
	if e := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM "+table).Scan(&n); e != nil || n != want {
		t.Fatalf("%s count=%d want=%d err=%v", table, n, want, e)
	}
}
func TestC06SignedIngestConcurrentReplayAndSequenceConflict(t *testing.T) {
	f := registrySetup(t)
	o := f.observation("18446744073709551615")
	raw := f.signed(t, o)
	var results [2]inventory.Result
	var errs [2]error
	var wg sync.WaitGroup
	for i := range 2 {
		wg.Add(1)
		go func(i int) { defer wg.Done(); results[i], errs[i] = f.registry.Ingest(f.ctx, tenant, sourceID, raw) }(i)
	}
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	if results[0].AssetID == nil || results[1].AssetID == nil || *results[0].AssetID != *results[1].AssetID || results[0].Duplicate == results[1].Duplicate {
		t.Fatal("replay did not converge")
	}
	count(t, f, "assets.assets", 1)
	count(t, f, "inventory.observations", 1)
	count(t, f, "responsibility.responsibility_assignments", 1)
	count(t, f, "messaging.outbox_events", 4)
	count(t, f, "assets.asset_changes", 3)
	changed := o
	changed.ID = identifier.New()
	if _, e := f.registry.Ingest(f.ctx, tenant, sourceID, f.signed(t, changed)); !errors.Is(e, domain.Conflict) {
		t.Fatal("sequence reused", e)
	}
	changed = o
	changed.Sections = append([]contracts.Section(nil), o.Sections...)
	changed.Clock = "estimated"
	if _, e := f.registry.Ingest(f.ctx, tenant, sourceID, f.signed(t, changed)); !errors.Is(e, domain.Conflict) {
		t.Fatal("observation ID overwritten", e)
	}
	card, e := f.registry.Get(f.ctx, f.identity, *results[0].AssetID)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(card)
	if e = f.registry.Wire.Validate("Asset", b); e != nil {
		t.Fatal("C03 asset response invalid", string(b), e)
	}
	if card.Hostname == nil || *card.Hostname != "host-one" || card.Accountable == "" || card.Freshness != "fresh" {
		t.Fatal("incomplete card")
	}
}
func TestC06LatePartialUnavailableAndManualFields(t *testing.T) {
	f := registrySetup(t)
	initial := f.observation("10")
	result := f.ingest(t, initial)
	uid := *result.AssetID
	display := "Approved name"
	purpose := "manual"
	card, e := f.registry.Patch(f.ctx, f.identity, uid, "1", contracts.BusinessPatch{DisplayName: &display, Purpose: &purpose})
	if e != nil {
		t.Fatal(e)
	}
	businessRevision := card.Revision
	partial := f.observation("12")
	partial.Sections[0].Records = []map[string]any{{"hostname": "new-host"}}
	partial.Sections[0].Status = "partial"
	partial.Sections[0].Complete = false
	for i := 1; i < 3; i++ {
		partial.Sections[i].Records = []map[string]any{}
		partial.Sections[i].Count = 0
		partial.Sections[i].Complete = false
		partial.Sections[i].Status = "unavailable"
	}
	f.ingest(t, partial)
	late := f.observation("11")
	late.Sections[0].Records[0]["hostname"] = "late-host"
	f.ingest(t, late)
	card, e = f.registry.Get(f.ctx, f.identity, uid)
	if e != nil {
		t.Fatal(e)
	}
	if *card.Hostname != "new-host" || *card.OS != "Linux 6" || *card.Business.DisplayName != display || card.Revision != businessRevision {
		t.Fatal("late/partial overwrote projection or business")
	}
	var network int
	if e = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM inventory.current_facts WHERE section_name='network'").Scan(&network); e != nil || network != 2 {
		t.Fatal("unavailable cleared network", network, e)
	}
	empty := f.observation("13")
	empty.Sections[2].Records = []map[string]any{}
	empty.Sections[2].Count = 0
	f.ingest(t, empty)
	if e = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM inventory.current_facts WHERE section_name='network'").Scan(&network); e != nil || network != 0 {
		t.Fatal("complete empty snapshot did not clear", network, e)
	}
	skewed := f.observation("14")
	skewed.Clock = "skewed"
	skewed.Sections[0].Records[0]["hostname"] = "clock-bad"
	f.ingest(t, skewed)
	card, e = f.registry.Get(f.ctx, f.identity, uid)
	if e != nil || *card.Hostname == "clock-bad" {
		t.Fatal("skewed clock projected", e)
	}
	regressed := f.observation("15")
	regressed.CollectedAt = initial.CollectedAt.Add(-2 * time.Hour)
	for i := range regressed.Sections {
		regressed.Sections[i].CollectedAt = regressed.CollectedAt
	}
	regressed.Sections[0].Records[0]["hostname"] = "regressed-clock"
	f.ingest(t, regressed)
	card, e = f.registry.Get(f.ctx, f.identity, uid)
	if e != nil || *card.Hostname != "regressed-clock" || card.Freshness != "unknown" {
		t.Fatal("clock regression lost sequence or uncertainty", e)
	}
	count(t, f, "inventory.observations", 6)
}
func TestC06ConservativeIdentityAndPendingReplay(t *testing.T) {
	f := registrySetup(t)
	first := f.ingest(t, f.observation("1"))
	o := f.observation("2")
	o.Record.LocalID = "host-2"
	pending := f.ingest(t, o)
	if pending.Disposition != "recorded_pending_resolution" || pending.AssetID != nil {
		t.Fatal("cross-record auto-merge occurred")
	}
	replayed := f.ingest(t, o)
	if !replayed.Duplicate || replayed.Disposition != pending.Disposition {
		t.Fatal("pending replay changed")
	}
	count(t, f, "assets.assets", 1)
	count(t, f, "assets.reconciliation_conflicts", 1)
	cloned := f.observation("3")
	cloned.Candidates[0].Value = identifier.New()
	pending = f.ingest(t, cloned)
	if pending.AssetID != nil {
		t.Fatal("contradictory strong identifier accepted")
	}
	card, e := f.registry.Get(f.ctx, f.identity, *first.AssetID)
	if e != nil || *card.Hostname != "host-one" {
		t.Fatal("conflict altered card", e)
	}
	var mapped string
	if e = f.pool.QueryRow(f.ctx, "SELECT asset_uid::text FROM assets.source_records WHERE source_local_id='host-1'").Scan(&mapped); e != nil || mapped != *first.AssetID {
		t.Fatal("conflict changed old mapping", e)
	}
	count(t, f, "inventory.observations", 3)
}
func TestC06SignatureTenantSourceScopeAndSchemaRejection(t *testing.T) {
	f := registrySetup(t)
	o := f.observation("1")
	raw := f.signed(t, o)
	var signed contracts.SignedObservation
	_ = json.Unmarshal(raw, &signed)
	signed.Signature = strings.Repeat("A", 86)
	bad, _ := json.Marshal(signed)
	if _, e := f.registry.Ingest(f.ctx, tenant, sourceID, bad); !errors.Is(e, domain.Invalid) {
		t.Fatal("bad signature accepted", e)
	}
	for _, mutate := range []func(*contracts.Observation){func(o *contracts.Observation) { o.Record.Namespace = "other" }, func(o *contracts.Observation) { o.Origin.GenerationID = identifier.New() }, func(o *contracts.Observation) { o.Scope.SiteID = identifier.New() }} {
		changed := o
		mutate(&changed)
		if _, e := f.registry.Ingest(f.ctx, tenant, sourceID, f.signed(t, changed)); !errors.Is(e, domain.Unauthorized) {
			t.Fatal("scope binding bypassed", e)
		}
	}
	if _, e := f.registry.Ingest(f.ctx, otherTenant, sourceID, raw); !errors.Is(e, domain.Unauthorized) {
		t.Fatal("tenant bypassed", e)
	}
	o.Sections[0].Count = 2
	if _, e := f.registry.Ingest(f.ctx, tenant, sourceID, f.signed(t, o)); !errors.Is(e, domain.Invalid) {
		t.Fatal("count mismatch accepted", e)
	}
	count(t, f, "assets.assets", 0)
	count(t, f, "inventory.observations", 0)
}

type failingEvents struct{}

func (failingEvents) Emit(context.Context, pgx.Tx, messaging.Event) error {
	return errors.New("synthetic event write failure")
}
func TestC06EventFailureRollsBackWholeIngest(t *testing.T) {
	f := registrySetup(t)
	f.registry.Events = failingEvents{}
	if _, e := f.registry.Ingest(f.ctx, tenant, sourceID, f.signed(t, f.observation("1"))); e == nil {
		t.Fatal("injected failure ignored")
	}
	for _, table := range []string{"assets.assets", "assets.source_records", "assets.asset_identifiers", "responsibility.responsibility_assignments", "inventory.observations", "audit.audit_events", "messaging.outbox_events"} {
		count(t, f, table, 0)
	}
}
func TestC06DatabaseRejectsMissingCommitEvidence(t *testing.T) {
	f := registrySetup(t)
	f.ingest(t, f.observation("1"))
	for _, query := range []string{"UPDATE assets.asset_business_fields SET purpose='no event'", "UPDATE inventory.current_facts SET value='no event'", "UPDATE assets.assets SET aggregate_version=aggregate_version+1", "UPDATE messaging.outbox_events SET payload='{}'"} {
		_, e := f.pool.Exec(f.ctx, query)
		var pg *pgconn.PgError
		if !errors.As(e, &pg) || pg.Code != "23514" {
			t.Fatal("missing evidence accepted", query, e)
		}
	}
}
func TestC06OutboxConsumerRetryAtomicityAndRestart(t *testing.T) {
	f := registrySetup(t)
	f.ingest(t, f.observation("1"))
	worked, e := messaging.ConsumeOne(f.ctx, f.pool, tenant, "registry-version", func(ctx context.Context, tx pgx.Tx, event messaging.Event) error {
		if _, e := tx.Exec(ctx, "INSERT INTO assets.consumer_versions(tenant_id,asset_uid,aggregate_version) VALUES($1,$2,99)", tenant, event.AssetID); e != nil {
			return e
		}
		return errors.New("synthetic consumer crash")
	})
	if e != nil || !worked {
		t.Fatal(worked, e)
	}
	count(t, f, "assets.consumer_versions", 0)
	var state string
	var attempts int
	if e = f.pool.QueryRow(f.ctx, "SELECT state,attempts FROM messaging.consumer_checkpoints").Scan(&state, &attempts); e != nil || state != "retry" || attempts != 1 {
		t.Fatal(state, attempts, e)
	}
	if _, e = f.pool.Exec(f.ctx, "UPDATE messaging.consumer_checkpoints SET lease_until=clock_timestamp()-interval '1 second'"); e != nil {
		t.Fatal(e)
	}
	for range 10 {
		worked, e = f.registry.ConsumeOne(f.ctx, tenant)
		if e != nil {
			t.Fatal(e)
		}
		if !worked {
			break
		}
	}
	var version string
	if e = f.pool.QueryRow(f.ctx, "SELECT aggregate_version::text FROM assets.consumer_versions").Scan(&version); e != nil || version != "3" {
		t.Fatal(version, e)
	}
	count(t, f, "messaging.consumer_checkpoints", 4)
	restarted, e := app.NewRegistry(f.pool, f.users)
	if e != nil {
		t.Fatal(e)
	}
	worked, e = restarted.ConsumeOne(f.ctx, tenant)
	if e != nil || worked {
		t.Fatal("replayed completed effects", worked, e)
	}
}
func TestC06RegistryHTTPTenantPaginationAndOptimisticPatch(t *testing.T) {
	f := registrySetup(t)
	uid := *f.ingest(t, f.observation("1")).AssetID
	h, e := access.NewHTTP(f.users, "https://ui.example", false)
	if e != nil {
		t.Fatal(e)
	}
	handler, e := app.NewHTTP(h, health.Handler(func(context.Context) error { return nil }), f.registry)
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	b := newBrowser(t, server)
	session := b.login(t, "admin")
	code, body, headers := b.request(t, "GET", "/api/v1/assets/"+uid, "", "", "", nil)
	expect(t, 200, code)
	if e = f.registry.Wire.Validate("Asset", body); e != nil {
		t.Fatal(e)
	}
	etag := headers.Get("ETag")
	second := f.observation("1")
	second.Record.LocalID = "another-host"
	second.Candidates[0].Value = identifier.New()
	second.Candidates[1].Value = "host-two"
	second.Sections[0].Records[0]["hostname"] = "host-two"
	second.Sections[0].Records[0]["machine_uuid"] = second.Candidates[0].Value
	f.ingest(t, second)
	code, body, _ = b.request(t, "GET", "/api/v1/assets?limit=1", "", "", "", nil)
	expect(t, 200, code)
	if e = f.registry.Wire.Validate("AssetPage", body); e != nil {
		t.Fatal(e)
	}
	var firstPage contracts.AssetPage
	_ = json.Unmarshal(body, &firstPage)
	if firstPage.NextCursor == nil || len(firstPage.Items) != 1 {
		t.Fatal("missing pagination cursor")
	}
	code, nextBody, _ := b.request(t, "GET", "/api/v1/assets?limit=1&cursor="+*firstPage.NextCursor, "", "", "", nil)
	expect(t, 200, code)
	var nextPage contracts.AssetPage
	_ = json.Unmarshal(nextBody, &nextPage)
	if len(nextPage.Items) != 1 || nextPage.Items[0].UID == firstPage.Items[0].UID {
		t.Fatal("pagination duplicated/dropped existing assets")
	}
	code, _, _ = b.request(t, "GET", "/api/v1/assets?limit=0", "", "", "", nil)
	expect(t, 400, code)
	var codes [2]int
	var wg sync.WaitGroup
	for i := range 2 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i], _, _ = b.request(t, "PATCH", "/api/v1/assets/"+uid, `{"display_name":"manual"}`, session.CSRFToken, "https://ui.example", map[string]string{"If-Match": etag})
		}(i)
	}
	wg.Wait()
	if !((codes[0] == 200 && codes[1] == 412) || (codes[1] == 200 && codes[0] == 412)) {
		t.Fatal("optimistic concurrency failed", codes)
	}
	if _, e = f.pool.Exec(f.ctx, "INSERT INTO access.tenants(tenant_id,name,status) VALUES($1,'other','active')", otherTenant); e != nil {
		t.Fatal(e)
	}
	if e = f.users.Provision(f.ctx, false, otherTenant, "", "other-reader", password, "viewer"); e != nil {
		t.Fatal(e)
	}
	other := newBrowser(t, server)
	other.login(t, "other-reader")
	code, _, _ = other.request(t, "GET", "/api/v1/assets?cursor="+*firstPage.NextCursor, "", "", "", nil)
	expect(t, 400, code)
	code, _, _ = other.request(t, "GET", "/api/v1/assets/"+uid, "", "", "", nil)
	expect(t, 404, code)
	code, body, _ = other.request(t, "GET", "/api/v1/assets", "", "", "", nil)
	expect(t, 200, code)
	var page contracts.AssetPage
	_ = json.Unmarshal(body, &page)
	if len(page.Items) != 0 {
		t.Fatal("tenant leaked in list")
	}
}

func TestC06ConsumerDeadLetterAndAggregateGap(t *testing.T) {
	f := registrySetup(t)
	f.ingest(t, f.observation("1"))
	for range 5 {
		worked, e := messaging.ConsumeOne(f.ctx, f.pool, tenant, "broken", func(context.Context, pgx.Tx, messaging.Event) error {
			return errors.New("synthetic persistent failure")
		})
		if e != nil || !worked {
			t.Fatal(worked, e)
		}
		if _, e = f.pool.Exec(f.ctx, "UPDATE messaging.consumer_checkpoints SET lease_until=clock_timestamp()-interval '1 second' WHERE consumer_name='broken' AND state='retry'"); e != nil {
			t.Fatal(e)
		}
	}
	var attempts int
	var state string
	if e := f.pool.QueryRow(f.ctx, "SELECT state,attempts FROM messaging.consumer_checkpoints WHERE consumer_name='broken'").Scan(&state, &attempts); e != nil || state != "dead_letter" || attempts != 5 {
		t.Fatal(state, attempts, e)
	}
	// Независимый observation может пройти; более поздние asset versions не обходят gap.
	for range 3 {
		_, e := messaging.ConsumeOne(f.ctx, f.pool, tenant, "broken", func(_ context.Context, _ pgx.Tx, event messaging.Event) error {
			if event.Aggregate == "asset" {
				t.Error("asset version bypassed dead-letter gap")
			}
			return nil
		})
		if e != nil {
			t.Fatal(e)
		}
	}
}
