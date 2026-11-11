//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/assets"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/audit"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/health"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

// C25.04 — исправимость и конкурентность слияния/разделения: встречные и повторные операции под нагрузкой приёма,
// компенсация ошибочного слияния разделением с полной историей, повтор outbox до согласованных версий,
// запрет межтенантных операций. Инвариант после каждого шага: наблюдения не потеряны.
func TestC2504RecoverabilityAndConcurrency(t *testing.T) {
	f := registrySetup(t)
	if _, err := f.registry.ConfigureInventoryProtocol12(true); err != nil {
		t.Fatal(err)
	}
	machine := &sources.MachineService{Pool: f.pool, Audit: audit.Store{}}
	type host struct {
		source, generation, local string
		key                       ed25519.PrivateKey
		candidate                 contracts.Candidate
		mu                        sync.Mutex
		sequence                  int
	}
	newHost := func(local string) *host {
		pub, key, _ := ed25519.GenerateKey(rand.Reader)
		h := &host{source: identifier.New(), generation: identifier.New(), local: local, key: key,
			candidate: contracts.Candidate{Kind: "machine_uuid", Namespace: "linux-machine-id", Value: "4c4c4544-0000-1000-8000-" + identifier.New()[24:]}}
		if _, err := machine.RegisterPortable(f.ctx, "console", sources.PortableRegistration{Tenant: tenant, Site: siteID, Scope: scopeID, Source: h.source, Generation: h.generation, PublicKey: pub}); err != nil {
			t.Fatal(err)
		}
		return h
	}
	sent := 0
	var sentMu sync.Mutex
	send := func(h *host) (string, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.sequence++
		o := testObservation12(t, f, strconv.Itoa(h.sequence))
		o.Origin = contracts.Origin{SourceID: h.source, SourceKind: "portable", GenerationID: h.generation}
		o.Record = contracts.SourceRecord{Namespace: "host", LocalID: h.local}
		o.Clock = "estimated"
		o.Candidates = []contracts.Candidate{h.candidate}
		raw, _ := json.Marshal(o)
		report, err := f.registry.ImportPortable(f.ctx, machine, tenant, h.source, portablePackage(t, h.key, h.source, raw))
		if err != nil {
			return "", err
		}
		if len(report.Records) != 1 || report.Records[0].Disposition != "applied" {
			return "", errors.New("not applied: " + report.Records[0].Disposition)
		}
		sentMu.Lock()
		sent++
		sentMu.Unlock()
		return report.Records[0].AssetID, nil
	}
	q := func(sql string, args ...any) int {
		var n int
		if err := f.pool.QueryRow(f.ctx, sql, args...).Scan(&n); err != nil {
			t.Fatal(sql, err)
		}
		return n
	}
	invariants := func(step string) {
		t.Helper()
		// каждое наблюдение — ровно одна активная связь, и она указывает на актив своей записи
		if n := q(`SELECT count(*) FROM inventory.observations o WHERE o.tenant_id=$1 AND 1<>(SELECT count(*) FROM assets.observation_links l
JOIN assets.source_records r ON r.tenant_id=l.tenant_id AND r.asset_uid=l.asset_uid AND r.source_record_key=o.source_record_key
WHERE l.tenant_id=o.tenant_id AND l.observation_id=o.observation_id AND l.valid_to IS NULL)`, tenant); n != 0 {
			t.Fatalf("%s: %d observations lost their asset", step, n)
		}
		sentMu.Lock()
		total := sent
		sentMu.Unlock()
		if n := q("SELECT count(*) FROM inventory.observations o WHERE o.tenant_id=$1 AND o.source_id IN (SELECT source_id FROM assets.source_records WHERE tenant_id=$1 AND namespace='host' AND source_local_id LIKE 'c2504:%')", tenant); n != total {
			t.Fatalf("%s: stored %d observations, sent %d", step, n, total)
		}
		if n := q("SELECT count(*) FROM assets.source_records r JOIN assets.assets a USING(tenant_id,asset_uid) WHERE r.tenant_id=$1 AND a.merged_into IS NOT NULL", tenant); n != 0 {
			t.Fatalf("%s: records on merged assets", step)
		}
	}
	ha, hb := newHost("c2504:a"), newHost("c2504:b")
	a, err := send(ha)
	if err != nil {
		t.Fatal(err)
	}
	b, err := send(hb)
	if err != nil || a == b {
		t.Fatal(err, a, b)
	}
	recordOf := func(h *host) string {
		var k string
		if err := f.pool.QueryRow(f.ctx, "SELECT source_record_key::text FROM assets.source_records WHERE tenant_id=$1 AND source_id=$2", tenant, h.source).Scan(&k); err != nil {
			t.Fatal(err)
		}
		return k
	}
	rb := recordOf(hb)

	// 1. встречные слияния одновременно с приёмом: ровно одно слияние, второе — конфликт; приём не теряется
	var wg sync.WaitGroup
	results := make([]error, 2)
	for i, req := range []app.MergeRequest{{Target: a, Absorbed: b}, {Target: b, Absorbed: a}} {
		wg.Add(1)
		go func() { defer wg.Done(); _, results[i] = f.registry.MergeAssets(f.ctx, f.identity, req) }()
	}
	for _, h := range []*host{ha, hb, ha, hb} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := send(h); err != nil {
				t.Error("ingest during merge:", err)
			}
		}()
	}
	wg.Wait()
	ok := 0
	for _, e := range results {
		if e == nil {
			ok++
		} else if !errors.Is(e, domain.Conflict) {
			t.Fatal("loser of opposite merges must get a conflict:", e)
		}
	}
	if ok != 1 {
		t.Fatal("exactly one of opposite merges must win", results)
	}
	canonical, absorbed := a, b
	if results[0] != nil {
		canonical, absorbed = b, a
	}
	invariants("opposite merges")
	if got, err := send(hb); err != nil || got != canonical {
		t.Fatal("after merge new observations go to the canonical asset", got, err)
	}
	if got, err := send(ha); err != nil || got != canonical {
		t.Fatal(got, err)
	}

	// 2. компенсация: два одновременных разделения одной записи + приём — ровно одно разделение, один новый актив
	assetsBefore := q("SELECT count(*) FROM assets.assets WHERE tenant_id=$1", tenant)
	splits := make([]app.AssetOperationResult, 2)
	results = make([]error, 2)
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			splits[i], results[i] = f.registry.SplitAsset(f.ctx, f.identity, canonical, app.SplitRequest{Records: []string{rb}})
		}()
	}
	for _, h := range []*host{hb, ha, hb} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := send(h); err != nil {
				t.Error("ingest during split:", err)
			}
		}()
	}
	wg.Wait()
	var restored string
	ok = 0
	for i, e := range results {
		if e == nil {
			ok++
			restored = splits[i].ToAsset
		} else if !errors.Is(e, domain.Invalid) {
			t.Fatal("repeated split of the same record must be rejected:", e)
		}
	}
	if ok != 1 || q("SELECT count(*) FROM assets.assets WHERE tenant_id=$1", tenant) != assetsBefore+1 {
		t.Fatal("exactly one split and one new asset", results)
	}
	if restored == absorbed || restored == canonical {
		t.Fatal("split must not reuse UIDs")
	}
	invariants("concurrent splits")
	if got, err := send(hb); err != nil || got != restored {
		t.Fatal("after split the record's observations go to the split-off asset", got, err)
	}
	var merged assets.ErrMerged
	if _, err = f.registry.Get(f.ctx, f.identity, absorbed); !errors.As(err, &merged) || merged.Into != canonical {
		t.Fatal("absorbed UID stays an alias after compensation", err)
	}
	// история компенсации: обе операции и их причины на каждом затронутом активе, с аудитом
	if q("SELECT count(*) FROM assets.asset_operations WHERE tenant_id=$1 AND kind='merge' AND from_asset_uid=$2 AND to_asset_uid=$3", tenant, absorbed, canonical) != 1 ||
		q("SELECT count(*) FROM assets.asset_operations WHERE tenant_id=$1 AND kind='split' AND from_asset_uid=$2 AND to_asset_uid=$3 AND $4::uuid=ANY(source_record_keys)", tenant, canonical, restored, rb) != 1 {
		t.Fatal("merge and compensating split must both be recorded")
	}
	for _, c := range []struct{ asset, reason string }{{canonical, "ASSET_MERGE"}, {absorbed, "MERGED_INTO_ASSET"}, {canonical, "ASSET_SPLIT"}, {restored, "ASSET_SPLIT"}} {
		if q("SELECT count(*) FROM assets.asset_changes WHERE tenant_id=$1 AND asset_uid=$2 AND reason_code=$3", tenant, c.asset, c.reason) == 0 ||
			q("SELECT count(*) FROM audit.audit_events WHERE tenant_id=$1 AND object_type='asset' AND object_id=$2", tenant, c.asset) == 0 {
			t.Fatal("history and audit missing", c)
		}
	}

	// 3. повтор outbox: потребитель доходит до тех же версий, что у активов; повторный проход ничего не делает
	for range 10000 {
		worked, err := f.registry.ConsumeOne(f.ctx, tenant)
		if err != nil {
			t.Fatal(err)
		}
		if !worked {
			break
		}
	}
	if n := q("SELECT count(*) FROM assets.assets a LEFT JOIN assets.consumer_versions c USING(tenant_id,asset_uid) WHERE a.tenant_id=$1 AND c.aggregate_version IS DISTINCT FROM a.aggregate_version", tenant); n != 0 {
		t.Fatalf("%d assets: consumer versions differ from aggregate versions after replay", n)
	}
	restarted, err := app.NewRegistry(f.pool, f.users)
	if err != nil {
		t.Fatal(err)
	}
	if worked, err := restarted.ConsumeOne(f.ctx, tenant); err != nil || worked {
		t.Fatal("replay after restart must be a no-op", worked, err)
	}

	// 4. межтенантные операции запрещены: чужой администратор не видит активов, БД не принимает связь между тенантами
	if _, err = f.pool.Exec(f.ctx, "INSERT INTO access.tenants(tenant_id,name,status) VALUES($1,'other','active')", otherTenant); err != nil {
		t.Fatal(err)
	}
	if err = f.users.Provision(f.ctx, false, otherTenant, "", "foreign-admin", password, "admin"); err != nil {
		t.Fatal(err)
	}
	if err = f.users.Provision(f.ctx, false, tenant, "", "c2504-viewer", password, "viewer"); err != nil {
		t.Fatal(err)
	}
	auth, err := access.NewHTTP(f.users, "https://ui.example", false)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := app.NewHTTP(auth, health.Handler(func(context.Context) error { return nil }), f.registry)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	foreign := newBrowser(t, server)
	fs := foreign.login(t, "foreign-admin")
	body := `{"target_asset_uid":"` + canonical + `","absorbed_asset_uid":"` + restored + `"}`
	code, _, _ := foreign.request(t, "POST", "/api/v1/assets/merge", body, fs.CSRFToken, "https://ui.example", nil)
	expect(t, 404, code)
	code, _, _ = foreign.request(t, "POST", "/api/v1/assets/"+canonical+"/split", `{"source_record_keys":["`+recordOf(ha)+`"]}`, fs.CSRFToken, "https://ui.example", nil)
	expect(t, 404, code)
	code, _, _ = foreign.request(t, "GET", "/api/v1/assets/"+absorbed, "", "", "", nil)
	expect(t, 404, code) // псевдоним чужого тенанта не раскрывает канонический UID
	viewer := newBrowser(t, server)
	vs := viewer.login(t, "c2504-viewer")
	code, _, _ = viewer.request(t, "POST", "/api/v1/assets/merge", body, vs.CSRFToken, "https://ui.example", nil)
	expect(t, 403, code)
	if _, err = f.pool.Exec(f.ctx, "INSERT INTO assets.asset_operations(tenant_id,operation_id,kind,from_asset_uid,to_asset_uid,source_record_keys,actor_ref) VALUES($1,$2,'merge',$3,$4,'{}','test')", otherTenant, identifier.New(), restored, canonical); err == nil {
		t.Fatal("operation between tenants must violate foreign keys")
	}
	// 5. цепочка слияний: прежний псевдоним ведёт на последний канонический UID
	if _, err = f.registry.MergeAssets(f.ctx, f.identity, app.MergeRequest{Target: restored, Absorbed: canonical}); err != nil {
		t.Fatal(err)
	}
	for _, old := range []string{absorbed, canonical} {
		if _, err = f.registry.Get(f.ctx, f.identity, old); !errors.As(err, &merged) || merged.Into != restored {
			t.Fatal("alias chain must resolve to the latest canonical asset", old, err)
		}
	}
	code, raw, _ := br(t, f, server).request(t, "GET", "/api/v1/assets/"+absorbed, "", "", "", nil)
	if code != 200 || !strings.Contains(string(raw), restored) {
		t.Fatalf("old UID over HTTP: %d %s", code, raw)
	}
	invariants("final")
}

func br(t *testing.T, f *registryFixture, server *httptest.Server) browser {
	b := newBrowser(t, server)
	b.login(t, "admin")
	return b
}
