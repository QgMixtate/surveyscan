//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
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
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// C25.03: две карточки одного устройства сливаются, ошибочное слияние разделяется. Проверяется: старый UID
// разрешается в канонический, разделение не переиспользует UID, проекции после разделения совпадают с исходными
// (пересборка из неизменных наблюдений), наблюдения не теряются, история/аудит/outbox на каждом активе.
func TestMergeAndSplitAssets(t *testing.T) {
	f := registrySetup(t)
	if _, err := f.registry.ConfigureInventoryProtocol12(true); err != nil {
		t.Fatal(err)
	}
	machine := &sources.MachineService{Pool: f.pool, Audit: audit.Store{}}
	type portableSource struct {
		id, generation string
		key            ed25519.PrivateKey
	}
	newSource := func() portableSource {
		pub, key, _ := ed25519.GenerateKey(rand.Reader)
		s := portableSource{identifier.New(), identifier.New(), key}
		if _, err := machine.RegisterPortable(f.ctx, "console", sources.PortableRegistration{Tenant: tenant, Site: siteID, Scope: scopeID, Source: s.id, Generation: s.generation, PublicKey: pub}); err != nil {
			t.Fatal(err)
		}
		return s
	}
	send := func(s portableSource, sequence, local string, candidates ...contracts.Candidate) (string, string) {
		o := testObservation12(t, f, sequence)
		o.Origin = contracts.Origin{SourceID: s.id, SourceKind: "portable", GenerationID: s.generation}
		o.Record = contracts.SourceRecord{Namespace: "host", LocalID: local}
		o.Clock = "estimated"
		o.Candidates = candidates
		raw, _ := json.Marshal(o)
		report, err := f.registry.ImportPortable(f.ctx, machine, tenant, s.id, portablePackage(t, s.key, s.id, raw))
		if err != nil || len(report.Records) != 1 {
			t.Fatal(err, report)
		}
		if report.Records[0].Disposition == "quarantined" {
			t.Log("quarantined:", report.Records[0].Reason)
		}
		return report.Records[0].Disposition, report.Records[0].AssetID
	}
	mu := func() contracts.Candidate {
		return contracts.Candidate{Kind: "machine_uuid", Namespace: "linux-machine-id", Value: "4c4c4544-0000-1000-8000-" + identifier.New()[24:]}
	}
	q := func(sql string, args ...any) int {
		var n int
		if err := f.pool.QueryRow(f.ctx, sql, args...).Scan(&n); err != nil {
			t.Fatal(sql, err)
		}
		return n
	}
	// снимок проекции 1.2 актива: раздел/запись/поле/значение/наблюдение
	snapshot := func(asset string) string {
		var s *string
		if err := f.pool.QueryRow(f.ctx, `SELECT string_agg(x,E'\n' ORDER BY x) FROM (
SELECT section_name||'|'||record_key||'|'||field_name||'|'||value::text||'|'||observation_id::text x FROM inventory.record_facts12 WHERE tenant_id=$1 AND asset_uid=$2
UNION ALL SELECT 'state|'||section_name||'|'||last_attempt_id::text||'|'||last_status||'|'||clock_uncertain::text FROM inventory.record_section_state12 WHERE tenant_id=$1 AND asset_uid=$2
UNION ALL SELECT 'source|'||section_name||'|'||source_id::text||'|'||last_attempt_id::text||'|'||last_status||'|'||collected_at::text FROM inventory.record_section_source_state12 WHERE tenant_id=$1 AND asset_uid=$2) s`, tenant, asset).Scan(&s); err != nil {
			t.Fatal(err)
		}
		if s == nil {
			return ""
		}
		return *s
	}
	recordOf := func(source string) string {
		var k string
		if err := f.pool.QueryRow(f.ctx, "SELECT source_record_key::text FROM assets.source_records WHERE tenant_id=$1 AND source_id=$2", tenant, source).Scan(&k); err != nil {
			t.Fatal(err)
		}
		return k
	}

	// две карточки одного устройства: разные источники, разные сильные ID (автосведение не сработало)
	s1, s2 := newSource(), newSource()
	m1, m2 := mu(), mu()
	d, a1 := send(s1, "1", "host:a", m1)
	if d != "applied" {
		t.Fatal(d)
	}
	if d, a := send(s1, "2", "host:a", m1); d != "applied" || a != a1 {
		t.Fatal("second observation of the same record", d, a)
	}
	d, a2 := send(s2, "1", "host:b", m2)
	if d != "applied" || a2 == a1 || a1 == "" {
		t.Fatal("two separate cards expected", d, a1, a2)
	}
	r1, r2 := recordOf(s1.id), recordOf(s2.id)
	before1, before2 := snapshot(a1), snapshot(a2)
	if before1 == "" || before2 == "" {
		t.Fatal("both cards must have 1.2 projection")
	}
	purpose := "бухгалтерия"
	if _, err := f.registry.Patch(f.ctx, f.identity, a2, "1", contracts.BusinessPatch{Purpose: &purpose}); err != nil {
		t.Fatal(err)
	}

	// у поглощаемого актива — явный ответственный (у цели — по умолчанию площадки)
	owner := identifier.New()
	if _, err := f.pool.Exec(f.ctx, "INSERT INTO responsibility.subjects(tenant_id,subject_id,kind,name,contact) VALUES($1,$2,'team','Бухгалтерия','buh@example.test')", tenant, owner); err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{
		"UPDATE responsibility.responsibility_assignments SET valid_to=now() WHERE tenant_id=$1 AND asset_uid=$2 AND role='accountable' AND valid_to IS NULL AND $3::uuid IS NOT NULL",
		"INSERT INTO responsibility.responsibility_assignments(tenant_id,assignment_id,asset_uid,subject_id,role,reason_code,actor_ref) VALUES($1,gen_random_uuid(),$2,$3,'accountable','MANUAL','test')",
	} {
		if _, err = tx.Exec(f.ctx, sql, tenant, a2, owner); err != nil {
			tx.Rollback(f.ctx)
			t.Fatal(err)
		}
	}
	if err = tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}

	// отказы: тот же актив, неизвестный актив (в т.ч. чужого тенанта — не находится), устаревшая версия
	if _, err := f.registry.MergeAssets(f.ctx, f.identity, app.MergeRequest{Target: a1, Absorbed: a1}); !errors.Is(err, domain.Invalid) {
		t.Fatal("self merge must be invalid", err)
	}
	if _, err := f.registry.MergeAssets(f.ctx, f.identity, app.MergeRequest{Target: a1, Absorbed: identifier.New()}); !errors.Is(err, domain.NotFound) {
		t.Fatal("unknown asset must be not found", err)
	}
	if _, err := f.registry.MergeAssets(f.ctx, f.identity, app.MergeRequest{Target: a1, Absorbed: a2, TargetVersion: "999"}); !errors.Is(err, domain.Revision) {
		t.Fatal("stale version must be rejected", err)
	}

	// слияние a2 → a1
	res, err := f.registry.MergeAssets(f.ctx, f.identity, app.MergeRequest{Target: a1, Absorbed: a2})
	if err != nil || res.Records != 1 || res.Relinked != 1 || res.Rebuilt != 3 || res.ToAsset != a1 {
		t.Fatalf("merge: %+v %v", res, err)
	}
	var merged assets.ErrMerged
	if _, err = f.registry.Get(f.ctx, f.identity, a2); !errors.As(err, &merged) || merged.Into != a1 {
		t.Fatal("old UID must resolve to the canonical one", err)
	}
	page, err := f.registry.List(f.ctx, f.identity, "", 200)
	if err != nil || slices.ContainsFunc(page.Items, func(a contracts.Asset) bool { return a.UID == a2 }) {
		t.Fatal("merged asset must not be listed", err)
	}
	card, err := f.registry.Get(f.ctx, f.identity, a1)
	if err != nil || card.Business.Purpose == nil || *card.Business.Purpose != purpose {
		t.Fatal("empty business fields of the target are filled from the absorbed asset", err)
	}
	if q("SELECT count(*) FROM assets.source_records WHERE tenant_id=$1 AND asset_uid=$2", tenant, a1) != 2 || snapshot(a2) != "" || snapshot(a1) == "" {
		t.Fatal("records and projection must move to the target")
	}
	if q("SELECT count(*) FROM assets.asset_changes WHERE tenant_id=$1 AND asset_uid=$2 AND reason_code='ASSET_MERGE'", tenant, a1) != 2 || // факты + смена ответственного
		q("SELECT count(*) FROM assets.asset_changes WHERE tenant_id=$1 AND asset_uid=$2 AND reason_code='MERGED_INTO_ASSET'", tenant, a2) != 1 ||
		q("SELECT count(*) FROM assets.asset_operations WHERE tenant_id=$1 AND kind='merge' AND from_asset_uid=$2 AND to_asset_uid=$3", tenant, a2, a1) != 1 {
		t.Fatal("merge must be recorded in history and operations")
	}
	if card.Accountable != owner || q("SELECT count(*) FROM responsibility.responsibility_assignments WHERE tenant_id=$1 AND asset_uid=$2 AND role='accountable' AND valid_to IS NULL AND subject_id=$3", tenant, a2, owner) != 1 {
		t.Fatal("explicit accountable of the absorbed asset replaces the site fallback of the target", card.Accountable)
	}
	if _, err = f.registry.MergeAssets(f.ctx, f.identity, app.MergeRequest{Target: a2, Absorbed: a1}); !errors.Is(err, domain.Conflict) {
		t.Fatal("merged asset cannot take part in operations", err)
	}
	// новое наблюдение записи поглощённого актива применяется к каноническому
	if d, a := send(s2, "2", "host:b", m2); d != "applied" || a != a1 {
		t.Fatal("new observation of a moved record must apply to the canonical asset", d, a)
	}

	// отказы разделения: чужая запись, все записи в новый актив, слитый актив как цель
	if _, err = f.registry.SplitAsset(f.ctx, f.identity, a1, app.SplitRequest{Records: []string{identifier.New()}}); !errors.Is(err, domain.Invalid) {
		t.Fatal("foreign record must be invalid", err)
	}
	if _, err = f.registry.SplitAsset(f.ctx, f.identity, a1, app.SplitRequest{Records: []string{r1, r2}}); !errors.Is(err, domain.Invalid) {
		t.Fatal("moving every record to a new asset must be invalid", err)
	}
	if _, err = f.registry.SplitAsset(f.ctx, f.identity, a1, app.SplitRequest{Records: []string{r2}, Target: a2}); !errors.Is(err, domain.Conflict) {
		t.Fatal("merged asset cannot be a split target", err)
	}

	// разделение ошибочного слияния: запись r2 — в новый актив (новый UID, a2 не переиспользуется)
	res, err = f.registry.SplitAsset(f.ctx, f.identity, a1, app.SplitRequest{Records: []string{r2}})
	if err != nil || !res.Created || res.ToAsset == a2 || res.ToAsset == a1 || res.Records != 1 {
		t.Fatalf("split: %+v %v", res, err)
	}
	a3 := res.ToAsset
	if snapshot(a1) != before1 {
		t.Fatal("projection of the remaining asset must equal its state before the merge")
	}
	if got := snapshot(a3); got == "" || got == before2 {
		// a3 получил ещё и наблюдение №2 источника s2 (после слияния) — снимок новее исходного a2
		t.Fatal("split-off asset must carry its record projection", got == "")
	}
	if _, err = f.registry.Get(f.ctx, f.identity, a2); !errors.As(err, &merged) || merged.Into != a1 {
		t.Fatal("old merged UID stays an alias of the canonical asset", err)
	}
	if q("SELECT count(*) FROM assets.asset_identifiers WHERE tenant_id=$1 AND source_record_key=$2 AND valid_to IS NULL AND asset_uid<>$3", tenant, r2, a3) != 0 {
		t.Fatal("active identifiers of the record must follow it")
	}
	// наблюдения не потеряны: каждое — ровно с одной активной связью, связь — с активом своей записи
	if q("SELECT count(*) FROM inventory.observations o WHERE o.tenant_id=$1 AND NOT EXISTS(SELECT 1 FROM assets.observation_links l JOIN assets.source_records r ON r.tenant_id=l.tenant_id AND r.asset_uid=l.asset_uid AND r.source_record_key=o.source_record_key WHERE l.tenant_id=o.tenant_id AND l.observation_id=o.observation_id AND l.valid_to IS NULL)", tenant) != 0 {
		t.Fatal("every observation must keep one active link to its record's asset")
	}
	if q("SELECT count(*) FROM assets.asset_changes WHERE tenant_id=$1 AND reason_code='ASSET_SPLIT' AND asset_uid IN ($2,$3)", tenant, a1, a3) < 3 {
		t.Fatal("split must be recorded on both assets")
	}
	// повторное разделение в существующий актив (перепривязка записи): r2 возвращается на a1
	if res, err = f.registry.SplitAsset(f.ctx, f.identity, a3, app.SplitRequest{Records: []string{r2}, Target: a1}); err != nil || res.Created {
		t.Fatalf("rebind into an existing asset: %+v %v", res, err)
	}
	if q("SELECT count(*) FROM assets.source_records WHERE tenant_id=$1 AND asset_uid=$2", tenant, a3) != 0 || snapshot(a3) != "" {
		t.Fatal("source asset of a full rebind is left without records and projection")
	}

	// HTTP: старый UID карточки и инвентаризации ведёт на канонический; операция — сессия с CSRF, ответ по контракту
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
	br := newBrowser(t, server)
	session := br.login(t, "admin")
	for _, path := range []string{"/api/v1/assets/" + a2, "/api/v1/assets/" + a2 + "/inventory"} {
		code, raw, header := br.request(t, "GET", path, "", "", "", nil)
		if code == 308 {
			if header.Get("Location") != strings.Replace(path, a2, a1, 1) {
				t.Fatal("redirect target", header.Get("Location"))
			}
			continue
		}
		if code != 200 || !strings.Contains(string(raw), a1) {
			t.Fatalf("old UID must lead to the canonical asset: %d %s", code, raw)
		}
	}
	body := `{"target_asset_uid":"` + a1 + `","absorbed_asset_uid":"` + a3 + `"}`
	code, _, _ := br.request(t, "POST", "/api/v1/assets/merge", body, "", "https://ui.example", nil)
	expect(t, 403, code) // без CSRF
	code, raw, _ := br.request(t, "POST", "/api/v1/assets/merge", body, session.CSRFToken, "https://ui.example", nil)
	expect(t, 200, code)
	schemaRaw, err := os.ReadFile("../../contracts/c25-reconciliation.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := jsonschema.UnmarshalJSON(strings.NewReader(string(schemaRaw)))
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err = compiler.AddResource("urn:surveyscan:c25:reconciliation:1:0", doc); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("urn:surveyscan:c25:reconciliation:1:0#/$defs/AssetOperation")
	if err != nil {
		t.Fatal(err)
	}
	instance, _ := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
	if err = schema.Validate(instance); err != nil {
		t.Fatal("merge result violates its contract:", err, string(raw))
	}
	code, raw, _ = br.request(t, "GET", "/api/v1/assets/"+a1+"/source-records", "", "", "", nil)
	expect(t, 200, code)
	records, err := compiler.Compile("urn:surveyscan:c25:reconciliation:1:0#/$defs/SourceRecordPage")
	if err != nil {
		t.Fatal(err)
	}
	instance, _ = jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
	if err = records.Validate(instance); err != nil || !strings.Contains(string(raw), r1) || !strings.Contains(string(raw), r2) {
		t.Fatal("source records page:", err, string(raw))
	}
	code, _, _ = br.request(t, "POST", "/api/v1/assets/"+a1+"/split", `{"source_record_keys":["`+r1+`"],"extra":1}`, session.CSRFToken, "https://ui.example", nil)
	expect(t, 400, code) // неизвестное поле
	code, _, _ = br.request(t, "POST", "/api/v1/assets/"+a2+"/split", `{"source_record_keys":["`+r1+`"]}`, session.CSRFToken, "https://ui.example", nil)
	expect(t, 409, code) // слитый актив
}
