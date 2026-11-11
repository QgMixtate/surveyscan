//go:build integration

package app_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/audit"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

// Стенд R-027 (C25.03 на живых данных): разделение записей ОДНОЙ машины (агент + SSH с общим machine_uuid)
// не должно останавливать их данные, а слияние должно закрывать конфликты, возникшие, пока активы были раздельными,
// и привязывать ожидавшие наблюдения.
func TestR027StandSplitSameMachineAndMergeSettles(t *testing.T) {
	f := registrySetup(t)
	if _, err := f.registry.ConfigureInventoryProtocol12(true); err != nil {
		t.Fatal(err)
	}
	machine := &sources.MachineService{Pool: f.pool, Audit: audit.Store{}}
	type src struct {
		id, gen string
		key     ed25519.PrivateKey
	}
	newSource := func() src {
		pub, key, _ := ed25519.GenerateKey(rand.Reader)
		s := src{identifier.New(), identifier.New(), key}
		if _, err := machine.RegisterPortable(f.ctx, "console", sources.PortableRegistration{Tenant: tenant, Site: siteID, Scope: scopeID, Source: s.id, Generation: s.gen, PublicKey: pub}); err != nil {
			t.Fatal(err)
		}
		return s
	}
	send := func(s src, seq string, c ...contracts.Candidate) (string, string) {
		t.Helper()
		o := testObservation12(t, f, seq)
		o.Origin = contracts.Origin{SourceID: s.id, SourceKind: "portable", GenerationID: s.gen}
		o.Record = contracts.SourceRecord{Namespace: "host", LocalID: "host:" + s.id[:8]}
		o.Clock = "estimated"
		o.Candidates = c
		raw, _ := json.Marshal(o)
		r, err := f.registry.ImportPortable(f.ctx, machine, tenant, s.id, portablePackage(t, s.key, s.id, raw))
		if err != nil || len(r.Records) != 1 {
			t.Fatal(err, r)
		}
		return r.Records[0].Disposition, r.Records[0].AssetID
	}
	q := func(sql string, args ...any) int {
		t.Helper()
		var n int
		if err := f.pool.QueryRow(f.ctx, sql, args...).Scan(&n); err != nil {
			t.Fatal(sql, err)
		}
		return n
	}
	record := func(s src) string {
		t.Helper()
		var k string
		if err := f.pool.QueryRow(f.ctx, "SELECT source_record_key::text FROM assets.source_records WHERE tenant_id=$1 AND source_id=$2", tenant, s.id).Scan(&k); err != nil {
			t.Fatal(err)
		}
		return k
	}
	openConflicts := func() int {
		return q("SELECT count(*) FROM assets.reconciliation_conflicts WHERE tenant_id=$1 AND state='open'", tenant)
	}
	pending := func(s src) int {
		return q(`SELECT count(*) FROM inventory.observations o WHERE o.tenant_id=$1 AND o.source_id=$2
AND NOT EXISTS(SELECT 1 FROM assets.observation_links l WHERE l.tenant_id=o.tenant_id AND l.observation_id=o.observation_id AND l.valid_to IS NULL)`, tenant, s.id)
	}
	mu := func() contracts.Candidate {
		return contracts.Candidate{Kind: "machine_uuid", Namespace: "linux-machine-id", Value: "4c4c4544-0000-1000-8000-" + identifier.New()[24:]}
	}
	host := func(v string) contracts.Candidate {
		return contracts.Candidate{Kind: "hostname", Namespace: "hostname.raw", Value: v}
	}

	// 1. агент и SSH одной машины: общий machine_uuid → один актив (C25.01)
	m := mu()
	agent, ssh := newSource(), newSource()
	if d, a := send(agent, "1", m, host("mvp")); d != "applied" || a == "" {
		t.Fatal("agent", d)
	}
	_, linux := send(agent, "2", m, host("mvp"))
	if d, a := send(ssh, "1", m, host("mvp")); d != "applied" || a != linux {
		t.Fatal("ssh view must auto-attach", d, a, linux)
	}
	// 2. оператор выделяет SSH-запись в новый актив
	res, err := f.registry.SplitAsset(f.ctx, f.identity, linux, app.SplitRequest{Records: []string{record(ssh)}})
	if err != nil || !res.Created {
		t.Fatal("split", res, err)
	}
	separate := res.ToAsset
	// дефект стенда: оба источника уходили в конфликт на каждом наблюдении (общий machine_uuid в двух активах).
	// Решение оператора «это разные активы» соблюдается: каждый источник продолжает вести свой актив.
	if d, a := send(agent, "3", m, host("mvp")); d != "applied" || a != linux {
		t.Fatal("after split the agent record must keep applying to its asset", d, a)
	}
	if d, a := send(ssh, "2", m, host("mvp")); d != "applied" || a != separate {
		t.Fatal("after split the ssh record must keep applying to the separated asset", d, a)
	}
	if n := openConflicts(); n != 0 {
		t.Fatal("split of one machine's records must not open conflicts", n)
	}
	// обратное слияние возвращает обе записи на Linux-актив, наблюдения продолжают применяться
	if _, err = f.registry.MergeAssets(f.ctx, f.identity, app.MergeRequest{Target: linux, Absorbed: separate}); err != nil {
		t.Fatal("merge back", err)
	}
	if d, a := send(ssh, "3", m, host("mvp")); d != "applied" || a != linux {
		t.Fatal("after merge ssh applies to the canonical asset", d, a)
	}

	// 3. конфликт, возникший, пока активы раздельны (не через split): запись W совпадает с активом Z по hostname
	cz, cw := newSource(), newSource()
	_, z := send(cz, "1", mu(), host("h-z"))
	mw := mu()
	_, w := send(cw, "1", mw, host("h-w"))
	if z == "" || w == "" || z == w {
		t.Fatal("two separate assets expected", z, w)
	}
	if d, _ := send(cw, "2", mw, host("h-z")); d != "recorded_pending_resolution" {
		t.Fatal("weak match with another asset must go to the queue", d)
	}
	if openConflicts() != 1 || pending(cw) != 1 {
		t.Fatal("one open conflict and one pending observation expected", openConflicts(), pending(cw))
	}
	// слияние W в Z: у конфликта не остаётся других кандидатов → закрыт, ожидавшее наблюдение привязано к Z
	out, err := f.registry.MergeAssets(f.ctx, f.identity, app.MergeRequest{Target: z, Absorbed: w})
	if err != nil {
		t.Fatal("merge", err)
	}
	if n := openConflicts(); n != 0 {
		t.Fatal("merge must settle conflicts that only pointed at the merged pair", n)
	}
	if n := pending(cw); n != 0 {
		t.Fatal("pending observations of the merged record must be linked", n, out)
	}
	if n := q("SELECT count(*) FROM assets.observation_links l JOIN inventory.observations o USING(tenant_id,observation_id) WHERE l.tenant_id=$1 AND o.source_id=$2 AND l.valid_to IS NULL AND l.asset_uid=$3", tenant, cw.id, z); n != 2 {
		t.Fatal("both observations of the merged record must belong to the target", n)
	}
}
