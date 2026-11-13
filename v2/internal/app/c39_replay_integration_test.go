//go:build integration

package app_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/assets"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/audit"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

// C39.03: после восстановления (байт-в-байт, учения dr_drill) источники повторно присылают старые пакеты. Повтор
// пакета не создаёт эффекта (дубль по журналу приёма), пакет поглощённого при слиянии актива попадает в
// канонический актив через алиас, старый UID остаётся «надгробием» — не воскресает.
func TestC39ReplayAfterRestoreRespectsLedgerAliasesAndTombstones(t *testing.T) {
	f := registrySetup(t)
	if _, err := f.registry.ConfigureInventoryProtocol12(true); err != nil {
		t.Fatal(err)
	}
	machine := &sources.MachineService{Pool: f.pool, Audit: audit.Store{}}
	type src struct {
		id, generation string
		key            ed25519.PrivateKey
	}
	newSource := func() src {
		pub, key, _ := ed25519.GenerateKey(rand.Reader)
		s := src{identifier.New(), identifier.New(), key}
		if _, err := machine.RegisterPortable(f.ctx, "console", sources.PortableRegistration{Tenant: tenant, Site: siteID, Scope: scopeID, Source: s.id, Generation: s.generation, PublicKey: pub}); err != nil {
			t.Fatal(err)
		}
		return s
	}
	build := func(s src, sequence, local string, c contracts.Candidate) []byte {
		o := testObservation12(t, f, sequence)
		o.Origin = contracts.Origin{SourceID: s.id, SourceKind: "portable", GenerationID: s.generation}
		o.Record = contracts.SourceRecord{Namespace: "host", LocalID: local}
		o.Clock = "estimated"
		o.Candidates = []contracts.Candidate{c}
		raw, _ := json.Marshal(o)
		return portablePackage(t, s.key, s.id, raw)
	}
	imp := func(s src, pkg []byte) (string, string) {
		report, err := f.registry.ImportPortable(f.ctx, machine, tenant, s.id, pkg)
		if err != nil || len(report.Records) != 1 {
			t.Fatal(err, report)
		}
		return report.Records[0].Disposition, report.Records[0].AssetID
	}
	count := func(sql string) int {
		var n int
		if err := f.pool.QueryRow(f.ctx, sql, tenant).Scan(&n); err != nil {
			t.Fatal(sql, err)
		}
		return n
	}
	mu := func() contracts.Candidate {
		return contracts.Candidate{Kind: "machine_uuid", Namespace: "linux-machine-id", Value: "4c4c4544-0000-1000-8000-" + identifier.New()[24:]}
	}
	s1, s2 := newSource(), newSource()
	m1, m2 := mu(), mu()
	p1 := build(s1, "1", "host:a", m1)
	p2 := build(s2, "1", "host:b", m2)
	if d, _ := imp(s1, p1); d != "applied" {
		t.Fatal("first package", d)
	}
	if d, _ := imp(s1, p1); d != "duplicate" { // повтор до слияния — тоже дубль
		t.Fatal("replay before merge", d)
	}
	d, a2 := imp(s2, p2)
	if d != "applied" || a2 == "" {
		t.Fatal("second source", d)
	}
	var first string
	if err := f.pool.QueryRow(f.ctx, "SELECT asset_uid::text FROM assets.source_records WHERE tenant_id=$1 AND source_id=$2", tenant, s1.id).Scan(&first); err != nil {
		t.Fatal(err)
	}
	if _, err := f.registry.MergeAssets(f.ctx, f.identity, app.MergeRequest{Target: first, Absorbed: a2}); err != nil {
		t.Fatal(err)
	}
	obs := count("SELECT count(*) FROM inventory.observations WHERE tenant_id=$1")
	live := count("SELECT count(*) FROM assets.assets WHERE tenant_id=$1")
	outbox := count("SELECT count(*) FROM messaging.outbox_events WHERE tenant_id=$1")
	// «после восстановления»: оба источника повторяют уже принятые пакеты
	for _, c := range []struct {
		s   src
		pkg []byte
	}{{s1, p1}, {s2, p2}} {
		if d, _ := imp(c.s, c.pkg); d != "duplicate" {
			t.Fatal("replayed package after restore must be a duplicate, got", d)
		}
	}
	if count("SELECT count(*) FROM inventory.observations WHERE tenant_id=$1") != obs || count("SELECT count(*) FROM assets.assets WHERE tenant_id=$1") != live ||
		count("SELECT count(*) FROM messaging.outbox_events WHERE tenant_id=$1") != outbox {
		t.Fatal("replay created observations, assets or events")
	}
	// новый пакет источника поглощённого актива — в канонический актив; старый UID не воскресает
	if d, a := imp(s2, build(s2, "2", "host:b", m2)); d != "applied" || a != first {
		t.Fatalf("next package of the absorbed source: %s → %s, want applied → %s", d, a, first)
	}
	var merged assets.ErrMerged
	if _, err := f.registry.Get(f.ctx, f.identity, a2); !errors.As(err, &merged) || merged.Into != first {
		t.Fatal("absorbed UID must stay a tombstone alias of the canonical asset", err)
	}
	if count("SELECT count(*) FROM assets.assets WHERE tenant_id=$1") != live {
		t.Fatal("no asset may be created by post-restore traffic")
	}
}
