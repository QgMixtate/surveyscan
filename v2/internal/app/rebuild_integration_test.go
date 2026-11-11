//go:build integration

package app_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/audit"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

// C25.03: пакетная пересборка проекции 1.2 в памяти обязана давать то же, что последовательный приём
// (ProjectPartial12) — значения, наблюдение-владелец, состояние раздела и состояния по источникам. Смесь трёх
// источников одного актива: доверенные и недоверенные часы, разное время сбора, частичные наборы записей.
func TestRebuild12MatchesSequentialProjection(t *testing.T) {
	f := registrySetup(t)
	if _, err := f.registry.ConfigureInventoryProtocol12(true); err != nil {
		t.Fatal(err)
	}
	machine := &sources.MachineService{Pool: f.pool, Audit: audit.Store{}}
	mu := contracts.Candidate{Kind: "machine_uuid", Namespace: "linux-machine-id", Value: "4c4c4544-0000-1000-8000-" + identifier.New()[24:]}
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	asset := ""
	for source := range 3 {
		pub, key, _ := ed25519.GenerateKey(rand.Reader)
		id, generation := identifier.New(), identifier.New()
		if _, err := machine.RegisterPortable(f.ctx, "console", sources.PortableRegistration{Tenant: tenant, Site: siteID, Scope: scopeID, Source: id, Generation: generation, PublicKey: pub}); err != nil {
			t.Fatal(err)
		}
		var payloads [][]byte
		for i := 1; i <= 6; i++ {
			o := testObservation12(t, f, strconv.Itoa(i))
			o.Origin = contracts.Origin{SourceID: id, SourceKind: "portable", GenerationID: generation}
			o.Record = contracts.SourceRecord{Namespace: "host", LocalID: fmt.Sprintf("host:%d", source)}
			o.Candidates = []contracts.Candidate{mu}
			o.Clock = []string{"trusted", "estimated"}[(source+i)%2]
			// время сбора перемешано между источниками: поздний приём не значит свежий сбор
			at := base.Add(time.Duration((i*7+source*11)%23) * time.Minute)
			o.CollectedAt = at
			for s := range o.Sections {
				o.Sections[s].CollectedAt = at
				if o.Sections[s].Name == "software" {
					n := 3 + (i+source)%4 // частичные наборы: записи то появляются, то пропадают
					records := make([]map[string]any, n)
					for p := range records {
						records[p] = map[string]any{"name": fmt.Sprintf("pkg-%d", p), "version": fmt.Sprintf("%d.%d", source, i), "scope": "machine", "source": "uninstall_registry", "registry_view": "64", "registry_key": fmt.Sprintf("k-%d", p)}
					}
					o.Sections[s].Records, o.Sections[s].Count = records, n
					o.Sections[s].Status, o.Sections[s].Complete = "partial", false
				}
			}
			raw, _ := json.Marshal(o)
			payloads = append(payloads, raw)
		}
		report, err := f.registry.ImportPortable(f.ctx, machine, tenant, id, portablePackage(t, key, id, payloads...))
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range report.Records {
			if r.Disposition != "applied" || asset != "" && r.AssetID != asset {
				t.Fatal("all observations must apply to one asset", r, asset)
			}
			asset = r.AssetID
		}
	}
	snapshot := func() string {
		var s string
		if err := f.pool.QueryRow(f.ctx, `SELECT string_agg(x,E'\n' ORDER BY x) FROM (
SELECT section_name||'|'||record_key||'|'||field_name||'|'||value::text||'|'||observation_id::text||'|'||link_id::text x FROM inventory.record_facts12 WHERE tenant_id=$1 AND asset_uid=$2
UNION ALL SELECT 'state|'||section_name||'|'||last_attempt_id::text||'|'||last_status||'|'||clock_uncertain::text FROM inventory.record_section_state12 WHERE tenant_id=$1 AND asset_uid=$2
UNION ALL SELECT 'source|'||section_name||'|'||source_id::text||'|'||last_attempt_id::text||'|'||last_status||'|'||collected_at::text FROM inventory.record_section_source_state12 WHERE tenant_id=$1 AND asset_uid=$2) s`, tenant, asset).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	sequential := snapshot()
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	n, err := f.registry.Inventory.Rebuild(f.ctx, tx, tenant, asset)
	if err != nil || n != 18 {
		t.Fatal(n, err)
	}
	if err = tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if rebuilt := snapshot(); rebuilt != sequential {
		t.Fatalf("rebuild differs from sequential projection:\n--- sequential\n%s\n--- rebuilt\n%s", sequential, rebuilt)
	}
}
