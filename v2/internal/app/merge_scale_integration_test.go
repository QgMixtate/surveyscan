//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/audit"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

// Замер C25.03 на крупных активах (по запросу): SURVEYSCAN_MERGE_SCALE=наблюдений_на_актив:записей_ПО,
// например 250:2000 (порядок стенда: ~250 наблюдений Linux-агента, тысячи пакетов). Без переменной — пропуск.
func TestMergeSplitScale(t *testing.T) {
	spec := os.Getenv("SURVEYSCAN_MERGE_SCALE")
	var observations, packages int
	if _, err := fmt.Sscanf(spec, "%d:%d", &observations, &packages); err != nil || observations < 1 || packages < 1 {
		t.Skip("set SURVEYSCAN_MERGE_SCALE=observations:packages, e.g. 250:2000")
	}
	f := registrySetup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	f.ctx = ctx
	if _, err := f.registry.ConfigureInventoryProtocol12(true); err != nil {
		t.Fatal(err)
	}
	machine := &sources.MachineService{Pool: f.pool, Audit: audit.Store{}}
	load := func(local string) (string, string) {
		pub, key, _ := ed25519.GenerateKey(rand.Reader)
		source, generation := identifier.New(), identifier.New()
		if _, err := machine.RegisterPortable(f.ctx, "console", sources.PortableRegistration{Tenant: tenant, Site: siteID, Scope: scopeID, Source: source, Generation: generation, PublicKey: pub}); err != nil {
			t.Fatal(err)
		}
		mu := contracts.Candidate{Kind: "machine_uuid", Namespace: "linux-machine-id", Value: "4c4c4544-0000-1000-8000-" + identifier.New()[24:]}
		asset := ""
		for start := 1; start <= observations; start += 50 {
			var payloads [][]byte
			for i := start; i < start+50 && i <= observations; i++ {
				o := testObservation12(t, f, strconv.Itoa(i))
				o.Origin = contracts.Origin{SourceID: source, SourceKind: "portable", GenerationID: generation}
				o.Record = contracts.SourceRecord{Namespace: "host", LocalID: local}
				o.Clock = "estimated"
				o.Candidates = []contracts.Candidate{mu}
				for s := range o.Sections {
					if o.Sections[s].Name == "software" {
						records := make([]map[string]any, packages)
						for p := range records {
							records[p] = map[string]any{"name": fmt.Sprintf("pkg-%d", p), "version": fmt.Sprintf("1.%d", i), "scope": "machine", "source": "uninstall_registry", "registry_view": "64", "registry_key": fmt.Sprintf("synthetic-uninstall-%d", p)}
						}
						o.Sections[s].Records, o.Sections[s].Count = records, packages
					}
				}
				raw, _ := json.Marshal(o)
				payloads = append(payloads, raw)
			}
			report, err := f.registry.ImportPortable(f.ctx, machine, tenant, source, portablePackage(t, key, source, payloads...))
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range report.Records {
				if r.Disposition != "applied" {
					t.Fatal(r)
				}
				asset = r.AssetID
			}
		}
		var record string
		if err := f.pool.QueryRow(f.ctx, "SELECT source_record_key::text FROM assets.source_records WHERE tenant_id=$1 AND source_id=$2", tenant, source).Scan(&record); err != nil {
			t.Fatal(err)
		}
		return asset, record
	}
	started := time.Now()
	a1, _ := load("host:scale-a")
	a2, r2 := load("host:scale-b")
	t.Logf("load: 2x%d observations x %d packages in %s", observations, packages, time.Since(started).Round(time.Millisecond))
	started = time.Now()
	res, err := f.registry.MergeAssets(f.ctx, f.identity, app.MergeRequest{Target: a1, Absorbed: a2})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("MERGE: rebuilt=%d relinked=%d in %s", res.Rebuilt, res.Relinked, time.Since(started).Round(time.Millisecond))
	started = time.Now()
	res, err = f.registry.SplitAsset(f.ctx, f.identity, a1, app.SplitRequest{Records: []string{r2}})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("SPLIT: rebuilt=%d relinked=%d in %s", res.Rebuilt, res.Relinked, time.Since(started).Round(time.Millisecond))
}
