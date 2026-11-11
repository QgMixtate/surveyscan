//go:build integration

package app_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/audit"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/cmdb"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

// C26.04 — большие списки (2000 установок ПО на актив, 120 сервисов) через курсор без пропусков и повторов,
// повтор outbox после изменений CMDB до версий активов, история связей при слиянии.
func TestC2604LargeListsEventsAndHistory(t *testing.T) {
	f := registrySetup(t)
	if _, err := f.registry.ConfigureInventoryProtocol12(true); err != nil {
		t.Fatal(err)
	}
	machine := &sources.MachineService{Pool: f.pool, Audit: audit.Store{}}
	load := func(local string, packages int) string {
		pub, key, _ := ed25519.GenerateKey(rand.Reader)
		source, generation := identifier.New(), identifier.New()
		if _, err := machine.RegisterPortable(f.ctx, "console", sources.PortableRegistration{Tenant: tenant, Site: siteID, Scope: scopeID, Source: source, Generation: generation, PublicKey: pub}); err != nil {
			t.Fatal(err)
		}
		o := testObservation12(t, f, "1")
		o.Origin = contracts.Origin{SourceID: source, SourceKind: "portable", GenerationID: generation}
		o.Record = contracts.SourceRecord{Namespace: "host", LocalID: local}
		o.Clock = "estimated"
		o.Candidates = []contracts.Candidate{{Kind: "machine_uuid", Namespace: "linux-machine-id", Value: "4c4c4544-0000-1000-8000-" + identifier.New()[24:]}}
		for i := range o.Sections {
			if o.Sections[i].Name == "software" {
				records := make([]map[string]any, packages)
				for p := range records {
					// имена с одинаковыми префиксами и регистрами — проверка устойчивой сортировки
					records[p] = map[string]any{"name": fmt.Sprintf("%s-%04d", []string{"lib", "Lib", "LIB"}[p%3], p), "version": "1", "scope": "machine", "source": "uninstall_registry", "registry_view": "64", "registry_key": fmt.Sprintf("k-%05d", p)}
				}
				o.Sections[i].Records, o.Sections[i].Count = records, packages
			}
		}
		raw, _ := json.Marshal(o)
		report, err := f.registry.ImportPortable(f.ctx, machine, tenant, source, portablePackage(t, key, source, raw))
		if err != nil || len(report.Records) != 1 || report.Records[0].Disposition != "applied" {
			t.Fatal(err, report)
		}
		return report.Records[0].AssetID
	}
	a, b := load("host:large-a", 2000), load("host:large-b", 5)

	// 1. 2000 установок ПО — страницы по 500 (максимум), без пропусков и повторов
	seen, cursor, pages := map[string]bool{}, "", 0
	for {
		page, err := f.registry.AssetSoftware(f.ctx, f.identity, a, "", cursor, 500)
		if err != nil {
			t.Fatal(err)
		}
		pages++
		for _, i := range page.Items {
			if seen[i.RecordKey] {
				t.Fatal("duplicate across pages", i.RecordKey)
			}
			seen[i.RecordKey] = true
		}
		if page.NextCursor == nil {
			break
		}
		cursor = *page.NextCursor
	}
	if len(seen) != 2000 || pages != 4 {
		t.Fatal("large software list", len(seen), pages)
	}

	// 2. 120 сервисов — страницы по 50, без пропусков и повторов; у части — связи с активами
	created := map[string]bool{}
	var first app.ServiceDetail
	for i := range 120 {
		name := fmt.Sprintf("Сервис %03d", i)
		s, err := f.registry.CreateService(f.ctx, f.identity, cmdb.ServiceInput{Name: &name})
		if err != nil {
			t.Fatal(err)
		}
		created[s.UID] = true
		if i == 0 {
			first = s
		}
		if i < 3 {
			if _, err = f.registry.CreateRelation(f.ctx, f.identity, cmdb.RelationInput{Type: "runs_on", From: cmdb.End{Kind: "service", ID: s.UID}, To: cmdb.End{Kind: "asset", ID: b}}); err != nil {
				t.Fatal(err)
			}
		}
	}
	listed, cursor := 0, ""
	for {
		page, err := f.registry.Services(f.ctx, f.identity, cursor, 50, false)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range page.Items {
			if !created[s.UID] {
				t.Fatal("unknown or repeated service", s.UID)
			}
			delete(created, s.UID)
			listed++
		}
		if page.NextCursor == nil {
			break
		}
		cursor = *page.NextCursor
	}
	if listed != 120 || len(created) != 0 {
		t.Fatal("service pagination", listed, len(created))
	}

	// 3. слияние b → a: связи переезжают, история модуля фиксирует перенос
	if _, err := f.registry.MergeAssets(f.ctx, f.identity, app.MergeRequest{Target: a, Absorbed: b}); err != nil {
		t.Fatal(err)
	}
	card, err := f.registry.AssetCMDB(f.ctx, f.identity, a)
	if err != nil || len(card.Relations) != 3 {
		t.Fatal("relations after merge", len(card.Relations), err)
	}
	var retargeted int
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM cmdb.changes WHERE tenant_id=$1 AND action='retargeted' AND detail->>'from_asset_uid'=$2", tenant, b).Scan(&retargeted)
	if retargeted != 3 {
		t.Fatal("retarget history", retargeted)
	}
	detail, err := f.registry.ServiceDetail(f.ctx, f.identity, first.UID)
	if err != nil || len(detail.Relations) != 1 || detail.Relations[0].To.ID != a {
		t.Fatal("service sees the canonical asset", detail.Relations, err)
	}

	// 4. повтор outbox: события смены связей и слияния доходят до версий активов
	for range 100000 {
		worked, err := f.registry.ConsumeOne(f.ctx, tenant)
		if err != nil {
			t.Fatal(err)
		}
		if !worked {
			break
		}
	}
	var lagging int
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM assets.assets a LEFT JOIN assets.consumer_versions c USING(tenant_id,asset_uid) WHERE a.tenant_id=$1 AND c.aggregate_version IS DISTINCT FROM a.aggregate_version", tenant).Scan(&lagging)
	if lagging != 0 {
		t.Fatal("consumer versions lag after replay", lagging)
	}
}
