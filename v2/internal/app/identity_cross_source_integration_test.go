//go:build integration

package app_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/audit"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

// Фиксация текущего поведения E1 (C02 §3): второй источник с тем же сильным идентификатором (machine_uuid)
// НЕ склеивается автоматически с существующим активом — запись уходит в конфликт до ручного разбора (C25).
func TestCrossSourceStrongIdentifierGoesToConflict(t *testing.T) {
	f := registrySetup(t)
	if _, err := f.registry.ConfigureInventoryProtocol12(true); err != nil {
		t.Fatal(err)
	}
	machine := &sources.MachineService{Pool: f.pool, Audit: audit.Store{}}
	uuid := "4c4c4544-0000-1000-8000-" + identifier.New()[24:]
	importOne := func(local string) (string, string) {
		pub, key, _ := ed25519.GenerateKey(rand.Reader)
		source, generation := identifier.New(), identifier.New()
		if _, err := machine.RegisterPortable(f.ctx, "console", sources.PortableRegistration{Tenant: tenant, Site: siteID, Scope: scopeID, Source: source, Generation: generation, PublicKey: pub}); err != nil {
			t.Fatal(err)
		}
		o := testObservation12(t, f, "1")
		o.Origin = contracts.Origin{SourceID: source, SourceKind: "portable", GenerationID: generation}
		o.Record = contracts.SourceRecord{Namespace: "host", LocalID: local}
		o.Clock = "estimated"
		o.Candidates = []contracts.Candidate{{Kind: "machine_uuid", Namespace: "linux-machine-id", Value: uuid}}
		raw, _ := json.Marshal(o)
		report, err := f.registry.ImportPortable(f.ctx, machine, tenant, source, portablePackage(t, key, source, raw))
		if err != nil || len(report.Records) != 1 {
			t.Fatal(err, report)
		}
		return report.Records[0].Disposition, report.Records[0].AssetID
	}
	d1, a1 := importOne("host:first")
	d2, a2 := importOne("host:second")
	t.Logf("first=%s/%s second=%s/%s", d1, a1, d2, a2)
	if d1 != "applied" || a1 == "" {
		t.Fatal("first source must create an asset")
	}
	if d2 != "recorded_pending_resolution" || a2 != "" {
		t.Fatal("second source with the same machine_uuid must go to a reconciliation conflict, got", d2, a2)
	}
}
