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

// C25.01 вариант Б (решение пользователя R-027): запись другого источника привязывается к существующему активу только
// по единственному надёжному сильному идентификатору; противоречия, заглушки, совпадения только слабых признаков и
// неоднозначность — в очередь разбора (recorded_pending_resolution), без молчаливого склеивания.
func TestCrossSourceStrongIdentifierResolution(t *testing.T) {
	f := registrySetup(t)
	if _, err := f.registry.ConfigureInventoryProtocol12(true); err != nil {
		t.Fatal(err)
	}
	machine := &sources.MachineService{Pool: f.pool, Audit: audit.Store{}}
	importOne := func(local string, candidates ...contracts.Candidate) (string, string, string) {
		pub, key, _ := ed25519.GenerateKey(rand.Reader)
		source, generation := identifier.New(), identifier.New()
		if _, err := machine.RegisterPortable(f.ctx, "console", sources.PortableRegistration{Tenant: tenant, Site: siteID, Scope: scopeID, Source: source, Generation: generation, PublicKey: pub}); err != nil {
			t.Fatal(err)
		}
		o := testObservation12(t, f, "1")
		o.Origin = contracts.Origin{SourceID: source, SourceKind: "portable", GenerationID: generation}
		o.Record = contracts.SourceRecord{Namespace: "host", LocalID: local}
		o.Clock = "estimated"
		o.Candidates = candidates
		raw, _ := json.Marshal(o)
		report, err := f.registry.ImportPortable(f.ctx, machine, tenant, source, portablePackage(t, key, source, raw))
		if err != nil || len(report.Records) != 1 {
			t.Fatal(err, report)
		}
		return report.Records[0].Disposition, report.Records[0].AssetID, report.Records[0].Reason
	}
	uid := func() string { return "4c4c4544-0000-1000-8000-" + identifier.New()[24:] }
	mu := func(v string) contracts.Candidate {
		return contracts.Candidate{Kind: "machine_uuid", Namespace: "linux-machine-id", Value: v}
	}
	bios := func(v string) contracts.Candidate {
		return contracts.Candidate{Kind: "bios_uuid", Namespace: "smbios", Value: v}
	}
	host := func(v string) contracts.Candidate {
		return contracts.Candidate{Kind: "hostname", Namespace: "hostname.raw", Value: v}
	}

	// 1. агент + SSH одной машины: тот же machine_uuid → тот же актив, причина AUTO_STRONG_MATCH, аудит/история
	u1, b1 := uid(), uid()
	d, a1, _ := importOne("host:first", mu(u1), bios(b1), host("srv-1"))
	if d != "applied" || a1 == "" {
		t.Fatal("first source must create an asset", d)
	}
	d, a2, reason := importOne("host:ssh-view", mu(u1), host("srv-1"))
	if d != "applied" || a2 != a1 || reason != "AUTO_STRONG_MATCH" {
		t.Fatalf("same machine_uuid must attach to the existing asset: %s %s %s", d, a2, reason)
	}
	var history int
	if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM assets.asset_changes WHERE tenant_id=$1 AND asset_uid=$2 AND reason_code='AUTO_STRONG_MATCH'", tenant, a1).Scan(&history); err != nil || history != 1 {
		t.Fatal("auto attach must be recorded in asset history", history, err)
	}
	// 2. противоречие: тот же machine_uuid, но другой bios_uuid у актива → конфликт (клон)
	if d, a, _ := importOne("host:clone", mu(u1), bios(uid())); d != "recorded_pending_resolution" || a != "" {
		t.Fatal("contradicting strong identifier must go to the review queue", d, a)
	}
	// 3. заглушка serial не сводит
	if d, a, _ := importOne("host:oem-a", contracts.Candidate{Kind: "serial", Namespace: "smbios", Value: "To be filled by O.E.M."}); d != "applied" || a == "" {
		t.Fatal("first placeholder host creates its own asset", d)
	}
	if d, a, _ := importOne("host:oem-b", contracts.Candidate{Kind: "serial", Namespace: "smbios", Value: "To be filled by O.E.M."}); d != "recorded_pending_resolution" || a != "" {
		t.Fatal("placeholder serial must not auto-attach", d, a)
	}
	// 4. только слабый признак (hostname) — очередь
	if d, a, _ := importOne("host:weak", host("srv-1")); d != "recorded_pending_resolution" || a != "" {
		t.Fatal("weak-only match must go to the review queue", d, a)
	}
	// 6. сценарий стенда: запись SSH/WinRM уже в конфликте без актива; следующее наблюдение того же источника
	// приносит machine_uuid → авто-привязка, открытые конфликты записи закрываются
	{
		pub, key, _ := ed25519.GenerateKey(rand.Reader)
		source, generation := identifier.New(), identifier.New()
		if _, err := machine.RegisterPortable(f.ctx, "console", sources.PortableRegistration{Tenant: tenant, Site: siteID, Scope: scopeID, Source: source, Generation: generation, PublicKey: pub}); err != nil {
			t.Fatal(err)
		}
		send := func(seq string, c ...contracts.Candidate) (string, string) {
			o := testObservation12(t, f, seq)
			o.Origin = contracts.Origin{SourceID: source, SourceKind: "portable", GenerationID: generation}
			o.Record = contracts.SourceRecord{Namespace: "host", LocalID: "host:winrm-view"}
			o.Clock = "estimated"
			o.Candidates = c
			raw, _ := json.Marshal(o)
			r, err := f.registry.ImportPortable(f.ctx, machine, tenant, source, portablePackage(t, key, source, raw))
			if err != nil || len(r.Records) != 1 {
				t.Fatal(err, r)
			}
			return r.Records[0].Disposition, r.Records[0].AssetID
		}
		if d, a := send("1", host("srv-1")); d != "recorded_pending_resolution" || a != "" {
			t.Fatal("weak-only first observation must be pending", d)
		}
		if d, a := send("2", mu(u1), host("srv-1")); d != "applied" || a != a1 {
			t.Fatal("pending record must auto-attach once a strong identifier arrives", d, a)
		}
		var open int
		if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM assets.reconciliation_conflicts c JOIN assets.source_records r USING(tenant_id,source_record_key) WHERE c.tenant_id=$1 AND r.source_id=$2 AND c.state='open'", tenant, source).Scan(&open); err != nil || open != 0 {
			t.Fatal("open conflicts of the attached record must be resolved", open, err)
		}
	}
	// 5. сильное совпадение с одним активом, слабое — с другим → неоднозначно, очередь
	u3 := uid()
	if d, _, _ := importOne("host:other", mu(u3), host("srv-other")); d != "applied" {
		t.Fatal("other asset", d)
	}
	if d, a, _ := importOne("host:mixed", mu(u3), host("srv-1")); d != "recorded_pending_resolution" || a != "" {
		t.Fatal("ambiguous strong/weak matches must go to the review queue", d, a)
	}
}
