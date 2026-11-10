//go:build integration

package app_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/audit"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/portable"
)

// portableObservation — наблюдение 1.2 portable-источника (секции из фикстуры C15, partial, не новее наблюдения).
func portableObservation(t *testing.T, f *registryFixture, source, generation, local, seq string) []byte {
	t.Helper()
	o := testObservation12(t, f, seq)
	o.Origin = contracts.Origin{SourceID: source, SourceKind: "portable", GenerationID: generation}
	o.Record = contracts.SourceRecord{Namespace: "host", LocalID: local}
	o.Clock = "estimated"
	raw, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func portablePackage(t *testing.T, key ed25519.PrivateKey, source string, payloads ...[]byte) []byte {
	t.Helper()
	signed := [][]byte{}
	for _, p := range payloads {
		so, err := portable.SignObservation(key, p)
		if err != nil {
			t.Fatal(err)
		}
		signed = append(signed, so)
	}
	var buf bytes.Buffer
	if err := portable.Write(&buf, key, tenant, source, time.Now(), signed); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func countObservations(t *testing.T, f *registryFixture, source string) int {
	var n int
	if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM inventory.observations WHERE tenant_id=$1 AND source_id=$2", tenant, source).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestC23PortableRegisterAndImport(t *testing.T) {
	f := registrySetup(t)
	if _, err := f.registry.ConfigureInventoryProtocol12(true); err != nil {
		t.Fatal(err)
	}
	machine := &sources.MachineService{Pool: f.pool, Audit: audit.Store{}}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	source, generation := identifier.New(), identifier.New()
	reg := sources.PortableRegistration{Tenant: tenant, Site: siteID, Scope: scopeID, Source: source, Generation: generation, PublicKey: pub}

	keyID, err := machine.RegisterPortable(f.ctx, "console", reg)
	if err != nil || keyID != portable.KeyID(pub) {
		t.Fatal("register:", keyID, err)
	}
	if _, err = machine.RegisterPortable(f.ctx, "console", reg); err != nil {
		t.Fatal("identical re-registration must be idempotent:", err)
	}
	otherPub, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	if _, err = machine.RegisterPortable(f.ctx, "console", sources.PortableRegistration{Tenant: tenant, Site: siteID, Scope: scopeID, Source: source, Generation: identifier.New(), PublicKey: otherPub}); !errors.Is(err, domain.Conflict) {
		t.Fatal("another generation for the same source must conflict:", err)
	}

	pkg := portablePackage(t, key, source,
		portableObservation(t, f, source, generation, "host:audited-host", "1"),
		portableObservation(t, f, source, generation, "host:audited-host", "2"))
	report, err := f.registry.ImportPortable(f.ctx, machine, tenant, source, pkg)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Records) != 2 {
		t.Fatalf("%+v", report)
	}
	for _, r := range report.Records {
		if r.Disposition == "rejected" || r.Disposition == "quarantined" || r.AssetID == "" {
			t.Fatalf("record must be applied to an asset: %+v", r)
		}
	}
	if n := countObservations(t, f, source); n != 2 {
		t.Fatal("observations stored:", n)
	}
	// факты спроецированы сразу при импорте и видны через API чтения записей 1.2 и сводку источников актива
	asset := report.Records[0].AssetID
	page, err := f.registry.InventoryRecordFacts(f.ctx, f.identity, asset, "hardware", "", 50)
	if err != nil || len(page.Items) == 0 {
		t.Fatal("portable facts must be readable for the asset card:", err, len(page.Items))
	}
	for _, it := range page.Items {
		if it.Evidence.Origin.SourceID != source || it.Evidence.Origin.SourceKind != "portable" || it.Evidence.Observation == "" {
			t.Fatalf("each fact must carry its portable origin: %+v", it.Evidence)
		}
	}
	// Известный общий пробел (не portable): сводка источников карточки C09 строится только из проекции 1.0,
	// поэтому источники данных профиля 1.2 (агенты и portable) в ней не перечислены. Фиксируем текущее поведение.
	if card := detail(t, f, asset); len(card.Sources) != 0 {
		t.Log("C09 card now lists 1.2 sources — update this test and the journal:", card.Sources)
	}

	// повторная загрузка того же пакета (обрыв/повтор) не дублирует наблюдения
	again, err := f.registry.ImportPortable(f.ctx, machine, tenant, source, pkg)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range again.Records {
		if r.Disposition == "rejected" || r.Disposition == "quarantined" {
			t.Fatalf("re-import must be idempotent, got %+v", r)
		}
	}
	if n := countObservations(t, f, source); n != 2 {
		t.Fatal("re-import duplicated observations:", n)
	}

	// пакет, подписанный незарегистрированным ключом, отвергается целиком
	foreign := portablePackage(t, otherKey, source, portableObservation(t, f, source, generation, "host:x", "3"))
	if _, err = f.registry.ImportPortable(f.ctx, machine, tenant, source, foreign); err == nil {
		t.Fatal("foreign key package must be refused")
	}
	// незарегистрированный источник
	if _, err = f.registry.ImportPortable(f.ctx, machine, tenant, identifier.New(), pkg); !errors.Is(err, domain.NotFound) {
		t.Fatal("unknown portable source must be refused:", err)
	}
	if n := countObservations(t, f, source); n != 2 {
		t.Fatal("refused packages must not store anything:", n)
	}
	var audits int
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM audit.audit_events WHERE tenant_id=$1 AND action='source.portable_registered' AND object_id=$2", tenant, source).Scan(&audits); err != nil || audits < 1 {
		t.Fatal("registration must be audited", audits, err)
	}
	_ = app.PortableReport{}
}
