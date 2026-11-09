//go:build integration

package app_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/migrate"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

// Real PG and registered enrollment fingerprints; this service-level test is
// distinct from actual compiled TLS/Transit profile relay in the smoke harness.
func TestC15InventoryProfileSeparateProgressAndOriginProof(t *testing.T) {
	u := uploadSetup(t)
	f := u.f
	var collector string
	if err := f.pool.QueryRow(f.ctx, "SELECT collector_id::text FROM sources.collectors WHERE tenant_id=$1 AND source_id=$2", tenant, u.source).Scan(&collector); err != nil {
		t.Fatal(err)
	}
	public, key, _ := ed25519.GenerateKey(rand.Reader)
	csr, hash, _, _ := csrTLSMaterial(t)
	source := identifier.New()
	grant, err := u.sources.Grant(f.ctx, f.identity, contracts.EnrollmentGrantRequest{TenantID: tenant, SourceID: source, Kind: "agent", SiteID: siteID, CollectorID: &collector, TTL: 900, CSRHash: hash, PublicKey: base64.RawURLEncoding.EncodeToString(public)})
	if err != nil {
		t.Fatal(err)
	}
	enrolled, err := u.sources.Enroll(f.ctx, grant.Token, contracts.EnrollmentRequest{GrantID: grant.ID, SourceID: source, CSR: csr, PublicKey: base64.RawURLEncoding.EncodeToString(public)})
	if err != nil {
		t.Fatal(err)
	}
	origin := contracts.Origin{SourceID: source, SourceKind: "agent", GenerationID: enrolled.GenerationID}
	request := func(applied *contracts.InventoryRevision12) []byte {
		t.Helper()
		nonce, _ := wire.NewInventoryNonce()
		raw, err := wire.SignInventoryProfile12(contracts.InventoryProfileRequest12{Version: contracts.Version{Major: 1, Minor: 2}, Tenant: tenant, Origin: origin, Nonce: nonce, Sent: time.Now().UTC(), Platform: contracts.InventoryPlatform12, Applied: applied}, wire.InventoryProfileRequestDomain12, enrolled.KeyID, key)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	revision := &contracts.InventoryRevision12{Common: "1", Policy: contracts.InventoryPolicy12}
	if _, err = u.sources.PollInventoryProfile12(f.ctx, u.fingerprint, request(revision)); !errors.Is(err, domain.Invalid) {
		t.Fatal("unoffered revision application accepted", err)
	}
	first, err := u.sources.PollInventoryProfile12(f.ctx, u.fingerprint, request(nil))
	if err != nil || first.Managed || first.Config.CollectionSeconds != 420 || first.Config.WorkerSeconds != 30 || len(first.Config.Sections) != 12 {
		t.Fatal("first profile", err)
	}
	view, err := u.sources.InventoryProfile12View(f.ctx, f.identity, source)
	if err != nil || view.Applied != nil || view.LastContact == nil {
		t.Fatal("offer incorrectly marked applied", err)
	}
	if _, err = u.sources.PollInventoryProfile12(f.ctx, u.fingerprint, request(revision)); err != nil {
		t.Fatal(err)
	}
	options := contracts.ProfileOptions{Heartbeat: 30, Inventory: 120, Jitter: 10, SpoolBytes: 524288}
	if _, err = u.sources.UpdateProfile(f.ctx, f.identity, source, "1", options); err != nil {
		t.Fatal(err)
	}
	second, err := u.sources.PollInventoryProfile12(f.ctx, u.fingerprint, request(revision))
	if err != nil || !second.Managed || second.Config.Revision != "2" || second.Config.Inventory != 120 || second.Config.Limits.BatchBytes > 524288-65536-4096 {
		t.Fatal("common cadence/profile budget diverged", err)
	}
	future := &contracts.InventoryRevision12{Common: "3", Policy: contracts.InventoryPolicy12}
	if _, err = u.sources.PollInventoryProfile12(f.ctx, u.fingerprint, request(future)); !errors.Is(err, domain.Invalid) {
		t.Fatal("future revision accepted", err)
	}
	revision.Common = "2"
	if _, err = u.sources.PollInventoryProfile12(f.ctx, u.fingerprint, request(revision)); err != nil {
		t.Fatal(err)
	}
	revision.Common = "1"
	if _, err = u.sources.PollInventoryProfile12(f.ctx, u.fingerprint, request(revision)); err != nil {
		t.Fatal(err)
	}
	view, err = u.sources.InventoryProfile12View(f.ctx, f.identity, source)
	if err != nil || view.Applied == nil || view.Applied.Common != "2" {
		t.Fatal("application progress rolled back", err)
	}
	var count int
	for _, query := range []string{"SELECT count(*) FROM sources.profile_progress", "SELECT count(*) FROM sources.heartbeat_state", "SELECT count(*) FROM sources.inventory_progress", "SELECT count(*) FROM sources.runtime_diagnostics", "SELECT count(*) FROM inventory.observations"} {
		if err = f.pool.QueryRow(f.ctx, query).Scan(&count); err != nil || count != 0 {
			t.Fatal("profile polluted other freshness/progress", err)
		}
	}
	bad := request(nil)
	bad[len(bad)-8] ^= 1
	if _, err = u.sources.PollInventoryProfile12(f.ctx, u.fingerprint, bad); err == nil {
		t.Fatal("forged frame accepted")
	}
	if _, err = u.sources.InventoryProfile12View(f.ctx, f.identity, identifier.New()); !errors.Is(err, domain.NotFound) {
		t.Fatal("unknown agent detail leaked", err)
	}
	if _, err = f.pool.Exec(f.ctx, "UPDATE sources.sources SET state='revoked' WHERE tenant_id=$1 AND source_id=$2", tenant, source); err != nil {
		t.Fatal(err)
	}
	if _, err = u.sources.PollInventoryProfile12(f.ctx, u.fingerprint, request(nil)); !errors.Is(err, domain.Unauthorized) {
		t.Fatal("revoked agent profile issued", err)
	}
}

func TestC15PlatformMigrationPreservesExistingCatalogAndData(t *testing.T) {
	ctx, c, current := database(t)
	old := []migrate.Migration{}
	for _, m := range current {
		if m.ID != "0035_inventory_platform" {
			old = append(old, m)
		}
	}
	if len(old) != 35 || len(current) != 36 {
		t.Fatal("unexpected catalogs")
	}
	apply(t, ctx, c, old)
	const snapshot = `SELECT jsonb_agg(to_jsonb(m) ORDER BY id)::text FROM platform.schema_migrations m WHERE id<>'0035_inventory_platform'`
	var before, after string
	if err := c.QueryRow(ctx, snapshot).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if n, err := migrate.Apply(ctx, c, current); err != nil || n != 1 {
		t.Fatal("not one append", n, err)
	}
	if err := c.QueryRow(ctx, snapshot).Scan(&after); err != nil || before != after {
		t.Fatal("old SQL ledger mutated", err)
	}
	if n, err := migrate.Apply(ctx, c, current); err != nil || n != 0 {
		t.Fatal("repeat not noop", n, err)
	}
	if err := migrate.Check(ctx, c, old); !errors.Is(err, migrate.ErrDrift) {
		t.Fatal("old binary accepts new schema", err)
	}
}

// Платформа источника фиксируется при регистрации: Linux-агент получает Linux-политику,
// запрос с другой платформой отвергается, по умолчанию (поле не задано) остаётся Windows.
func TestC15ProfilePlatformComesFromRegistration(t *testing.T) {
	u := uploadSetup(t)
	f := u.f
	var collector string
	if err := f.pool.QueryRow(f.ctx, "SELECT collector_id::text FROM sources.collectors WHERE tenant_id=$1 AND source_id=$2", tenant, u.source).Scan(&collector); err != nil {
		t.Fatal(err)
	}
	type agentKey struct {
		key ed25519.PrivateKey
		id  string
	}
	enroll := func(platform string) (string, contracts.Origin, agentKey) {
		t.Helper()
		public, key, _ := ed25519.GenerateKey(rand.Reader)
		csr, hash, _, _ := csrTLSMaterial(t)
		source := identifier.New()
		encoded := base64.RawURLEncoding.EncodeToString(public)
		grant, err := u.sources.Grant(f.ctx, f.identity, contracts.EnrollmentGrantRequest{TenantID: tenant, SourceID: source, Kind: "agent", SiteID: siteID, CollectorID: &collector, TTL: 900, CSRHash: hash, PublicKey: encoded, InventoryPlatform: platform})
		if err != nil {
			t.Fatal(platform, err)
		}
		enrolled, err := u.sources.Enroll(f.ctx, grant.Token, contracts.EnrollmentRequest{GrantID: grant.ID, SourceID: source, CSR: csr, PublicKey: encoded})
		if err != nil {
			t.Fatal(err)
		}
		return source, contracts.Origin{SourceID: source, SourceKind: "agent", GenerationID: enrolled.GenerationID}, agentKey{key, enrolled.KeyID}
	}
	poll := func(origin contracts.Origin, key agentKey, platform string) (contracts.InventoryProfile12, error) {
		t.Helper()
		nonce, _ := wire.NewInventoryNonce()
		raw, err := wire.SignInventoryProfile12(contracts.InventoryProfileRequest12{Version: contracts.Version{Major: 1, Minor: 2}, Tenant: tenant, Origin: origin, Nonce: nonce, Sent: time.Now().UTC(), Platform: platform}, wire.InventoryProfileRequestDomain12, key.id, key.key)
		if err != nil {
			t.Fatal(err)
		}
		return u.sources.PollInventoryProfile12(f.ctx, u.fingerprint, raw)
	}
	linuxSource, linuxOrigin, linuxKey := enroll(contracts.InventoryPlatformLinux12)
	got, err := poll(linuxOrigin, linuxKey, contracts.InventoryPlatformLinux12)
	if err != nil || got.Config.Platform != contracts.InventoryPlatformLinux12 || got.Config.Policy != contracts.InventoryPolicyLinux12 {
		t.Fatal("linux profile", err, got.Config.Platform, got.Config.Policy)
	}
	if _, err = poll(linuxOrigin, linuxKey, contracts.InventoryPlatform12); !errors.Is(err, domain.Invalid) {
		t.Fatal("platform mismatch accepted", err)
	}
	view, err := u.sources.InventoryProfile12View(f.ctx, f.identity, linuxSource)
	if err != nil || view.Config.Platform != contracts.InventoryPlatformLinux12 {
		t.Fatal("linux view", err)
	}
	_, winOrigin, winKey := enroll("") // поле не задано — прежнее поведение
	got, err = poll(winOrigin, winKey, contracts.InventoryPlatform12)
	if err != nil || got.Config.Platform != contracts.InventoryPlatform12 || got.Config.Policy != contracts.InventoryPolicy12 {
		t.Fatal("default windows profile", err)
	}
	if _, err = poll(winOrigin, winKey, contracts.InventoryPlatformLinux12); !errors.Is(err, domain.Invalid) {
		t.Fatal("windows source accepted linux request", err)
	}
	// Неизвестная платформа в заявке на регистрацию отвергается до записи.
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	_, hash, _, _ := csrTLSMaterial(t)
	if _, err = u.sources.Grant(f.ctx, f.identity, contracts.EnrollmentGrantRequest{TenantID: tenant, SourceID: identifier.New(), Kind: "agent", SiteID: siteID, CollectorID: &collector, TTL: 900, CSRHash: hash, PublicKey: base64.RawURLEncoding.EncodeToString(public), InventoryPlatform: "darwin/arm64"}); !errors.Is(err, domain.Invalid) {
		t.Fatal("unknown platform accepted", err)
	}
}
