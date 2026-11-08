package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

type profileCacheFixture struct {
	scope profileScope12
	key   ed25519.PrivateKey
}

func newProfileCacheFixture(t *testing.T) profileCacheFixture {
	t.Helper()
	public, key, _ := ed25519.GenerateKey(rand.Reader)
	source, collector := identifier.New(), identifier.New()
	return profileCacheFixture{key: key, scope: profileScope12{Tenant: identifier.New(), Collector: collector, KeyID: identifier.New(), Public: public,
		Origin: contracts.Origin{SourceID: source, SourceKind: "agent", GenerationID: identifier.New()}}}
}

// signed возвращает профиль, подписанный в прошлом: срок уже истёк, как при офлайн-старте.
func (f profileCacheFixture) signed(t *testing.T, revision string, heartbeat int) InventoryProfileSelection12 {
	t.Helper()
	collector := f.scope.Collector
	config, err := wire.InventoryConfigFromCommon12(contracts.MachineConfig{SourceID: f.scope.Origin.SourceID, CollectorID: &collector, Revision: revision, Heartbeat: heartbeat, Inventory: 60, Jitter: 10, SpoolBytes: 524288})
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := wire.NewInventoryNonce()
	issued := time.Now().UTC().Add(-time.Hour)
	p := contracts.InventoryProfile12{Version: contracts.Version{Major: 1, Minor: 2}, Tenant: f.scope.Tenant, Origin: f.scope.Origin, Nonce: nonce, Issued: issued, Expires: issued.Add(2 * time.Minute), Managed: revision != "1", Config: config}
	raw, err := wire.SignInventoryProfile12(p, wire.InventoryProfileResponseDomain12, f.scope.KeyID, f.key)
	if err != nil {
		t.Fatal(err)
	}
	return InventoryProfileSelection12{Profile: p, Raw: raw}
}

func TestInventoryProfile12CacheSurvivesExpiryAndRestart(t *testing.T) {
	f := newProfileCacheFixture(t)
	dir := t.TempDir()
	if _, _, present, err := loadInventoryProfile12(dir, f.scope); err != nil || present {
		t.Fatal("empty cache must be absence", present, err)
	}
	sel := f.signed(t, "2", 30)
	if err := commitInventoryProfile12(dir, sel, f.scope); err != nil {
		t.Fatal(err)
	}
	p, raw, present, err := loadInventoryProfile12(dir, f.scope)
	if err != nil || !present || p.Config.Revision != "2" || string(raw) != string(sel.Raw) {
		t.Fatal("offline load of an expired but signed profile", err)
	}
	if !p.Expires.Before(time.Now()) {
		t.Fatal("fixture must be expired to prove offline acceptance")
	}
}

func TestInventoryProfile12CacheRejectsScopeKeyAndTamper(t *testing.T) {
	f := newProfileCacheFixture(t)
	dir := t.TempDir()
	if err := commitInventoryProfile12(dir, f.signed(t, "2", 30), f.scope); err != nil {
		t.Fatal(err)
	}
	mutate := map[string]func(profileScope12) profileScope12{
		"generation changed": func(s profileScope12) profileScope12 { s.Origin.GenerationID = identifier.New(); return s },
		"tenant changed":     func(s profileScope12) profileScope12 { s.Tenant = identifier.New(); return s },
		"collector changed":  func(s profileScope12) profileScope12 { s.Collector = identifier.New(); return s },
		"key id changed":     func(s profileScope12) profileScope12 { s.KeyID = identifier.New(); return s },
		"other public key": func(s profileScope12) profileScope12 {
			s.Public, _, _ = ed25519.GenerateKey(rand.Reader)
			return s
		},
	}
	for name, change := range mutate {
		if _, _, _, err := loadInventoryProfile12(dir, change(f.scope)); err == nil {
			t.Fatal("cache accepted", name)
		}
	}
	path := filepath.Join(dir, profileCacheFile12)
	data, _ := os.ReadFile(path)
	data[len(data)/2] ^= 0x01
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := loadInventoryProfile12(dir, f.scope); err == nil {
		t.Fatal("tampered cache accepted")
	}
}

func TestInventoryProfile12CacheRevisionIsMonotonic(t *testing.T) {
	f := newProfileCacheFixture(t)
	dir := t.TempDir()
	if err := commitInventoryProfile12(dir, f.signed(t, "3", 30), f.scope); err != nil {
		t.Fatal(err)
	}
	if err := commitInventoryProfile12(dir, f.signed(t, "2", 30), f.scope); err == nil {
		t.Fatal("older revision replaced a newer cache")
	}
	if err := commitInventoryProfile12(dir, f.signed(t, "3", 45), f.scope); err == nil {
		t.Fatal("same revision with different config accepted")
	}
	if err := commitInventoryProfile12(dir, f.signed(t, "3", 30), f.scope); err != nil {
		t.Fatal("identical re-commit must be idempotent", err)
	}
	if err := commitInventoryProfile12(dir, f.signed(t, "4", 45), f.scope); err != nil {
		t.Fatal("newer revision rejected", err)
	}
	p, _, _, err := loadInventoryProfile12(dir, f.scope)
	if err != nil || p.Config.Revision != "4" || p.Config.Heartbeat != 45 {
		t.Fatal("latest revision not stored", err)
	}
}
