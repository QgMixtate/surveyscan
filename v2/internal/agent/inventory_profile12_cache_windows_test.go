//go:build windows

package agent

import (
	"path/filepath"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/diskspool"
)

func TestWindowsProfileCacheThroughPrivateAdapters(t *testing.T) {
	f := newProfileCacheFixture(t)
	dir := filepath.Join(t.TempDir(), "state")
	// Lock создаёт каталог как приватный корень (DACL, без reparse) и берёт блокировку писателя.
	unlock, err := diskspool.Lock(dir)
	if err != nil {
		t.Fatal("private state root", err)
	}
	defer unlock()
	if err = commitInventoryProfile12(dir, f.signed(t, "2", 30), f.scope); err != nil {
		t.Fatal("commit through adapters", err)
	}
	p, _, present, err := loadInventoryProfile12(dir, f.scope)
	if err != nil || !present || p.Config.Revision != "2" {
		t.Fatal("offline load of an expired profile", present, err)
	}
	if err = commitInventoryProfile12(dir, f.signed(t, "1", 30), f.scope); err == nil {
		t.Fatal("older revision replaced the cache")
	}
	applied, err := appliedFromCache(dir, f.scope)
	if err != nil || applied == nil || applied.Common != "2" {
		t.Fatal("applied revision not taken from durable cache", err)
	}
	unlock()
	if commitInventoryProfile12(dir, f.signed(t, "3", 30), f.scope) == nil {
		t.Fatal("cache written without the writer lock")
	}
	if p, _, present, err = loadInventoryProfile12(dir, f.scope); err != nil || !present || p.Config.Revision != "2" {
		t.Fatal("state changed after unlocked write attempt", err)
	}
}
