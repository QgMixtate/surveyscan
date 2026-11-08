//go:build windows

package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

func TestWindowsStateDirIsPrivateAndLocked(t *testing.T) {
	state := filepath.Join(t.TempDir(), "nested", "state")
	if err := ensureStateDir(state); err != nil {
		t.Fatal("create private state", err)
	}
	if err := ensureStateDir(state); err != nil {
		t.Fatal("existing private state must be accepted", err)
	}
	if err := ensureStateDir(filepath.Join(state, "spool")); err != nil {
		t.Fatal("private spool inside state", err)
	}
	unlock, err := lockState(state)
	if err != nil {
		t.Fatal("state lock", err)
	}
	if _, err = lockState(state); err == nil {
		t.Fatal("second state writer accepted")
	}
	unlock()
	plain := filepath.Join(t.TempDir(), "plain")
	if err = os.MkdirAll(plain, 0700); err != nil {
		t.Fatal(err)
	}
	if ensureStateDir(plain) == nil {
		t.Fatal("directory with an inherited ACL accepted as private state")
	}
}

func TestWindowsPrepareIsStablePrivateAndConfigNeedsPrivateDirectory(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	cfg := Config{State: state}
	first, err := Prepare(cfg)
	if err != nil {
		t.Fatal("prepare on a fresh Windows state", err)
	}
	again, err := Prepare(cfg)
	if err != nil || again != first {
		t.Fatal("second prepare replaced the identity", err)
	}
	tls, err := readKey(filepath.Join(state, "tls.key"))
	if err != nil {
		t.Fatal(err)
	}
	signing, err := readKey(filepath.Join(state, "signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	if string(tls) == string(signing) {
		t.Fatal("TLS and observation keys reused")
	}
	// Конфигурация читается только из приватного каталога (его готовит установщик, C15.03).
	configDir := filepath.Join(t.TempDir(), "config")
	if err = ensureStateDir(configDir); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(Config{Tenant: identifier.New(), Site: identifier.New(), Scope: identifier.New(), CollectorSource: identifier.New(), CollectorURL: "https://collector.invalid", State: state, CA: "ca.pem"})
	configPath := filepath.Join(configDir, "agent.json")
	unlock, err := lockState(configDir)
	if err != nil {
		t.Fatal(err)
	}
	if err = writeAtomic(configPath, body); err != nil {
		t.Fatal(err)
	}
	unlock()
	if loaded, err := ReadConfig(configPath); err != nil || loaded.InventorySeconds != 900 || loaded.HeartbeatSeconds != 60 {
		t.Fatal("config from a private directory rejected or defaults lost", err)
	}
	plain := filepath.Join(t.TempDir(), "plain")
	if err = os.MkdirAll(plain, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(plain, "agent.json"), body, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadConfig(filepath.Join(plain, "agent.json")); err == nil {
		t.Fatal("config from an ordinary directory accepted")
	}
}
