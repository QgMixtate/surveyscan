package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestHostBindingRejectsCloneAndWrongSigningKey(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	binding := bindingValue("source", "machine-A", key)
	if e := verifyBindingValue(binding, "source", "machine-A", key); e != nil {
		t.Fatal(e)
	}
	for _, check := range []struct {
		source, id string
		key        ed25519.PrivateKey
	}{{"source", "machine-B", key}, {"replacement-source", "machine-A", key}, {"source", "machine-A", other}} {
		if e := verifyBindingValue(binding, check.source, check.id, check.key); e == nil {
			t.Fatal("copied state accepted different host/source/signing key")
		}
	}
	cfg := Config{State: t.TempDir()}
	prep, e := Prepare(cfg)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(cfg.State, "host-binding.json"))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(cfg.State, "host-binding.json"), []byte(`{"version":1,"digest":"00"}`), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = Prepare(cfg); e == nil {
		t.Fatal("prepare silently rebound cloned state")
	}
	if _, e = Open(cfg); e == nil {
		t.Fatal("cloned state startup succeeded")
	}
	if e = os.WriteFile(filepath.Join(cfg.State, "host-binding.json"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	again, e := Prepare(cfg)
	if e != nil || again != prep {
		t.Fatal("original host/source identity changed", e)
	}
}
func TestMissingHostBindingRequiresExplicitLegacyAdoption(t *testing.T) {
	cfg := Config{State: t.TempDir()}
	_, e := Prepare(cfg)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(filepath.Join(cfg.State, "host-binding.json")); e != nil {
		t.Fatal(e)
	}
	if _, e = Prepare(cfg); e == nil {
		t.Fatal("legacy preparation silently adopted machine")
	}
	if _, e = Open(cfg); e == nil {
		t.Fatal("unbound legacy state started")
	}
	if _, e = os.Stat(filepath.Join(cfg.State, "host-binding.json")); !os.IsNotExist(e) {
		t.Fatal("refused startup wrote host binding")
	}
}
