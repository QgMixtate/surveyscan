package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/remote/sshlinux"
)

func writePrivate(t *testing.T, dir, name, text string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadSSHTargetValidation(t *testing.T) {
	if os.Getenv("GOOS") == "windows" {
		t.Skip("POSIX permissions")
	}
	dir := t.TempDir()
	good := writePrivate(t, dir, "t.json", `{"addr":"h:22","user":"u","host_key_sha256":"SHA256:abc","password_file":"/x"}`)
	if _, err := LoadSSHTarget(good); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"nokey.json":   `{"addr":"h:22","user":"u","password_file":"/x"}`,
		"both.json":    `{"addr":"h:22","user":"u","host_key_sha256":"SHA256:a","password_file":"/x","private_key_file":"/y"}`,
		"none.json":    `{"addr":"h:22","user":"u","host_key_sha256":"SHA256:a"}`,
		"unknown.json": `{"addr":"h:22","user":"u","host_key_sha256":"SHA256:a","password_file":"/x","extra":1}`,
	} {
		if _, err := LoadSSHTarget(writePrivate(t, dir, name, body)); err == nil {
			t.Errorf("%s must be rejected", name)
		}
	}
	loose := filepath.Join(dir, "loose.json")
	_ = os.WriteFile(loose, []byte(`{"addr":"h:22","user":"u","host_key_sha256":"SHA256:a","password_file":"/x"}`), 0o644)
	if _, err := LoadSSHTarget(loose); err == nil {
		t.Error("group/world readable target config must be rejected")
	}
}

func TestSSHCollectFailsClosedWithoutLeakingSecret(t *testing.T) {
	dir := t.TempDir()
	pw := writePrivate(t, dir, "pw", "TOPSECRET-PASSWORD\n")
	target := SSHTarget{Addr: "127.0.0.1:1", User: "u", HostKeySHA256: "SHA256:abc", PasswordFile: pw}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := NewSSHCollect12(target, sshlinux.Policy{ConnectTimeout: time.Second, ConnectRetries: 0})(ctx)
	if err == nil || strings.Contains(err.Error(), "TOPSECRET") {
		t.Fatal("must fail closed without leaking the secret:", err)
	}
	// файл секрета с широкими правами отвергается
	loose := filepath.Join(dir, "loose")
	_ = os.WriteFile(loose, []byte("p"), 0o644)
	target.PasswordFile = loose
	if _, err = NewSSHCollect12(target, sshlinux.Policy{})(ctx); err == nil {
		t.Fatal("non-private secret file must be rejected")
	}
}

func TestConfigInventoryPlatformOverride(t *testing.T) {
	dir := t.TempDir()
	base := Config{Tenant: identifier.New(), Site: identifier.New(), Scope: identifier.New(), CollectorSource: identifier.New(),
		CollectorURL: "https://collector.invalid:18443", State: dir, CA: "/etc/ca.pem"}
	write := func(c Config) string {
		raw, _ := json.Marshal(c)
		p := filepath.Join(dir, "c.json")
		_ = os.Remove(p)
		if err := writeAtomic(p, raw); err != nil {
			t.Fatal(err)
		}
		return p
	}
	// по умолчанию — платформа хоста
	c, err := ReadConfig(write(base))
	if err != nil {
		t.Fatal(err)
	}
	if (&Client{cfg: c}).platform() != platform12() {
		t.Fatal("default platform must be the host platform")
	}
	// виртуальная личность Windows-цели на Linux-хосте объявляет платформу цели
	base.InventoryPlatform = "windows/amd64"
	if c, err = ReadConfig(write(base)); err != nil || (&Client{cfg: c}).platform() != "windows/amd64" {
		t.Fatal("explicit platform must be used", err)
	}
	base.InventoryPlatform = "plan9/mips"
	if _, err = ReadConfig(write(base)); err == nil {
		t.Fatal("unsupported platform must be rejected")
	}
}
