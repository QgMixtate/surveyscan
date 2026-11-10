//go:build !windows

package privatefile

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, dir, name string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestStrictByDefault(t *testing.T) {
	dir := t.TempDir()
	if _, err := Read(write(t, dir, "ok", 0o600), 10); err != nil {
		t.Fatal(err)
	}
	for _, m := range []os.FileMode{0o640, 0o440, 0o644, 0o604} {
		if _, err := Read(write(t, dir, "bad", m), 10); err == nil {
			t.Errorf("mode %o must be refused outside a systemd credentials dir", m)
		}
	}
}

func TestSystemdCredentialsDirectory(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("нужен root: файл credentials принадлежит root:root")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o550); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	if _, err := Read(write(t, dir, "config", 0o440), 10); err != nil {
		t.Fatal("systemd >=255 credential (root:root 0440 in CREDENTIALS_DIRECTORY) must be accepted:", err)
	}
	for _, m := range []os.FileMode{0o444, 0o640, 0o444 | 0o200} {
		if _, err := Read(write(t, dir, "wide", m), 10); err == nil {
			t.Errorf("mode %o in credentials dir must still be refused", m)
		}
	}
	// такой же файл вне каталога credentials — отвергается
	other := t.TempDir()
	if _, err := Read(write(t, other, "config", 0o440), 10); err == nil {
		t.Fatal("0440 outside CREDENTIALS_DIRECTORY must be refused")
	}
	// каталог доступен «остальным» — отвергается
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(write(t, dir, "config2", 0o440), 10); err == nil {
		t.Fatal("world-accessible credentials directory must be refused")
	}
}
