package app

import (
	"os"
	"path/filepath"
	"testing"
)

// C31.02: objectGUID AD — первые три поля little-endian (как показывает AD: {00112233-4455-6677-8899-aabbccddeeff}).
func TestADGUID(t *testing.T) {
	raw := []byte{0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	if got := adGUID(raw); got != "00112233-4455-6677-8899-aabbccddeeff" {
		t.Fatal(got)
	}
	if adGUID(raw[:15]) != "" {
		t.Fatal("short GUID must be rejected")
	}
}

func TestDirectorySyncConfig(t *testing.T) {
	pw := filepath.Join(t.TempDir(), "pw")
	_ = os.WriteFile(pw, []byte("secret\n"), 0o600)
	ok := DirectorySyncConfig{TenantID: "00000000-0000-4000-8000-000000000001", URL: "ldaps://dc.example.test", BaseDN: "dc=example,dc=test", BindDN: "cn=reader,dc=example,dc=test", PasswordFile: pw}
	d, err := NewDirectorySync(ok)
	if err != nil || d.password != "secret" || d.Config.UserFilter == "" || d.Config.GUIDAttribute != "objectGUID" || d.Config.IntervalMinutes != 15 || d.Config.FullHours != 24 {
		t.Fatal(err, d)
	}
	for name, mutate := range map[string]func(*DirectorySyncConfig){
		"plaintext":   func(c *DirectorySyncConfig) { c.URL = "ldap://dc.example.test" },
		"path":        func(c *DirectorySyncConfig) { c.URL = "ldaps://dc.example.test/x" },
		"base":        func(c *DirectorySyncConfig) { c.BaseDN = "not a dn" },
		"filter":      func(c *DirectorySyncConfig) { c.GroupFilter = "(cn=" },
		"tenant":      func(c *DirectorySyncConfig) { c.TenantID = "x" },
		"interval":    func(c *DirectorySyncConfig) { c.IntervalMinutes = -1 },
		"public file": func(c *DirectorySyncConfig) { _ = os.Chmod(pw, 0o644) },
	} {
		c := ok
		mutate(&c)
		if _, err := NewDirectorySync(c); err == nil {
			t.Fatal(name, "must be refused")
		}
		_ = os.Chmod(pw, 0o600)
	}
	plain := ok
	plain.URL, plain.AllowPlaintext = "ldap://127.0.0.1:389", true
	if _, err := NewDirectorySync(plain); err != nil {
		t.Fatal("explicit plaintext for development", err)
	}
}
