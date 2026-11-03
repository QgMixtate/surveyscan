package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDatabaseSecrets(t *testing.T) {
	t.Setenv("SURVEYSCAN_V2_DATABASE_PASSWORD_FILE", "")
	t.Setenv("SURVEYSCAN_V2_DATABASE_URL", "postgres://user:SECRET@%zz")
	_, err := Database()
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatal("DSN error leaked or accepted")
	}
	t.Setenv("SURVEYSCAN_V2_DATABASE_URL", "postgres://user@localhost/test?sslmode=disable")
	p := filepath.Join(t.TempDir(), "password")
	if err = os.WriteFile(p, []byte("private-password\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SURVEYSCAN_V2_DATABASE_PASSWORD_FILE", p)
	c, err := Database()
	if err != nil || c.Password != "private-password" {
		t.Fatal("private file not read")
	}
	if err = os.Chmod(p, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = Database(); err == nil {
		t.Fatal("public file accepted")
	}
}
func TestBaoAddress(t *testing.T) {
	for _, s := range []string{"", "ftp://example", "http://user:password@example", "http://example?token=x"} {
		t.Setenv("SURVEYSCAN_V2_BAO_ADDR", s)
		if _, e := BaoURL(); e == nil {
			t.Errorf("accepted %q", s)
		}
	}
	t.Setenv("SURVEYSCAN_V2_BAO_ADDR", "http://bao:8200/")
	if s, e := BaoURL(); e != nil || s != "http://bao:8200" {
		t.Fatal(s, e)
	}
}
