//go:build bao

package bao

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRealOpenBaoScopedKeyAndSecretOperations(t *testing.T) {
	path := os.Getenv("SURVEYSCAN_TEST_BAO_CONFIG")
	if path == "" {
		t.Fatal("explicit scoped OpenBao fixture required")
	}
	c, e := Load(path)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if e = c.Check(ctx); e != nil {
		t.Fatal(e)
	}
	public, e := c.Public("center")
	if e != nil {
		t.Fatal(e)
	}
	message := []byte("SURVEYSCAN-CENTER-RESULT-V1\nsynthetic")
	signature, e := c.Sign(ctx, "center", message)
	if e != nil || !ed25519.Verify(public, message, signature) {
		t.Fatal("remote signature invalid", e)
	}
	secret, e := c.Read(ctx, "canary")
	if e != nil || len(secret) < 24 {
		t.Fatal("scoped KV ref unavailable", e)
	}
	for i := range secret {
		secret[i] = 0
	}
	if _, e = c.Read(ctx, "arbitrary-vault-path"); !errors.Is(e, Denied) {
		t.Fatal("unconfigured ref available")
	}
	root, e := Load(os.Getenv("SURVEYSCAN_TEST_BAO_ROOT_CONFIG"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = root.Sign(ctx, "center", message); !errors.Is(e, Denied) {
		t.Fatal("application accepted root token", e)
	}
}

func TestRealTokenRenewalRevocationAndAtomicReplacement(t *testing.T) {
	c, e := Load(os.Getenv("SURVEYSCAN_TEST_BAO_SHORT_CONFIG"))
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if e = c.Check(ctx); e != nil {
		t.Fatal("short periodic token renewal failed", e)
	}
	token, e := c.token(ctx)
	if e != nil {
		t.Fatal(e)
	}
	var info struct {
		Data struct {
			Renewed int64 `json:"last_renewal_time"`
		} `json:"data"`
	}
	if e = c.call(ctx, "GET", "auth/token/lookup-self", token, nil, &info); e != nil || info.Data.Renewed == 0 {
		t.Fatal("renew-self not observed", e)
	}
	original, e := os.ReadFile(c.cfg.TokenFile)
	if e != nil {
		t.Fatal(e)
	}
	revoked, e := os.ReadFile(os.Getenv("SURVEYSCAN_TEST_BAO_REVOKED_TOKEN"))
	if e != nil {
		t.Fatal(e)
	}
	// Same client must pick up the operator's replacement, without restart/cached old token.
	replace := func(raw []byte) {
		t.Helper()
		f, e := os.CreateTemp(filepath.Dir(c.cfg.TokenFile), ".token-*")
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.Write(raw); e != nil {
			t.Fatal(e)
		}
		if e = f.Close(); e != nil {
			t.Fatal(e)
		}
		if e = os.Rename(f.Name(), c.cfg.TokenFile); e != nil {
			t.Fatal(e)
		}
	}
	replace(revoked)
	if _, e = c.Sign(ctx, "center", []byte("test")); !errors.Is(e, Denied) {
		t.Fatal("revoked token kept working", e)
	}
	replace(original)
	if _, e = c.Sign(ctx, "center", []byte("test")); e != nil {
		t.Fatal("atomic token replacement not read", e)
	}
}
