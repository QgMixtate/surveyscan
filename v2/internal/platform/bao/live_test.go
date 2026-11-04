//go:build bao

package bao

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
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
