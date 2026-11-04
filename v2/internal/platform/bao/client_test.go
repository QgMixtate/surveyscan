package bao

import (
	"context"
	"encoding/base64"
	"testing"
)

func TestPinnedPublicMetadataOfflineAndReferenceBounds(t *testing.T) {
	cfg := Config{Address: "http://127.0.0.1:1", DevLoopbackHTTP: true, TokenFile: "/nonexistent/token", Policy: "surveyscan", TransitMount: "transit", Keys: map[string]Key{"center": {Name: "center", Version: 1, Public: base64.RawURLEncoding.EncodeToString(make([]byte, 32))}}}
	c, e := New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.Public("center"); e != nil {
		t.Fatal("public metadata unexpectedly requires online secrets", e)
	}
	if _, e = c.Sign(context.Background(), "../export", nil); e != Denied {
		t.Fatal("unconfigured ref accepted")
	}
	if _, e = c.Read(context.Background(), "unknown"); e != Denied {
		t.Fatal("unconfigured KV ref accepted")
	}
	cfg.Address = "http://example.invalid"
	if _, e = New(cfg); e == nil {
		t.Fatal("non-loopback plaintext Bao accepted")
	}
	cfg.Address = "https://example.invalid"
	cfg.Keys["center"] = Key{Name: "../root", Version: 1, Public: base64.RawURLEncoding.EncodeToString(make([]byte, 32))}
	if _, e = New(cfg); e == nil {
		t.Fatal("path traversal key accepted")
	}
}
