package router

import (
	"strings"
	"testing"
)

func TestRouteCookieSignature(t *testing.T) {
	r := &Router{Key: []byte(strings.Repeat("a", 32))}
	other := &Router{Key: []byte(strings.Repeat("b", 32))}
	const tenant = "00000000-0000-4000-8000-000000000001"
	v := r.sign(tenant, 3)
	if got, ok := r.verify(v); !ok || got != tenant {
		t.Fatal("valid cookie rejected")
	}
	for _, bad := range []string{other.sign(tenant, 3), strings.Replace(v, ".3.", ".4.", 1), v + "A", "x." + v, tenant + ".0." + strings.Split(r.sign(tenant, 0), ".")[2], ""} {
		if _, ok := r.verify(bad); ok {
			t.Fatalf("forged cookie accepted: %q", bad)
		}
	}
}
