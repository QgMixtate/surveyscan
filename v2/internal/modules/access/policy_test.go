package access

import (
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"testing"
)

func TestRoleAndTokenPolicy(t *testing.T) {
	for _, tc := range []struct {
		role, kind, action string
		scopes             []string
		ok                 bool
	}{{"viewer", "session", "assets:read", nil, true}, {"viewer", "session", "jobs:write", nil, false}, {"operator", "session", "jobs:write", nil, true}, {"operator", "session", "sources:admin", nil, false}, {"admin", "session", "sources:admin", nil, true}, {"admin", "cli", "sources:admin", []string{"assets:read"}, false}, {"viewer", "cli", "assets:read", []string{"sources:read"}, false}, {"viewer", "cli", "assets:read", []string{"assets:read"}, true}, {"admin", "session", "unknown", nil, false}} {
		id := port.Identity{Role: tc.role, Kind: tc.kind, Scopes: tc.scopes}
		if got := allowed(id, tc.action); got != tc.ok {
			t.Errorf("%+v: %v", tc, got)
		}
	}
}
func TestProductionOriginPolicy(t *testing.T) {
	for _, tc := range []struct {
		origin  string
		dev, ok bool
	}{{"https://ui.example", false, true}, {"http://127.0.0.1:58081", true, true}, {"http://127.0.0.1", false, false}, {"http://evil.example", true, false}, {"https://user:pass@ui.example", false, false}, {"https://ui.example/path", false, false}, {"https://ui.example?token=x", false, false}, {"", false, false}} {
		_, e := NewHTTP(nil, tc.origin, tc.dev)
		if (e == nil) != tc.ok {
			t.Errorf("%q: %v", tc.origin, e)
		}
	}
}

func BenchmarkArgon2idPolicy(b *testing.B) {
	salt := make([]byte, 16)
	b.ReportAllocs()
	for b.Loop() {
		_ = derive("synthetic benchmark passphrase", salt)
	}
}
