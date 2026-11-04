package bao

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// TLS plumbing test uses an explicit synthetic Bao HTTP handler; live Bao is tested separately.
func TestHTTPSRequiresTrustedCAAndNeverForwardsRedirect(t *testing.T) {
	var forwarded atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded.Add(1); w.WriteHeader(200) }))
	defer destination.Close()
	var redirect atomic.Bool
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if redirect.Load() {
			http.Redirect(w, r, destination.URL, 302)
			return
		}
		if r.URL.Path != "/v1/auth/token/lookup-self" || r.Header.Get("X-Vault-Token") != "synthetic-scoped-test-token" {
			w.WriteHeader(403)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"policies": []string{"app"}, "renewable": true, "ttl": 3600}})
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	dir := t.TempDir()
	token := filepath.Join(dir, "token")
	if e := os.WriteFile(token, []byte("synthetic-scoped-test-token"), 0600); e != nil {
		t.Fatal(e)
	}
	cfg := Config{Address: server.URL, TokenFile: token, Policy: "app", TransitMount: "transit"}
	untrusted, e := New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	if e = untrusted.Check(context.Background()); e == nil {
		t.Fatal("self-signed HTTPS was trusted without configured CA")
	}
	ca := filepath.Join(dir, "ca.pem")
	if e = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); e != nil {
		t.Fatal(e)
	}
	cfg.TLSCAFile = ca
	trusted, e := New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	if !trusted.Secure() {
		t.Fatal("verified HTTPS profile not secure")
	}
	if e = trusted.Check(context.Background()); e != nil {
		t.Fatal("explicit trusted CA failed", e)
	}
	redirect.Store(true)
	if e = trusted.Check(context.Background()); e == nil {
		t.Fatal("redirect was accepted")
	}
	if forwarded.Load() != 0 {
		t.Fatal("redirect leaked scoped request to another endpoint")
	}
}
