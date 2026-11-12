package bao

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// C31.05: секреты интеграций в KV v2 — отсутствие (404) отличается от отказа, путь ограничен разделом
// integrations_path, значение хранится в поле value.
func TestIntegrationSecrets(t *testing.T) {
	var mu sync.Mutex
	stored := map[string]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "t0k" {
			w.WriteHeader(403)
			return
		}
		if r.URL.Path == "/v1/auth/token/lookup-self" {
			_, _ = w.Write([]byte(`{"data":{"policies":["surveyscan"],"ttl":3600,"renewable":true}}`))
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if !strings.HasPrefix(r.URL.Path, "/v1/kv/data/server/integrations/") {
			w.WriteHeader(403)
			return
		}
		switch r.Method {
		case "GET":
			v, ok := stored[r.URL.Path]
			if !ok {
				w.WriteHeader(404)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": map[string]string{"value": v}}})
		case "POST":
			var body struct {
				Data map[string]string `json:"data"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			stored[r.URL.Path] = body.Data["value"]
			w.WriteHeader(200)
		}
	}))
	defer server.Close()
	token := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(token, []byte("t0k\n"), 0o600)
	cfg := Config{Address: server.URL, DevLoopbackHTTP: true, TokenFile: token, Policy: "surveyscan", TransitMount: "transit", KVMount: "kv", IntegrationsPath: "server/integrations"}
	c, err := New(cfg)
	if err != nil || !c.Integrations() {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, ok, err := c.ReadIntegration(ctx, "center", "webhook-master"); ok || err != nil {
		t.Fatal("absent secret must be not found, not an error", ok, err)
	}
	if err = c.WriteIntegration(ctx, "center", "webhook-master", []byte("secret-bytes")); err != nil {
		t.Fatal(err)
	}
	if v, ok, err := c.ReadIntegration(ctx, "center", "webhook-master"); !ok || err != nil || string(v) != "secret-bytes" {
		t.Fatal("round trip", ok, err)
	}
	if _, _, err = c.ReadIntegration(ctx, "../root", "x"); !errors.Is(err, Denied) {
		t.Fatal("traversal scope accepted")
	}
	cfg.IntegrationsPath = "../escape"
	if _, err = New(cfg); err == nil {
		t.Fatal("unsafe integrations_path accepted")
	}
	cfg.IntegrationsPath = ""
	off, _ := New(cfg)
	if off.Integrations() || off.WriteIntegration(ctx, "center", "k", []byte("v")) == nil {
		t.Fatal("integrations must be off without integrations_path")
	}
}
