//go:build integration

package app_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
)

// A real PG lock delays session authorization after password verification. The
// request must fail closed, roll back, and leave no credential to leak/replay.
// This is controlled contention, not proof of the historical VM's exact cause.
func TestC14LoginDeadlineDoesNotMintSession(t *testing.T) {
	ctx, service, pool := authService(t)
	bootstrap(t, ctx, service)
	blocker, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(ctx)
	if _, err = blocker.Exec(ctx, "SELECT user_id FROM access.users WHERE username='admin' FOR UPDATE"); err != nil {
		t.Fatal(err)
	}
	auth, err := access.NewHTTP(service, "http://127.0.0.1", true)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	auth.Register(mux)
	server := httptest.NewServer(mux)
	defer server.Close()
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": password})
	request, err := http.NewRequest("POST", server.URL+"/api/v1/auth/sessions", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://127.0.0.1")
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable || len(response.Cookies()) != 0 {
		t.Fatal("deadline did not fail closed without a cookie")
	}
	var failure struct {
		Code string `json:"code"`
	}
	if json.NewDecoder(io.LimitReader(response.Body, 8192)).Decode(&failure) != nil || failure.Code != "TEMPORARILY_UNAVAILABLE" {
		t.Fatal("unexpected bounded error response")
	}
	if err = blocker.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var credentials int
	if err = pool.QueryRow(ctx, "SELECT count(*) FROM access.credentials").Scan(&credentials); err != nil || credentials != 0 {
		t.Fatal("failed login minted a credential")
	}
	// Explicit new request after the competing transaction is gone, not an
	// automatic replay/retry inside either the product or the boot fixture.
	if _, _, err = service.Login(ctx, "admin", password); err != nil {
		t.Fatal("login did not recover after contention ended")
	}
	if err = pool.QueryRow(ctx, "SELECT count(*) FROM access.credentials").Scan(&credentials); err != nil || credentials != 1 {
		t.Fatal("recovered login did not create exactly one credential")
	}
}
