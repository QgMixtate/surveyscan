//go:build linux

package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/pki"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

// The real actor uses durable private counters/spool and signed challenge
// heartbeat. HTTP responses are a test double, not PG/machine authorization.
func TestSlowCollectionDoesNotBlockHeartbeatOrOverlap(t *testing.T) {
	cfg := Config{State: t.TempDir(), Limit: 1048576, HeartbeatSeconds: 1, InventorySeconds: 1}
	if err := os.Mkdir(filepath.Join(cfg.State, "spool"), 0700); err != nil {
		t.Fatal(err)
	}
	prep, err := Prepare(cfg)
	if err != nil {
		t.Fatal(err)
	}
	key, err := readKey(filepath.Join(cfg.State, "signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	validator, err := wire.New()
	if err != nil {
		t.Fatal(err)
	}
	claims := pki.Claims{Tenant: identifier.New(), Source: prep.Source, Generation: identifier.New(), Kind: "agent", KeyID: identifier.New()}
	cfg.Site = identifier.New()
	cfg.Scope = identifier.New()
	beats := make(chan struct{}, 8)
	var accepted atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/machine/heartbeat-challenges":
			nonce, _ := wire.NewInventoryNonce()
			now := time.Now().UTC()
			_ = json.NewEncoder(w).Encode(contracts.ChallengeResponse{Challenges: []contracts.Challenge{{ID: identifier.New(), Tenant: claims.Tenant, Source: claims.Source, Generation: claims.Generation, Nonce: nonce, Issued: now, Expires: now.Add(time.Minute), Purpose: "heartbeat"}}})
		case "/api/v1/machine/heartbeats":
			var frame contracts.SignedHeartbeat
			if json.NewDecoder(r.Body).Decode(&frame) != nil {
				t.Error("malformed heartbeat")
				w.WriteHeader(400)
				return
			}
			canonical, err := wire.Canonical(frame.Payload)
			sig, decode := base64.RawURLEncoding.DecodeString(frame.Signature)
			if err != nil || decode != nil || !ed25519.Verify(key.Public().(ed25519.PublicKey), append([]byte("SURVEYSCAN-HEARTBEAT-V1\n"), canonical...), sig) {
				t.Error("bad heartbeat signature")
				w.WriteHeader(400)
				return
			}
			var heartbeat contracts.Heartbeat
			_ = json.Unmarshal(frame.Payload, &heartbeat)
			now := time.Now().UTC()
			_ = json.NewEncoder(w).Encode(contracts.HeartbeatResult{ID: heartbeat.ID, Accepted: now, LastContact: now, Request: identifier.New()})
			accepted.Add(1)
			beats <- struct{}{}
		default:
			w.WriteHeader(501)
		}
	}))
	defer server.Close()
	cfg.CollectorURL = server.URL
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{server.TLS.Certificates[0]}
	httpClient := &http.Client{Transport: transport, Timeout: time.Second}
	defer httpClient.CloseIdleConnections()
	client := &Client{cfg: cfg, claims: claims, key: key, wire: validator, http: httpClient, sequence: counters{Inventory: "0", Heartbeat: "0"}}
	snapshot, err := Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	collect := func(ctx context.Context) (Snapshot, error) {
		calls.Add(1)
		close(started)
		select {
		case <-release:
			return snapshot, nil
		case <-ctx.Done():
			return Snapshot{}, ctx.Err()
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queued := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- runClientLoop(ctx, client, func(event string) {
			if event == "inventory_queued" {
				queued <- struct{}{}
			}
		}, collect, 10*time.Second)
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("collection not started")
	}
	// At least one heartbeat must be accepted after collection is already active.
	<-beats
	select {
	case <-beats:
	case <-time.After(5 * time.Second):
		t.Fatal("blocked collection stalled heartbeat")
	}
	if calls.Load() != 1 {
		t.Fatal("overlapping collection")
	}
	files, err := os.ReadDir(filepath.Join(cfg.State, "spool"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if filepath.Ext(f.Name()) == ".pending" {
			t.Fatal("unfinished collection was signed/queued")
		}
	}
	close(release)
	select {
	case <-queued:
	case <-time.After(5 * time.Second):
		t.Fatal("finished snapshot not queued")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("actor did not stop")
	}
	var sequence counters
	if err = loadJSON(filepath.Join(cfg.State, "sequences.json"), &sequence); err != nil {
		t.Fatal(err)
	}
	if sequence.Inventory != "1" || accepted.Load() < 2 {
		t.Fatal("counter ownership/heartbeat progress failed")
	}
}

func TestCollectionDeadlineRejectsLateSuccessAndCooperativeShutdown(t *testing.T) {
	release := make(chan struct{})
	task := startCollection(context.Background(), func(context.Context) (Snapshot, error) { <-release; return Snapshot{}, nil }, 20*time.Millisecond)
	<-task.ctx.Done()
	select {
	case <-task.done:
		t.Fatal("noncooperative provider unexpectedly completed")
	default:
	}
	close(release)
	result := <-task.done
	if result.err != context.DeadlineExceeded {
		t.Fatal("late success survived deadline", result.err)
	}
	task = startCollection(context.Background(), func(ctx context.Context) (Snapshot, error) { <-ctx.Done(); return Snapshot{}, ctx.Err() }, time.Minute)
	task.cancel()
	select {
	case result := <-task.done:
		if result.err != context.Canceled {
			t.Fatal(result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("cooperative provider leaked")
	}
}
