//go:build collectorlive

package collector

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/diskspool"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

// The Python harness supplies a real running server/PG/OpenBao and stops the compiled
// collector for this port. Only the scheduling deadline is injected, not issuance/TLS/storage.
func TestLiveCollectorAutomaticTLSReload(t *testing.T) {
	path := os.Getenv("SURVEYSCAN_TEST_COLLECTOR_CONFIG")
	if path == "" {
		t.Fatal("explicit owned live collector config required")
	}
	c, e := Load(path)
	if e != nil {
		t.Fatal(e)
	}
	initial := c.certificate.Load()
	der := append([]byte(nil), initial.Certificate[0]...)
	// Advance only the renewal scheduler's clock; real certificates and TLS validity stay unchanged.
	c.clock = func() time.Time { return initial.Leaf.NotAfter.Add(-30 * time.Minute) }
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	defer func() {
		cancel()
		if e := <-done; e != nil {
			t.Error(e)
		}
	}()
	transport := &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: c.roots, MinVersion: tls.VersionTLS12, ServerName: c.Claims.Source + ".collector.invalid"}}
	client := &http.Client{Transport: transport, Timeout: time.Second}
	defer client.CloseIdleConnections()
	var peer []byte
	for ctx.Err() == nil {
		response, err := client.Get("https://" + c.Config.Listen + "/health/live")
		if err == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode != 200 {
				t.Fatal("listener unavailable during rotation")
			}
			peer = append([]byte(nil), response.TLS.PeerCertificates[0].Raw...)
			if !bytes.Equal(peer, der) {
				break
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(25 * time.Millisecond):
		}
	}
	if bytes.Equal(peer, der) || len(peer) == 0 {
		t.Fatal("automatic renewal did not hot-reload server certificate")
	}
	current := c.certificate.Load()
	if !bytes.Equal(peer, current.Certificate[0]) || current.Leaf.NotAfter.Before(time.Now().Add(time.Hour)) {
		t.Fatal("TLS directions did not share committed credential")
	}
	raw, _ := json.Marshal(contracts.ChallengeRequest{Sources: []string{c.Claims.Source}, Purpose: "heartbeat"})
	status, _, e := c.post(ctx, "/api/v1/machine/heartbeat-challenges", raw, "")
	if e != nil || status != 200 {
		t.Fatal("new outbound identity not accepted by real center", status, e)
	}
	if _, e = os.Stat(c.Config.CredentialState + "/renewal.pending.json"); !os.IsNotExist(e) {
		t.Fatal("automatic renewal left pending state", e)
	}
	// Both credential and spool locks remain exclusive during hot reload.
	if other, e := diskspool.Lock(c.Config.CredentialState); e == nil {
		other()
		t.Fatal("credential writer lock missing")
	}
	if other, e := diskspool.Lock(c.Config.Spool); e == nil {
		other()
		t.Fatal("spool writer lock missing")
	}
}
