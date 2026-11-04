//go:build linux

package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/pki"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

type responseTransport struct {
	status int
	body   string
	fail   bool
}

func (r responseTransport) RoundTrip(*http.Request) (*http.Response, error) {
	if r.fail {
		return nil, errors.New("offline")
	}
	return &http.Response{StatusCode: r.status, Body: io.NopCloser(strings.NewReader(r.body)), Header: make(http.Header)}, nil
}
func TestAgentOfflineAndUntrustedAckNeverTrim(t *testing.T) {
	dir := t.TempDir()
	spool := filepath.Join(dir, "spool")
	if e := os.Mkdir(spool, 0700); e != nil {
		t.Fatal(e)
	}
	id := identifier.New()
	tenant := identifier.New()
	raw, _ := json.Marshal(contracts.Batch{Version: contracts.Version{Major: 1}, TenantID: tenant, DeliveryID: id, Records: []json.RawMessage{}})
	path := filepath.Join(spool, id+".pending")
	if e := writeAtomic(path, raw); e != nil {
		t.Fatal(e)
	}
	v, e := wire.New()
	if e != nil {
		t.Fatal(e)
	}
	pub, _, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	for _, transport := range []responseTransport{{fail: true}, {status: 202, body: `{"spool_action":"remove"}`}, {status: 202, body: `{}`}} {
		c := &Client{cfg: Config{State: dir, CollectorURL: "https://collector.invalid"}, claims: pki.Claims{Tenant: tenant, CenterKeyID: identifier.New(), CenterPublic: pub}, wire: v, http: &http.Client{Transport: transport}}
		_ = c.Flush(context.Background())
		if _, e := os.Stat(path); e != nil {
			t.Fatal("offline or forged receipt removed sender packet", e)
		}
	}
}
func TestAgentPrepareStableLockAndPrivateConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{State: dir}
	first, e := Prepare(cfg)
	if e != nil {
		t.Fatal(e)
	}
	again, e := Prepare(cfg)
	if e != nil || again != first {
		t.Fatal("prepare replaced identity", e)
	}
	a, e := readKey(filepath.Join(dir, "tls.key"))
	if e != nil {
		t.Fatal(e)
	}
	b, e := readKey(filepath.Join(dir, "signing.key"))
	if e != nil {
		t.Fatal(e)
	}
	if string(a) == string(b) {
		t.Fatal("TLS and observation keys reused")
	}
	unlock, e := lockState(dir)
	if e != nil {
		t.Fatal(e)
	}
	if other, e := lockState(dir); e == nil {
		other()
		t.Fatal("second process acquired state")
	}
	unlock()
	config := filepath.Join(dir, "config.json")
	raw, _ := json.Marshal(Config{Tenant: identifier.New(), Site: identifier.New(), Scope: identifier.New(), CollectorSource: identifier.New(), CollectorURL: "http://collector.invalid", State: dir, CA: "ca.pem"})
	if e = writeAtomic(config, raw); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadConfig(config); e == nil {
		t.Fatal("cleartext collector allowed")
	}
	if e = os.Chmod(config, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadConfig(config); e == nil {
		t.Fatal("public config allowed")
	}
}
