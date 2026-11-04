//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/collector"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/imports"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/health"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/pki"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func writePrivate(t *testing.T, path string, b []byte) {
	t.Helper()
	if e := os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
}
func tlsPair(t *testing.T, chain string, key ed25519.PrivateKey) tls.Certificate {
	t.Helper()
	der, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	pair, e := tls.X509KeyPair([]byte(chain), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if e != nil {
		t.Fatal(e)
	}
	return pair
}
func TestC07AgentCollectorCenterPGAndVerifiedReturn(t *testing.T) {
	f := registrySetup(t)
	machine, authority := machineService(t, f)
	centerPub, centerKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	machine.CenterPublicKey = base64.RawURLEncoding.EncodeToString(centerPub)
	uploads := &imports.UploadService{Pool: f.pool, Auth: machine, Registry: app.MachineRegistry{Registry: f.registry, Auth: machine}, Wire: f.registry.Wire, KeyID: machine.CenterKeyID, Key: centerKey}
	f.registry.Machine = &app.MachineAPI{Sources: machine, Uploads: uploads}
	auth, e := access.NewHTTP(f.users, "https://ui.example", false)
	if e != nil {
		t.Fatal(e)
	}
	handler, e := app.NewHTTP(auth, health.Handler(func(context.Context) error { return nil }), f.registry)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(authority.Certificate)
	serverPub, serverKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "synthetic-center"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	serverDER, e := x509.CreateCertificate(rand.Reader, serverTemplate, authority.Certificate, serverPub, authority.Key)
	if e != nil {
		t.Fatal(e)
	}
	serverPair := tlsPair(t, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})), serverKey)
	var centerFailure atomic.Int32
	var centerAttempts atomic.Int32
	center := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/api/v1/machine/observations" {
			centerAttempts.Add(1)
		}
		if centerFailure.Load() == 3 && r.URL.Path == "/api/v1/machine/observations" {
			saved := httptest.NewRecorder()
			handler.ServeHTTP(saved, r)
			connection, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = connection.Close()
			}
			return
		}
		if centerFailure.Load() == 4 && r.URL.Path == "/api/v1/machine/observations" {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(2 * time.Second):
				w.WriteHeader(503)
				return
			}
		}
		switch centerFailure.Load() {
		case 1:
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		case 2:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		handler.ServeHTTP(w, r)
	}))
	center.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverPair}, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: roots}
	center.StartTLS()
	t.Cleanup(center.Close)
	collectorSource := identifier.New()
	csr, hash, _, collectorTLSKey := csrTLSMaterial(t)
	collectorSignPub, _, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	grant, e := machine.Grant(f.ctx, f.identity, contracts.EnrollmentGrantRequest{TenantID: tenant, SourceID: collectorSource, Kind: "collector", SiteID: siteID, TTL: 900, CSRHash: hash, PublicKey: base64.RawURLEncoding.EncodeToString(collectorSignPub)})
	if e != nil {
		t.Fatal(e)
	}
	result, e := machine.Enroll(f.ctx, grant.Token, contracts.EnrollmentRequest{GrantID: grant.ID, SourceID: collectorSource, CSR: csr, PublicKey: base64.RawURLEncoding.EncodeToString(collectorSignPub)})
	if e != nil {
		t.Fatal(e)
	}
	claims, e := pki.VerifyEnrollmentResult(result, roots, collectorSource, collectorSignPub)
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	certPath, keyPath, caPath := filepath.Join(dir, "collector.pem"), filepath.Join(dir, "collector.key"), filepath.Join(dir, "ca.pem")
	writePrivate(t, certPath, []byte(result.Chain))
	der, e := x509.MarshalPKCS8PrivateKey(collectorTLSKey)
	if e != nil {
		t.Fatal(e)
	}
	writePrivate(t, keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	writePrivate(t, caPath, authority.Chain)
	relay, e := collector.New(collector.Config{Listen: "127.0.0.1:0", CenterURL: center.URL, Certificate: certPath, PrivateKey: keyPath, CA: caPath, Spool: filepath.Join(dir, "spool")})
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(relay.Handler())
	server.TLS = relay.TLS
	server.StartTLS()
	t.Cleanup(server.Close)
	agentSource := identifier.New()
	agentCSR, agentHash, _, agentTLSKey := csrTLSMaterial(t)
	agentSignPub := f.key.Public().(ed25519.PublicKey)
	agentGrant, e := machine.Grant(f.ctx, f.identity, contracts.EnrollmentGrantRequest{TenantID: tenant, SourceID: agentSource, Kind: "agent", SiteID: siteID, CollectorID: &claims.Collector, TTL: 900, CSRHash: agentHash, PublicKey: base64.RawURLEncoding.EncodeToString(agentSignPub)})
	if e != nil {
		t.Fatal(e)
	}
	// Агент регистрируется через collector, не требует прямого соединения с центром.
	bootstrapClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: collectorSource + ".collector.invalid"}}, Timeout: 5 * time.Second}
	t.Cleanup(bootstrapClient.CloseIdleConnections)
	bootstrap := browser{bootstrapClient, server.URL}
	enrollRequest := contracts.EnrollmentRequest{GrantID: agentGrant.ID, SourceID: agentSource, CSR: agentCSR, PublicKey: base64.RawURLEncoding.EncodeToString(agentSignPub)}
	body, _ := json.Marshal(enrollRequest)
	code, body, _ := bootstrap.request(t, "POST", "/api/v1/machine/enroll", string(body), "", "", map[string]string{"Authorization": "Bearer " + agentGrant.Token})
	expect(t, 201, code)
	var agentResult contracts.EnrollmentResult
	if e = json.Unmarshal(body, &agentResult); e != nil {
		t.Fatal(e)
	}
	if _, e = pki.VerifyEnrollmentResult(agentResult, roots, agentSource, agentSignPub); e != nil {
		t.Fatal(e)
	}
	// Подмена enrollment response relay не меняет CA-подписанный center key в сертификате.
	forged := agentResult
	forged.CenterPublicKey = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if _, e = pki.VerifyEnrollmentResult(forged, roots, agentSource, agentSignPub); e == nil {
		t.Fatal("relay replaced center verification key")
	}
	pair := tlsPair(t, agentResult.Chain, agentTLSKey)
	agentClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: collectorSource + ".collector.invalid", Certificates: []tls.Certificate{pair}}}, Timeout: 5 * time.Second}
	t.Cleanup(agentClient.CloseIdleConnections)
	agent := browser{agentClient, server.URL}
	observation := f.observation("1")
	observation.Origin = contracts.Origin{SourceID: agentSource, SourceKind: "agent", GenerationID: agentResult.GenerationID}
	f.keyID = agentResult.KeyID
	record := f.signed(t, observation)
	batch := contracts.Batch{Version: contracts.Version{Major: 1}, TenantID: tenant, DeliveryID: identifier.New(), Records: []json.RawMessage{record}}
	raw, _ := json.Marshal(batch)
	code, transport, _ := agent.request(t, "POST", "/api/v1/machine/observations", string(raw), "", "", nil)
	expect(t, 202, code)
	if e = f.registry.Wire.Validate("TransportReceipt", transport); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(dir, "spool", batch.DeliveryID+".pending")); e != nil {
		t.Fatal("transport receipt without durable spool", e)
	}
	beforeCommitPacket, err := os.ReadFile(filepath.Join(dir, "spool", batch.DeliveryID+".pending"))
	if err != nil {
		t.Fatal(err)
	}
	count(t, f, "inventory.observations", 0)
	// Реальный TLS timeout до commit не удаляет durable packet.
	centerFailure.Store(4)
	short, cancel := context.WithTimeout(f.ctx, 150*time.Millisecond)
	_ = relay.Pump(short)
	cancel()
	if !errors.Is(short.Err(), context.DeadlineExceeded) || centerAttempts.Load() != 1 {
		t.Fatal("socket timeout not exercised")
	}
	count(t, f, "inventory.observations", 0)
	relay, e = collector.New(relay.Config)
	if e != nil {
		t.Fatal(e)
	}
	// Недоступность центра и недостоверный ACK не удаляют durable packet.
	pumpAttempt := func() {
		t.Helper()
		prior := centerAttempts.Load()
		deadline := time.Now().Add(8 * time.Second)
		for centerAttempts.Load() == prior && time.Now().Before(deadline) {
			_ = relay.Pump(f.ctx)
			if centerAttempts.Load() == prior {
				time.Sleep(50 * time.Millisecond)
			}
		}
		if centerAttempts.Load() == prior {
			t.Fatal("bounded retry never attempted delivery")
		}
	}
	for _, failure := range []int32{1, 2} {
		centerFailure.Store(failure)
		pumpAttempt()
		if _, err := os.Stat(filepath.Join(dir, "spool", batch.DeliveryID+".pending")); err != nil {
			t.Fatal("untrusted response removed pending", err)
		}
		count(t, f, "inventory.observations", 0)
	}
	// Drop ACK после настоящего commit: источник всё ещё обязан retain.
	centerFailure.Store(3)
	pumpAttempt()
	count(t, f, "inventory.observations", 1)
	if _, err := os.Stat(filepath.Join(dir, "spool", batch.DeliveryID+".pending")); err != nil {
		t.Fatal("dropped ACK lost pending", err)
	}
	centerFailure.Store(0)
	pumpAttempt()
	code, receipt, _ := agent.request(t, "GET", "/api/v1/machine/deliveries/"+batch.DeliveryID, "", "", "", nil)
	expect(t, 200, code)
	signed, remove, e := f.registry.Wire.VerifyCenterResult(receipt, raw, machine.CenterKeyID, centerPub)
	if e != nil || !remove || signed.Payload.Results[0].AssetID == nil {
		t.Fatal("no verified commit result", string(receipt), e)
	}
	if _, e = os.Stat(filepath.Join(dir, "spool", batch.DeliveryID+".pending")); !os.IsNotExist(e) {
		t.Fatal("collector did not trim verified committed data", e)
	}
	// Receipt должен оставаться связан с исходной подписью, key и batch.
	forgedReceipt := signed
	forgedReceipt.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	forgedRaw, _ := json.Marshal(forgedReceipt)
	if _, trimmed, err := f.registry.Wire.VerifyCenterResult(forgedRaw, raw, machine.CenterKeyID, centerPub); err == nil || trimmed {
		t.Fatal("forged center signature accepted")
	}
	otherBatch := batch
	otherBatch.DeliveryID = identifier.New()
	otherRaw, _ := json.Marshal(otherBatch)
	if _, trimmed, err := f.registry.Wire.VerifyCenterResult(receipt, otherRaw, machine.CenterKeyID, centerPub); err == nil || trimmed {
		t.Fatal("receipt for another delivery accepted")
	}
	if _, trimmed, err := f.registry.Wire.VerifyCenterResult(receipt, raw, identifier.New(), centerPub); err == nil || trimmed {
		t.Fatal("untrusted key id accepted")
	}
	count(t, f, "assets.assets", 1)
	count(t, f, "inventory.observations", 1)
	// C10 crash window: ACK persisted, pending unlink not durable; center already offline.
	writePrivate(t, filepath.Join(dir, "spool", batch.DeliveryID+".pending"), beforeCommitPacket)
	centerFailure.Store(1)
	// После restart collector хранит receipt и не применяет данные повторно.
	restarted, e := collector.New(relay.Config)
	if e != nil {
		t.Fatal(e)
	}
	if e = restarted.Pump(f.ctx); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(dir, "spool", batch.DeliveryID+".pending")); !os.IsNotExist(e) {
		t.Fatal("verified cached ACK failed crash recovery", e)
	}
	centerFailure.Store(0)
	count(t, f, "inventory.observations", 1)
	admin := newBrowser(t, center)
	admin.login(t, "admin")
	uid := *signed.Payload.Results[0].AssetID
	code, card, _ := admin.request(t, "GET", "/api/v1/assets/"+uid, "", "", "", nil)
	expect(t, 200, code)
	if !strings.Contains(string(card), "host-one") {
		t.Fatal("committed card unavailable")
	}
}
