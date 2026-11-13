//go:build integration

package app_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/health"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// C51.01: обследования сети — правила D-13 на сервере (/22, пробы, расписание ≥ 60 мин, collector той же площадки),
// права (админ заводит, оператор запускает, наблюдатель только смотрит), одно незавершённое обследование на подсеть,
// задание только collector своей подсети (mTLS), подписанный результат, scope не расширяется, present/missing, аудит.
func TestC51DiscoveryPolicyRightsJobAndSignedResult(t *testing.T) {
	f := registrySetup(t)
	machine, authority := machineService(t, f)
	f.registry.Machine = &app.MachineAPI{Sources: machine}
	for _, u := range []struct{ name, role string }{{"op51", "operator"}, {"view51", "viewer"}} {
		if err := f.users.Provision(f.ctx, false, tenant, "", u.name, password, u.role); err != nil {
			t.Fatal(err)
		}
	}
	auth, err := access.NewHTTP(f.users, "https://ui.example", false)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := app.NewHTTP(auth, health.Handler(func(context.Context) error { return nil }), f.registry)
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	contract, err := os.ReadFile("../../contracts/c51-discovery.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := jsonschema.UnmarshalJSON(strings.NewReader(string(contract)))
	if err = compiler.AddResource("urn:surveyscan:c51:discovery:1:0", doc); err != nil {
		t.Fatal(err)
	}
	valid := func(def string, raw []byte) {
		t.Helper()
		schema, err := compiler.Compile("urn:surveyscan:c51:discovery:1:0#/$defs/" + def)
		if err != nil {
			t.Fatal(err)
		}
		instance, err := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
		if err != nil || schema.Validate(instance) != nil {
			t.Fatalf("%s violates contract: %v %s", def, schema.Validate(instance), raw)
		}
	}
	human := httptest.NewTLSServer(handler)
	t.Cleanup(human.Close)
	sessions51 := map[string]c31Client{}
	call := func(user, method, path, body string, want int) []byte {
		t.Helper()
		b, ok := sessions51[user]
		if !ok {
			b.b = newBrowser(t, human)
			b.csrf = b.b.login(t, user).CSRFToken
			sessions51[user] = b
		}
		csrf, origin := b.csrf, "https://ui.example"
		if method == "GET" {
			csrf, origin = "", ""
		}
		code, raw, _ := b.b.request(t, method, path, body, csrf, origin, nil)
		if code != want {
			t.Fatalf("%s %s %s: want %d, got %d %s", user, method, path, want, code, raw)
		}
		return raw
	}
	// collector площадки (mTLS) с собственным ключом подписи
	signPub, signKey, _ := ed25519.GenerateKey(rand.Reader)
	csr, hash, _, tlsKey := csrTLSMaterial(t)
	collector := identifier.New()
	grant, err := machine.Grant(f.ctx, f.identity, contracts.EnrollmentGrantRequest{TenantID: tenant, SourceID: collector, Kind: "collector", SiteID: siteID, TTL: 900, CSRHash: hash, PublicKey: base64.RawURLEncoding.EncodeToString(signPub)})
	if err != nil {
		t.Fatal(err)
	}
	enrolled, err := machine.Enroll(f.ctx, grant.Token, contracts.EnrollmentRequest{GrantID: grant.ID, SourceID: collector, CSR: csr, PublicKey: base64.RawURLEncoding.EncodeToString(signPub)})
	if err != nil {
		t.Fatal(err)
	}
	serverPublic, serverKey, _ := ed25519.GenerateKey(rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(51), Subject: pkix.Name{CommonName: "C51 fixture"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, authority.Certificate, serverPublic, authority.Key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(authority.Certificate)
	ms := httptest.NewUnstartedServer(handler)
	ms.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{tlsPair(t, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), serverKey)}, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: roots}
	ms.StartTLS()
	t.Cleanup(ms.Close)
	pair := tlsPair(t, enrolled.Chain, tlsKey)
	mc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{pair}}}}
	post := func(path string, body []byte) (int, []byte) {
		t.Helper()
		res, err := mc.Post(ms.URL+path, "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		return res.StatusCode, raw
	}

	// правила D-13
	net51 := func(cidr string, extra string) string {
		return fmt.Sprintf(`{"site_id":%q,"collector_id":%q,"name":"Офис %s","cidr":%q,"probes":["tcp","arp","icmp"]%s}`, siteID, collector, cidr, cidr, extra)
	}
	for _, bad := range []string{net51("10.0.0.0/21", ""), net51("10.0.0.1/24", ""), net51("fd00::/120", ""), net51("10.0.0.0/24", `,"schedule_minutes":30`),
		strings.Replace(net51("10.0.0.0/24", ""), `"tcp","arp","icmp"`, `"udp"`, 1), strings.Replace(net51("10.0.0.0/24", ""), collector, identifier.New(), 1)} {
		call("admin", "POST", "/api/v1/discovery/networks", bad, 422)
	}
	call("op51", "POST", "/api/v1/discovery/networks", net51("10.0.0.0/24", ""), 403)
	var n sources.DiscoveryNetwork
	created := call("admin", "POST", "/api/v1/discovery/networks", net51("10.51.0.0/24", `,"schedule_minutes":60`), 201)
	valid("DiscoveryNetwork", created)
	_ = json.Unmarshal(created, &n)
	if n.ID == "" || n.CIDR != "10.51.0.0/24" || n.Revision != "1" {
		t.Fatalf("network %+v", n)
	}
	call("admin", "POST", "/api/v1/discovery/networks", net51("10.51.0.0/24", ""), 409) // та же подсеть
	call("view51", "POST", "/api/v1/discovery/networks/"+n.ID+"/runs", "{}", 403)
	var run struct {
		Run string `json:"run_id"`
	}
	_ = json.Unmarshal(call("op51", "POST", "/api/v1/discovery/networks/"+n.ID+"/runs", "{}", 202), &run)
	call("op51", "POST", "/api/v1/discovery/networks/"+n.ID+"/runs", "{}", 409) // одно незавершённое
	page := call("view51", "GET", "/api/v1/discovery/networks", "", 200)
	valid("DiscoveryNetworkPage", page)
	valid("DiscoveryRunPage", call("view51", "GET", "/api/v1/discovery/networks/"+n.ID+"/runs", "", 200))
	if !strings.Contains(string(page), `"max_prefix":22`) {
		t.Fatal("limits must be visible to the Web")
	}

	// задание — только collector подсети, по mTLS
	anon := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}}
	if res, err := anon.Post(ms.URL+"/api/v1/machine/discovery-jobs", "application/json", strings.NewReader("{}")); err != nil || res.StatusCode != 401 {
		t.Fatal("job without client certificate", err)
	}
	code, raw := post("/api/v1/machine/discovery-jobs", []byte("{}"))
	var got struct {
		Job *sources.DiscoveryJob `json:"job"`
	}
	valid("DiscoveryJobResponse", raw)
	if code != 200 || json.Unmarshal(raw, &got) != nil || got.Job == nil || got.Job.Run != run.Run || got.Job.CIDR != "10.51.0.0/24" || got.Job.Rate != 50 || len(got.Job.Probes) != 3 {
		t.Fatalf("job %d %s", code, raw)
	}
	if code, raw = post("/api/v1/machine/discovery-jobs", []byte("{}")); code != 200 || string(raw) != `{"job":null}`+"\n" && string(raw) != `{"job":null}` {
		t.Fatalf("second claim must be empty: %d %s", code, raw)
	}

	submit := func(hosts []sources.FoundHost, errs []string, key ed25519.PrivateKey) (int, []byte) {
		payload, _ := json.Marshal(sources.DiscoveryResult{Major: 1, ResultID: identifier.New(), Tenant: tenant, Source: collector, Generation: enrolled.GenerationID, Run: run.Run,
			StartedAt: time.Now().Add(-time.Minute).UTC(), FinishedAt: time.Now().UTC(), Addresses: 254, Hosts: hosts, Errors: errs})
		canonical, _ := wire.Canonical(payload)
		sum := sha256.Sum256(canonical)
		sig := ed25519.Sign(key, append([]byte(sources.DiscoverySignaturePrefix), canonical...))
		body, _ := json.Marshal(sources.SignedDiscoveryResult{Payload: payload, Digest: hex.EncodeToString(sum[:]), KeyID: enrolled.KeyID, Signature: base64.RawURLEncoding.EncodeToString(sig)})
		valid("SignedDiscoveryResult", body)
		return post("/api/v1/machine/discovery-results", body)
	}
	mac := "AA:BB:CC:00:00:01"
	hosts := []sources.FoundHost{{IP: "10.51.0.10", MAC: &mac, Ports: []int{22, 9999, 22}, ICMP: true}, {IP: "10.51.0.20", Ports: []int{445, 3389}}, {IP: "192.168.1.1", Ports: []int{80}}}
	_, foreign, _ := ed25519.GenerateKey(rand.Reader)
	if code, _ := submit(hosts, nil, foreign); code < 400 {
		t.Fatal("result signed by another key accepted")
	}
	code, raw = submit(hosts, nil, signKey)
	var out sources.DiscoveryOutcome
	valid("DiscoveryOutcome", raw)
	if code != 200 || json.Unmarshal(raw, &out) != nil || out.Found != 2 || out.New != 2 || out.Dropped != 1 {
		t.Fatalf("result %d %s", code, raw)
	}
	var hl struct {
		Items []sources.DiscoveryHost `json:"items"`
	}
	hostsRaw := call("view51", "GET", "/api/v1/discovery/networks/"+n.ID+"/hosts", "", 200)
	valid("DiscoveryHostPage", hostsRaw)
	_ = json.Unmarshal(hostsRaw, &hl)
	if len(hl.Items) != 2 || hl.Items[0].IP != "10.51.0.10" || *hl.Items[0].MAC != "aa:bb:cc:00:00:01" || len(hl.Items[0].Ports) != 1 || !hl.Items[0].ICMP {
		t.Fatalf("hosts %+v", hl.Items)
	}
	// второе обследование: .20 пропал, .30 новый
	_ = json.Unmarshal(call("op51", "POST", "/api/v1/discovery/networks/"+n.ID+"/runs", "{}", 202), &run)
	if code, _ = post("/api/v1/machine/discovery-jobs", []byte("{}")); code != 200 {
		t.Fatal(code)
	}
	code, raw = submit([]sources.FoundHost{{IP: "10.51.0.10", Ports: []int{22}}, {IP: "10.51.0.30", Ports: []int{443}}}, nil, signKey)
	if code != 200 || json.Unmarshal(raw, &out) != nil || out.Found != 2 || out.New != 1 || out.Missing != 1 {
		t.Fatalf("second result %d %s", code, raw)
	}
	// повтор того же результата — без изменений
	if code, raw = submit(nil, nil, signKey); code != 200 || json.Unmarshal(raw, &out) != nil || out.Missing != 1 {
		t.Fatalf("replay of a finished run %d %s", code, raw)
	}
	var audits int
	if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM audit.audit_events WHERE tenant_id=$1 AND action LIKE 'discovery.%'", tenant).Scan(&audits); err != nil || audits != 3 {
		t.Fatal("audit of network creation and runs", audits, err)
	}
	// расписание: подсеть с периодом 60 мин и последним запуском только что — не ставится
	tx, _ := f.pool.Begin(f.ctx)
	k, err := sources.Store{}.DiscoveryDue(f.ctx, tx, tenant)
	tx.Rollback(f.ctx)
	if err != nil || k != 0 {
		t.Fatal("schedule must respect the period", k, err)
	}
}

// C51.03 (A): учётки сбора — вводит только администратор, секрет уходит в хранилище секретов и нигде не
// возвращается (ни в ответе, ни в списке, ни в аудите); без хранилища секретов учётка не сохраняется.
func TestC51CollectCredentialsSecretNeverReturned(t *testing.T) {
	f := registrySetup(t)
	if err := f.users.Provision(f.ctx, false, tenant, "", "op51c", password, "operator"); err != nil {
		t.Fatal(err)
	}
	auth, err := access.NewHTTP(f.users, "https://ui.example", false)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := app.NewHTTP(auth, health.Handler(func(context.Context) error { return nil }), f.registry)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	sessions51 := map[string]c31Client{}
	call := func(user, method, path, body string, want int) []byte {
		t.Helper()
		b, ok := sessions51[user]
		if !ok {
			b.b = newBrowser(t, srv)
			b.csrf = b.b.login(t, user).CSRFToken
			sessions51[user] = b
		}
		csrf, origin := b.csrf, "https://ui.example"
		if method == "GET" {
			csrf, origin = "", ""
		}
		code, raw, _ := b.b.request(t, method, path, body, csrf, origin, nil)
		if code != want {
			t.Fatalf("%s %s %s: want %d, got %d %s", user, method, path, want, code, raw)
		}
		return raw
	}
	const secret = "C51-very-secret-pass"
	ssh := `{"name":"Linux только чтение","kind":"ssh","username":"scanprobe","secret":{"password":"` + secret + `"}}`
	call("admin", "POST", "/api/v1/discovery/credentials", ssh, 409) // хранилища секретов нет — не сохраняем
	store := t.TempDir()
	f.registry.Secrets = app.FileSecrets{Dir: store}
	call("op51c", "POST", "/api/v1/discovery/credentials", ssh, 403)
	call("op51c", "GET", "/api/v1/discovery/credentials", "", 403)
	for _, bad := range []string{
		`{"name":"x","kind":"ssh","username":"u","secret":{}}`,
		`{"name":"x","kind":"ssh","username":"u","secret":{"password":"a","private_key":"-----BEGIN OPENSSH PRIVATE KEY-----"}}`,
		`{"name":"x","kind":"winrm","username":"u","secret":{"private_key":"k"}}`,
		`{"name":"x","kind":"snmp","username":"u","secret":{"auth_protocol":"MD5","auth_key":"12345678","priv_protocol":"AES","priv_key":"12345678"}}`,
		`{"name":"x","kind":"telnet","username":"u","secret":{"password":"a"}}`,
	} {
		call("admin", "POST", "/api/v1/discovery/credentials", bad, 422)
	}
	created := call("admin", "POST", "/api/v1/discovery/credentials", ssh, 201)
	var c sources.CollectCredential
	_ = json.Unmarshal(created, &c)
	call("admin", "POST", "/api/v1/discovery/credentials", ssh, 409) // то же название
	call("admin", "POST", "/api/v1/discovery/credentials", `{"name":"SNMP ядро","kind":"snmp","username":"surveyscan","secret":{"auth_protocol":"SHA256","auth_key":"auth-key-123","priv_protocol":"AES","priv_key":"priv-key-123"}}`, 201)
	list := call("admin", "GET", "/api/v1/discovery/credentials", "", 200)
	changed := call("admin", "PATCH", "/api/v1/discovery/credentials/"+c.ID, `{"revision":"1","secret":{"password":"`+secret+`-2"}}`, 200)
	call("admin", "PATCH", "/api/v1/discovery/credentials/"+c.ID, `{"revision":"1","name":"другое"}`, 412)
	for _, raw := range [][]byte{created, list, changed} {
		if strings.Contains(string(raw), secret) || strings.Contains(string(raw), "password") || strings.Contains(string(raw), "priv-key") {
			t.Fatalf("secret leaked into the API: %s", raw)
		}
	}
	stored, ok, err := f.registry.Secrets.Get(f.ctx, tenant, sources.CredentialSecretKey(c.ID))
	if err != nil || !ok || !strings.Contains(string(stored), secret+"-2") {
		t.Fatal("secret must be stored (and rotated) in the secret store", ok, err)
	}
	var leaked int
	if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM audit.audit_events WHERE tenant_id=$1 AND (action LIKE 'discovery.credential%') AND row_to_json(audit_events)::text LIKE '%'||$2||'%'", tenant, secret).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatal("secret in audit", leaked, err)
	}
	var audits int
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM audit.audit_events WHERE tenant_id=$1 AND action IN ('discovery.credential_created','discovery.credential_secret_changed')", tenant).Scan(&audits)
	if audits != 3 {
		t.Fatal("credential creation and secret change audited", audits)
	}
}
