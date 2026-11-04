package agent

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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/diskspool"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/pki"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/privatefile"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/retry"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

type Config struct {
	Tenant           string `json:"tenant_id"`
	Site             string `json:"site_id"`
	Scope            string `json:"network_scope_id"`
	CollectorURL     string `json:"collector_url"`
	CollectorSource  string `json:"collector_source_id"`
	CA               string `json:"ca_certificate_file"`
	State            string `json:"state_directory"`
	InventorySeconds int    `json:"inventory_seconds"`
	HeartbeatSeconds int    `json:"heartbeat_seconds"`
	Jitter           int    `json:"jitter_percent"`
	Limit            int64  `json:"spool_limit_bytes"`
}
type Preparation struct {
	Source string `json:"source_id"`
	CSR    string `json:"csr_pem"`
	Hash   string `json:"csr_sha256"`
	Public string `json:"signing_public_key"`
}
type counters struct {
	Inventory string `json:"inventory"`
	Heartbeat string `json:"heartbeat"`
}
type Client struct {
	profile     *contracts.ProfilePayload
	cfg         Config
	preparation Preparation
	claims      pki.Claims
	key         ed25519.PrivateKey
	http        *http.Client
	wire        *wire.Validator
	sequence    counters
}

func writeAtomic(path string, b []byte) error { return diskspool.Atomic(path, b) }
func loadJSON(path string, out any) error {
	b, e := privatefile.Read(path, 65536)
	if e != nil {
		return e
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e = d.Decode(out); e != nil {
		return errors.New("invalid private agent state")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return errors.New("invalid private agent state")
	}
	return nil
}
func saveJSON(path string, value any) error {
	b, e := json.Marshal(value)
	if e != nil {
		return e
	}
	return writeAtomic(path, b)
}
func ReadConfig(path string) (Config, error) {
	var c Config
	if e := loadJSON(path, &c); e != nil {
		return c, e
	}
	if !identifier.Valid(c.Tenant) || !identifier.Valid(c.Site) || !identifier.Valid(c.Scope) || !identifier.Valid(c.CollectorSource) || c.State == "" || !filepath.IsAbs(c.State) || c.CA == "" {
		return c, errors.New("explicit scoped agent configuration required")
	}
	u, e := url.Parse(c.CollectorURL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return c, errors.New("HTTPS collector origin required")
	}
	c.CollectorURL = strings.TrimRight(c.CollectorURL, "/")
	if c.InventorySeconds == 0 {
		c.InventorySeconds = 900
	}
	if c.HeartbeatSeconds == 0 {
		c.HeartbeatSeconds = 60
	}
	if c.Limit == 0 {
		c.Limit = 64 * 1024 * 1024
	}
	if c.InventorySeconds < 60 || c.InventorySeconds > 86400 || c.HeartbeatSeconds < 30 || c.HeartbeatSeconds > 3600 || c.Jitter < 0 || c.Jitter > 25 || c.Limit < 524288 || c.Limit > 1073741824 {
		return c, errors.New("agent intervals or spool bounds invalid")
	}
	return c, nil
}
func readKey(path string) (ed25519.PrivateKey, error) {
	b, e := privatefile.Read(path, 16384)
	if e != nil {
		return nil, e
	}
	block, rest := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid agent key")
	}
	key, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		return nil, e
	}
	ed, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("agent requires Ed25519 key")
	}
	return ed, nil
}
func Prepare(c Config) (Preparation, error) {
	var out Preparation
	if e := os.MkdirAll(c.State, 0700); e != nil {
		return out, e
	}
	if e := os.Chmod(c.State, 0700); e != nil {
		return out, e
	}
	unlock, e := lockState(c.State)
	if e != nil {
		return out, e
	}
	defer unlock()
	path := filepath.Join(c.State, "preparation.json")
	if _, e = os.Stat(path); e == nil {
		if e = loadJSON(path, &out); e != nil {
			return out, e
		}
		key, e := readKey(filepath.Join(c.State, "signing.key"))
		if e != nil {
			return out, e
		}
		return out, verifyHostBinding(c, out.Source, key)
	} else if !os.IsNotExist(e) {
		return out, e
	}
	hostID, e := localMachineID()
	if e != nil {
		return out, e
	}
	for _, name := range []string{"tls.key", "signing.key", "identity.json", "sequences.json", "host-binding.json", "tls-identity.json", "renewal.pending.json"} {
		if _, e = os.Stat(filepath.Join(c.State, name)); !os.IsNotExist(e) {
			return out, errors.New("agent state already contains identity material")
		}
	}
	tlsPublic, tlsKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return out, e
	}
	_ = tlsPublic
	signPublic, signKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return out, e
	}
	for name, key := range map[string]ed25519.PrivateKey{"tls.key": tlsKey, "signing.key": signKey} {
		der, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			return out, e
		}
		if e = writeAtomic(filepath.Join(c.State, name), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); e != nil {
			return out, e
		}
	}
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "untrusted-agent-request"}}, tlsKey)
	if e != nil {
		return out, e
	}
	digest := sha256.Sum256(csr)
	out = Preparation{Source: identifier.New(), CSR: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), Hash: hex.EncodeToString(digest[:]), Public: base64.RawURLEncoding.EncodeToString(signPublic)}
	if e = saveJSON(filepath.Join(c.State, "sequences.json"), counters{Inventory: "0", Heartbeat: "0"}); e != nil {
		return out, e
	}
	if e = saveJSON(filepath.Join(c.State, "host-binding.json"), bindingValue(out.Source, hostID, signKey)); e != nil {
		return out, e
	}
	return out, saveJSON(path, out)
}
func newHTTP(c Config, roots *x509.CertPool, pair *tls.Certificate, collectorID string) (*http.Client, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: c.CollectorSource + ".collector.invalid"}
	if pair != nil {
		cfg.Certificates = []tls.Certificate{*pair}
	}
	cfg.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
			return errors.New("collector TLS not verified")
		}
		claims, e := pki.ClaimsFromCertificate(state.PeerCertificates[0])
		if e != nil || claims.Kind != "collector" || claims.Source != c.CollectorSource || claims.Tenant != c.Tenant || (collectorID != "" && claims.Collector != collectorID) {
			return errors.New("collector identity mismatch")
		}
		return nil
	}
	return &http.Client{Timeout: 12 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}
func rootsFor(c Config) (*x509.CertPool, error) {
	b, e := os.ReadFile(c.CA)
	if e != nil || len(b) > 65536 {
		return nil, errors.New("agent trusted CA unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(b) {
		return nil, errors.New("agent trusted CA invalid")
	}
	return roots, nil
}
func request(ctx context.Context, client *http.Client, origin, method, path string, b []byte, token string) (int, []byte, error) {
	req, e := http.NewRequestWithContext(ctx, method, origin+path, bytes.NewReader(b))
	if e != nil {
		return 0, nil, e
	}
	if b != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	response, e := client.Do(req)
	if e != nil {
		return 0, nil, errors.New("collector unavailable or identity rejected")
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, 2*1048576+1))
	if e != nil || len(raw) > 2*1048576 {
		return response.StatusCode, nil, errors.New("collector response too large")
	}
	return response.StatusCode, raw, nil
}
func Enroll(ctx context.Context, c Config, grant contracts.EnrollmentGrant) error {
	unlock, e := lockState(c.State)
	if e != nil {
		return e
	}
	defer unlock()
	var prep Preparation
	if e = loadJSON(filepath.Join(c.State, "preparation.json"), &prep); e != nil {
		return e
	}
	if prep.Source != grant.SourceID {
		return errors.New("enrollment grant source mismatch")
	}
	key, e := readKey(filepath.Join(c.State, "signing.key"))
	if e != nil {
		return e
	}
	if e = verifyHostBinding(c, prep.Source, key); e != nil {
		return e
	}
	public := key.Public().(ed25519.PublicKey)
	if prep.Public != base64.RawURLEncoding.EncodeToString(public) {
		return errors.New("enrollment signing key mismatch")
	}
	roots, e := rootsFor(c)
	if e != nil {
		return e
	}
	client, e := newHTTP(c, roots, nil, "")
	if e != nil {
		return e
	}
	defer client.CloseIdleConnections()
	v, e := wire.New()
	if e != nil {
		return e
	}
	req := contracts.EnrollmentRequest{GrantID: grant.ID, SourceID: prep.Source, CSR: prep.CSR, PublicKey: prep.Public}
	b, _ := json.Marshal(req)
	code, raw, e := request(ctx, client, c.CollectorURL, "POST", "/api/v1/machine/enroll", b, grant.Token)
	if e != nil {
		return e
	}
	if code != 201 || v.Validate("EnrollmentResult", raw) != nil {
		return errors.New("agent enrollment rejected")
	}
	var result contracts.EnrollmentResult
	_ = json.Unmarshal(raw, &result)
	claims, e := pki.VerifyEnrollmentResult(result, roots, prep.Source, public)
	if e != nil || claims.Kind != "agent" || claims.Tenant != c.Tenant {
		return errors.New("enrollment identity not trusted")
	}
	tlsKey, e := privatefile.Read(filepath.Join(c.State, "tls.key"), 16384)
	if e != nil {
		return e
	}
	if _, e = tls.X509KeyPair([]byte(result.Chain), tlsKey); e != nil {
		return errors.New("enrollment TLS key mismatch")
	}
	// Нельзя подменить назначение collector сертификатом другого collector того же tenant.
	bound, e := newHTTP(c, roots, nil, claims.Collector)
	if e != nil {
		return e
	}
	defer bound.CloseIdleConnections()
	if code, _, e = request(ctx, bound, c.CollectorURL, "GET", "/health/live", nil, ""); e != nil || code != 200 {
		return errors.New("enrollment collector assignment mismatch")
	}
	if _, e := os.Stat(filepath.Join(c.State, "identity.json")); e == nil {
		prior, err := privatefile.Read(filepath.Join(c.State, "identity.json"), 65536)
		if err != nil {
			return err
		}
		existing, _ := json.Marshal(result)
		var old contracts.EnrollmentResult
		if json.Unmarshal(prior, &old) != nil {
			return errors.New("invalid existing identity")
		}
		oldRaw, _ := json.Marshal(old)
		if !bytes.Equal(oldRaw, existing) {
			return errors.New("existing identity cannot be replaced")
		}
		return nil
	} else if !os.IsNotExist(e) {
		return e
	}
	return saveJSON(filepath.Join(c.State, "identity.json"), result)
}
func Open(c Config) (*Client, error) { return open(c, true) }
func open(c Config, requireBinding bool) (*Client, error) {
	var prep Preparation
	if e := loadJSON(filepath.Join(c.State, "preparation.json"), &prep); e != nil {
		return nil, e
	}
	key, e := readKey(filepath.Join(c.State, "signing.key"))
	if e != nil {
		return nil, e
	}
	if requireBinding {
		if e = verifyHostBinding(c, prep.Source, key); e != nil {
			return nil, e
		}
	}
	var result contracts.EnrollmentResult
	var rotated tlsIdentity
	hasRotated, rotatedErr := loadOptionalJSON(filepath.Join(c.State, "tls-identity.json"), &rotated)
	if rotatedErr != nil {
		return nil, rotatedErr
	}
	if e = loadJSON(filepath.Join(c.State, "identity.json"), &result); e != nil {
		return nil, e
	}
	if hasRotated {
		result = rotated.Result
	}
	roots, e := rootsFor(c)
	if e != nil {
		return nil, e
	}
	claims, e := pki.VerifyEnrollmentResult(result, roots, prep.Source, key.Public().(ed25519.PublicKey))
	if e != nil || claims.Kind != "agent" || claims.Tenant != c.Tenant {
		return nil, errors.New("agent identity not trusted")
	}
	keyPEM, e := privatefile.Read(filepath.Join(c.State, "tls.key"), 16384)
	if e != nil {
		return nil, e
	}
	if hasRotated {
		keyPEM = []byte(rotated.Private)
	}
	pair, e := tls.X509KeyPair([]byte(result.Chain), keyPEM)
	if e != nil {
		return nil, e
	}
	client, e := newHTTP(c, roots, &pair, claims.Collector)
	if e != nil {
		return nil, e
	}
	v, e := wire.New()
	if e != nil {
		return nil, e
	}
	out := &Client{cfg: c, preparation: prep, claims: claims, key: key, http: client, wire: v}
	if e = loadJSON(filepath.Join(c.State, "sequences.json"), &out.sequence); e != nil {
		return nil, e
	}
	for _, seq := range []string{out.sequence.Inventory, out.sequence.Heartbeat} {
		if _, e = strconv.ParseUint(seq, 10, 64); e != nil {
			return nil, errors.New("invalid agent counters")
		}
	}
	if e = os.MkdirAll(filepath.Join(c.State, "spool"), 0700); e != nil {
		return nil, e
	}
	if e = out.loadProfile(); e != nil {
		out.http.CloseIdleConnections()
		return nil, e
	}
	return out, nil
}
func (c *Client) next(heartbeat bool) (string, error) {
	ptr := &c.sequence.Inventory
	if heartbeat {
		ptr = &c.sequence.Heartbeat
	}
	old, e := strconv.ParseUint(*ptr, 10, 64)
	if e != nil || old == ^uint64(0) {
		return "", errors.New("agent sequence exhausted")
	}
	*ptr = strconv.FormatUint(old+1, 10)
	if e = saveJSON(filepath.Join(c.cfg.State, "sequences.json"), c.sequence); e != nil {
		return "", e
	}
	return *ptr, nil
}
func (c *Client) signed(payload any, domain string) ([]byte, error) {
	raw, e := json.Marshal(payload)
	if e != nil {
		return nil, e
	}
	canonical, e := wire.Canonical(raw)
	if e != nil {
		return nil, e
	}
	sum := sha256.Sum256(canonical)
	return json.Marshal(contracts.SignedObservation{Payload: raw, Digest: hex.EncodeToString(sum[:]), KeyID: c.claims.KeyID, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(c.key, append([]byte(domain), canonical...)))})
}
func (c *Client) Inventory(ctx context.Context) error {
	if e := verifyHostBinding(c.cfg, c.claims.Source, c.key); e != nil {
		return e
	}
	if e := diskspool.Data(filepath.Join(c.cfg.State, "spool"), c.cfg.Limit-diskspool.AckReserve, 131072); e != nil {
		return e
	}
	snapshot, e := Collect(ctx)
	if e != nil {
		return e
	}
	sequence, e := c.next(false)
	if e != nil {
		return e
	}
	o := contracts.Observation{Version: contracts.Version{Major: 1}, ID: identifier.New(), TenantID: c.claims.Tenant, Origin: contracts.Origin{SourceID: c.claims.Source, SourceKind: "agent", GenerationID: c.claims.Generation}, Record: contracts.SourceRecord{Namespace: "host", LocalID: "host"}, Scope: contracts.Scope{SiteID: c.cfg.Site, ScopeID: c.cfg.Scope}, Sequence: sequence, CollectedAt: time.Now().UTC(), Clock: "trusted", Candidates: snapshot.Candidates, Sections: snapshot.Sections}
	raw, e := c.signed(o, "SURVEYSCAN-OBSERVATION-V1\n")
	if e != nil {
		return e
	}
	if _, _, _, e = c.wire.Observation(raw); e != nil {
		return e
	}
	batch := contracts.Batch{Version: contracts.Version{Major: 1}, TenantID: c.claims.Tenant, DeliveryID: identifier.New(), Records: []json.RawMessage{raw}}
	b, _ := json.Marshal(batch)
	if e = c.wire.Validate("Batch", b); e != nil {
		return e
	}
	return writeAtomic(filepath.Join(c.cfg.State, "spool", batch.DeliveryID+".pending"), b)
}
func (c *Client) Flush(ctx context.Context) error {
	entries, e := os.ReadDir(filepath.Join(c.cfg.State, "spool"))
	if e != nil {
		return e
	}
	waiting := false
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".pending") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".pending")
		if !identifier.Valid(id) {
			return errors.New("invalid agent packet path")
		}
		path := filepath.Join(c.cfg.State, "spool", entry.Name())
		raw, e := privatefile.Read(path, 1048576)
		if e != nil {
			return e
		}
		var batch contracts.Batch
		if e = json.Unmarshal(raw, &batch); e != nil || batch.DeliveryID != id || batch.TenantID != c.claims.Tenant {
			return errors.New("invalid agent pending packet")
		}
		if _, stat := os.Stat(filepath.Join(c.cfg.State, "spool", id+".receipt")); stat == nil {
			cached, e := privatefile.Read(filepath.Join(c.cfg.State, "spool", id+".receipt"), 1048576)
			if e != nil {
				return e
			}
			_, remove, e := c.wire.VerifyCenterResult(cached, raw, c.claims.CenterKeyID, c.claims.CenterPublic)
			if e != nil {
				return errors.New("cached source receipt verification failed")
			}
			if remove {
				if e = os.Remove(path); e != nil {
					return e
				}
				if e = diskspool.SyncDir(filepath.Dir(path)); e != nil {
					return e
				}
			}
			continue
		} else if !os.IsNotExist(stat) {
			return stat
		}
		// У transport receipt нет права удалять пакет. Результат центра проверяется независимо.
		code, ack, e := request(ctx, c.http, c.cfg.CollectorURL, "POST", "/api/v1/machine/observations", raw, "")
		if e != nil {
			return e
		}
		if code != 202 {
			return fmt.Errorf("collector batch rejected (HTTP %d)", code)
		}
		_, remove, verify := c.wire.VerifyCenterResult(ack, raw, c.claims.CenterKeyID, c.claims.CenterPublic)
		if verify != nil {
			code, ack, e = request(ctx, c.http, c.cfg.CollectorURL, "GET", "/api/v1/machine/deliveries/"+id, nil, "")
			if e != nil {
				return e
			}
			if code != 200 {
				return fmt.Errorf("collector status rejected (HTTP %d)", code)
			}
			_, remove, verify = c.wire.VerifyCenterResult(ack, raw, c.claims.CenterKeyID, c.claims.CenterPublic)
		}
		if verify != nil {
			waiting = true
			continue
		}
		if e = diskspool.Capacity(filepath.Join(c.cfg.State, "spool"), c.cfg.Limit, int64(len(ack))); e != nil {
			return e
		}
		if e = writeAtomic(filepath.Join(c.cfg.State, "spool", id+".receipt"), ack); e != nil {
			return e
		}
		if remove {
			if e = os.Remove(path); e != nil {
				return e
			}
			dir, e := os.Open(filepath.Dir(path))
			if e != nil {
				return e
			}
			e = dir.Sync()
			dir.Close()
			if e != nil {
				return e
			}
		}
	}
	if waiting {
		return errors.New("center result pending; source packet retained")
	}
	return nil
}
func (c *Client) Heartbeat(ctx context.Context) error {
	if e := verifyHostBinding(c.cfg, c.claims.Source, c.key); e != nil {
		return e
	}
	req := contracts.ChallengeRequest{Sources: []string{c.claims.Source}, Purpose: "heartbeat"}
	raw, _ := json.Marshal(req)
	code, b, e := request(ctx, c.http, c.cfg.CollectorURL, "POST", "/api/v1/machine/heartbeat-challenges", raw, "")
	if e != nil {
		return e
	}
	if code != 200 || c.wire.Validate("ChallengeResponse", b) != nil {
		return errors.New("fresh heartbeat challenge unavailable")
	}
	var response contracts.ChallengeResponse
	_ = json.Unmarshal(b, &response)
	if len(response.Challenges) != 1 {
		return errors.New("invalid heartbeat challenge")
	}
	challenge := response.Challenges[0]
	if challenge.Purpose != "heartbeat" || challenge.Tenant != c.claims.Tenant || challenge.Source != c.claims.Source || challenge.Generation != c.claims.Generation || !time.Now().Before(challenge.Expires) {
		return errors.New("heartbeat challenge binding invalid")
	}
	seq, e := c.next(true)
	if e != nil {
		return e
	}
	h := contracts.Heartbeat{Version: contracts.Version{Major: 1}, ID: identifier.New(), Tenant: c.claims.Tenant, Origin: contracts.Origin{SourceID: c.claims.Source, SourceKind: "agent", GenerationID: c.claims.Generation}, Challenge: challenge.ID, Nonce: challenge.Nonce, Sequence: seq, Sent: time.Now().UTC()}
	raw, e = c.signed(h, "SURVEYSCAN-HEARTBEAT-V1\n")
	if e != nil {
		return e
	}
	code, b, e = request(ctx, c.http, c.cfg.CollectorURL, "POST", "/api/v1/machine/heartbeats", raw, "")
	if e != nil {
		return e
	}
	if code != 200 || c.wire.Validate("HeartbeatResult", b) != nil {
		return errors.New("heartbeat not accepted")
	}
	var accepted contracts.HeartbeatResult
	_ = json.Unmarshal(b, &accepted)
	if accepted.ID != h.ID {
		return errors.New("heartbeat response mismatch")
	}
	return nil
}
func jitter(interval int, percent int) time.Duration {
	base := time.Duration(interval) * time.Second
	if percent == 0 {
		return base
	}
	var b [1]byte
	if _, e := rand.Read(b[:]); e != nil {
		return base
	}
	delta := (float64(b[0])/255*2 - 1) * float64(percent) / 100
	return time.Duration(float64(base) * (1 + delta))
}
func Run(ctx context.Context, c Config, report func(string)) error {
	unlock, e := lockState(c.State)
	if e != nil {
		return e
	}
	defer unlock()
	if e = diskspool.RecoverTemps(c.State); e != nil {
		return e
	}
	if e = diskspool.RecoverTemps(filepath.Join(c.State, "spool")); e != nil && !os.IsNotExist(e) {
		return e
	}
	client, e := Open(c)
	if e != nil {
		return e
	}
	defer func() { client.http.CloseIdleConnections() }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	inventoryAt, heartbeatAt, renewalAt, profileAt := time.Time{}, time.Time{}, time.Time{}, time.Time{}
	var delivery retry.Backoff
	for {
		if e = ctx.Err(); e != nil {
			return nil
		}
		now := time.Now()
		if !now.Before(profileAt) {
			task, cancel := context.WithTimeout(ctx, 3*time.Second)
			changed, err := client.PollProfile(task)
			cancel()
			if err != nil {
				report("profile_unavailable_cached_or_local")
			} else if changed {
				report("profile_applied")
				if !inventoryAt.IsZero() {
					inventoryAt = time.Now().Add(jitter(client.cfg.InventorySeconds, client.cfg.Jitter))
				}
				if !heartbeatAt.IsZero() {
					heartbeatAt = time.Now().Add(jitter(client.cfg.HeartbeatSeconds, client.cfg.Jitter))
				}
			}
			profileAt = time.Now().Add(20 * time.Second)
		}
		if !now.Before(renewalAt) && client.renewalDue(now) {
			if e = client.Renew(ctx); e != nil {
				report("renewal_pending")
			} else {
				report("renewal_checked")
			}
			renewalAt = time.Now().Add(time.Minute)
		}
		if !now.Before(heartbeatAt) {
			if e = client.Heartbeat(ctx); e != nil {
				report("heartbeat_failed")
			} else {
				report("heartbeat_accepted")
			}
			heartbeatAt = time.Now().Add(jitter(client.cfg.HeartbeatSeconds, client.cfg.Jitter))
		}
		if !now.Before(inventoryAt) {
			if e = client.Inventory(ctx); e != nil {
				report("inventory_failed")
			} else {
				report("inventory_queued")
			}
			inventoryAt = time.Now().Add(jitter(client.cfg.InventorySeconds, client.cfg.Jitter))
		}
		if delivery.Ready(time.Now()) {
			if e = client.Flush(ctx); e != nil {
				delivery.Failed(time.Now())
				report("delivery_pending")
			} else {
				delivery.Reset()
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
