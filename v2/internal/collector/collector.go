// Package collector реализует ограниченный HTTPS relay с durable spool.
package collector

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/diskspool"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/machinecred"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/pki"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/privatefile"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/retry"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/sourceprofile"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/telemetry"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Config struct {
	Inventory12     bool   `json:"inventory12_enabled"`
	SourceID        string `json:"source_id,omitempty"`
	CredentialState string `json:"credential_directory,omitempty"`
	SigningKey      string `json:"signing_private_key_file,omitempty"`
	Listen          string `json:"listen"`
	CenterURL       string `json:"center_url"`
	Certificate     string `json:"certificate_file"`
	PrivateKey      string `json:"private_key_file"`
	CA              string `json:"ca_certificate_file"`
	Spool           string `json:"spool_directory"`
	Limit           int64  `json:"spool_limit_bytes"`
}
type packet struct {
	Tenant  string          `json:"tenant"`
	Source  string          `json:"source"`
	ID      string          `json:"delivery_id"`
	Digest  string          `json:"batch_digest"`
	Batch   json.RawMessage `json:"batch,omitempty"`
	Receipt json.RawMessage `json:"receipt,omitempty"`
}
type Collector struct {
	profile     *contracts.ProfilePayload
	clock       func() time.Time
	certificate atomic.Pointer[tls.Certificate]
	roots       *x509.CertPool
	signing     ed25519.PrivateKey
	renewMu     sync.Mutex
	Config      Config
	Claims      pki.Claims
	TLS         *tls.Config
	client      *http.Client
	wire        *wire.Validator
	protocol    *wire.InventoryDecoder
	mu          sync.Mutex
	pump        sync.Mutex
	retries     map[string]*retry.Backoff
}

func Load(path string) (*Collector, error) {
	raw, e := privatefile.Read(path, 65536)
	if e != nil {
		return nil, e
	}
	var cfg Config
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e = d.Decode(&cfg); e != nil {
		return nil, errors.New("invalid collector configuration")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, errors.New("invalid collector configuration")
	}
	return New(cfg)
}
func New(cfg Config) (*Collector, error) {
	if cfg.Inventory12 && cfg.CredentialState == "" {
		return nil, errors.New("inventory1.2 requires managed collector signing identity")
	}
	if cfg.Listen == "" {
		return nil, errors.New("explicit collector listen address required")
	}
	if _, _, e := net.SplitHostPort(cfg.Listen); e != nil {
		return nil, errors.New("invalid collector listen address")
	}
	u, e := url.Parse(cfg.CenterURL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("HTTPS center origin required")
	}
	cfg.CenterURL = strings.TrimRight(cfg.CenterURL, "/")
	if cfg.Limit == 0 {
		cfg.Limit = 64 * 1024 * 1024
	}
	if cfg.Limit < 524288 || cfg.Limit > 1073741824 || cfg.Spool == "" {
		return nil, errors.New("bounded private spool required")
	}
	certificate, key, e := readCredential(cfg)
	if e != nil {
		return nil, e
	}
	pair, e := tls.X509KeyPair(certificate, key)
	if e != nil {
		return nil, errors.New("invalid collector certificate/key")
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return nil, e
	}
	ca, e := os.ReadFile(cfg.CA)
	if e != nil || len(ca) > 65536 {
		return nil, errors.New("collector CA unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("invalid collector CA")
	}
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
		return nil, errors.New("collector certificate not trusted")
	}
	claims, e := pki.ClaimsFromCertificate(leaf)
	if e != nil || claims.Kind != "collector" || (cfg.CredentialState != "" && (!identifier.Valid(cfg.SourceID) || claims.Source != cfg.SourceID)) || claims.Collector == "" || claims.CenterKeyID == "" || len(claims.CenterPublic) != 32 {
		return nil, errors.New("collector requires CA-attested identity and center verification key")
	}
	if e = os.MkdirAll(cfg.Spool, 0700); e != nil {
		return nil, e
	}
	if e = os.Chmod(cfg.Spool, 0700); e != nil {
		return nil, e
	}
	v, e := wire.New()
	if e != nil {
		return nil, e
	}
	out := &Collector{Config: cfg, Claims: claims, roots: roots, wire: v, clock: time.Now}
	if cfg.Inventory12 {
		out.protocol, e = wire.NewInventoryDecoder(v, true)
		if e != nil {
			return nil, e
		}
	}
	pair.Leaf = leaf
	out.certificate.Store(&pair)
	if cfg.CredentialState != "" {
		out.signing, e = readSigningKey(cfg.SigningKey)
		if e != nil || !ed25519.PublicKey(claims.SigningPublic).Equal(out.signing.Public()) {
			return nil, errors.New("collector signing key does not match attested identity")
		}
	}
	out.client = &http.Client{Timeout: 12 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return out.certificate.Load(), nil }}}, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	out.TLS = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return out.certificate.Load(), nil }, ClientCAs: roots, ClientAuth: tls.VerifyClientCertIfGiven}
	return out, nil
}

const maxPacketBytes = 2 * 1048576

func marshalPacket(p packet) ([]byte, error) {
	body, err := wire.RecordJSON(p)
	if err != nil || len(body) > maxPacketBytes {
		return nil, errors.New("collector packet exceeds bounded storage")
	}
	return body, nil
}

func atomicWrite(path string, b []byte) error { return diskspool.Atomic(path, b) }
func (c *Collector) path(id, suffix string) string {
	return filepath.Join(c.Config.Spool, strings.ToLower(id)+suffix)
}
func readPacket(path string) (packet, error) {
	var p packet
	raw, e := privatefile.Read(path, maxPacketBytes)
	if e != nil {
		return p, e
	}
	e = json.Unmarshal(raw, &p)
	if e == nil && (!identifier.Valid(p.ID) || !identifier.Valid(p.Tenant) || !identifier.Valid(p.Source)) {
		return p, errors.New("invalid spool identity")
	}
	if e == nil && len(p.Batch) > 0 {
		canonical, err := wire.Canonical(p.Batch)
		if err != nil {
			return p, errors.New("invalid spool payload")
		}
		sum := sha256.Sum256(canonical)
		if hex.EncodeToString(sum[:]) != p.Digest {
			return p, errors.New("spool digest mismatch")
		}
	}
	return p, e
}
func (c *Collector) peer(r *http.Request) (pki.Claims, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return pki.Claims{}, errors.New("client authentication required")
	}
	claims, e := pki.ClaimsFromCertificate(r.TLS.PeerCertificates[0])
	if e != nil || claims.Kind != "agent" || claims.Tenant != c.Claims.Tenant || claims.Collector != c.Claims.Collector {
		return claims, errors.New("agent scope mismatch")
	}
	return claims, nil
}
func reply(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func failure(w http.ResponseWriter, status int, code string) {
	reply(w, status, map[string]any{"code": code, "message": "Запрос не выполнен", "request_id": identifier.New(), "details": []any{}})
}
func (c *Collector) post(ctx context.Context, path string, raw []byte, token string) (int, []byte, error) {
	req, e := http.NewRequestWithContext(ctx, "POST", c.Config.CenterURL+path, bytes.NewReader(raw))
	if e != nil {
		return 0, nil, e
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	response, e := c.client.Do(req)
	if e != nil {
		return 0, nil, e
	}
	defer response.Body.Close()
	b, e := io.ReadAll(io.LimitReader(response.Body, 2*1048576+1))
	if e != nil || len(b) > 2*1048576 {
		return response.StatusCode, nil, errors.New("center response too large")
	}
	return response.StatusCode, b, nil
}
func (c *Collector) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/machine/inventory-profile", c.inventoryProfile12)
	mux.HandleFunc("POST /api/v1/machine/inventory-capabilities", c.inventoryCapabilities)
	mux.HandleFunc("POST /api/v1/machine/profile", func(w http.ResponseWriter, r *http.Request) {
		claims, e := c.peer(r)
		if e != nil {
			failure(w, 401, "AUTHENTICATION_REQUIRED")
			return
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
		if e != nil || c.wire.Validate("ProfileRequest", raw) != nil {
			failure(w, 422, "SCHEMA_INVALID")
			return
		}
		var frame contracts.ProfileFrame
		_ = json.Unmarshal(raw, &frame)
		var req contracts.ProfileRequestPayload
		_ = json.Unmarshal(frame.Payload, &req)
		if req.Tenant != claims.Tenant || req.Origin.SourceID != claims.Source || req.Origin.GenerationID != claims.Generation || req.Origin.SourceKind != claims.Kind || sourceprofile.Verify(frame, sourceprofile.RequestDomain, claims.KeyID, claims.SigningPublic) != nil {
			failure(w, 403, "FORBIDDEN")
			return
		}
		status, b, e := c.post(r.Context(), "/api/v1/machine/profile", raw, "")
		if e != nil {
			failure(w, 503, "CENTER_UNAVAILABLE")
			return
		}
		if status == 200 {
			if _, e = sourceprofile.VerifyResponse(c.wire, b, claims, req.Nonce, true); e != nil {
				failure(w, 503, "INVALID_CENTER_RESPONSE")
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		_, _ = w.Write(b)
	})
	// Heartbeat relay не хранит старые ответы для имитации свежего контакта.
	mux.HandleFunc("POST /api/v1/machine/heartbeat-challenges", func(w http.ResponseWriter, r *http.Request) {
		claims, e := c.peer(r)
		if e != nil {
			failure(w, 401, "AUTHENTICATION_REQUIRED")
			return
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
		if e != nil || c.wire.Validate("ChallengeRequest", raw) != nil {
			failure(w, 422, "SCHEMA_INVALID")
			return
		}
		var req contracts.ChallengeRequest
		_ = json.Unmarshal(raw, &req)
		if (req.Purpose != "heartbeat" && req.Purpose != "cert_renew") || len(req.Sources) != 1 || req.Sources[0] != claims.Source {
			failure(w, 403, "FORBIDDEN")
			return
		}
		status, b, e := c.post(r.Context(), "/api/v1/machine/heartbeat-challenges", raw, "")
		if e != nil {
			failure(w, 503, "CENTER_UNAVAILABLE")
			return
		}
		if status == 200 && c.wire.Validate("ChallengeResponse", b) != nil {
			failure(w, 503, "INVALID_CENTER_RESPONSE")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		_, _ = w.Write(b)
	})
	mux.HandleFunc("POST /api/v1/machine/heartbeats", func(w http.ResponseWriter, r *http.Request) {
		claims, e := c.peer(r)
		if e != nil {
			failure(w, 401, "AUTHENTICATION_REQUIRED")
			return
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
		if e != nil || c.wire.Validate("SignedHeartbeat", raw) != nil {
			failure(w, 422, "SCHEMA_INVALID")
			return
		}
		var signed contracts.SignedHeartbeat
		_ = json.Unmarshal(raw, &signed)
		var h contracts.Heartbeat
		_ = json.Unmarshal(signed.Payload, &h)
		if h.Tenant != claims.Tenant || h.Origin.SourceID != claims.Source || h.Origin.GenerationID != claims.Generation || h.Origin.SourceKind != claims.Kind || signed.KeyID != claims.KeyID {
			failure(w, 403, "FORBIDDEN")
			return
		}
		canonical, e := wire.Canonical(signed.Payload)
		sum := sha256.Sum256(canonical)
		sig, decode := base64.RawURLEncoding.Strict().DecodeString(signed.Signature)
		if e != nil || decode != nil || hex.EncodeToString(sum[:]) != signed.Digest || !ed25519.Verify(claims.SigningPublic, append([]byte("SURVEYSCAN-HEARTBEAT-V1\n"), canonical...), sig) {
			failure(w, 422, "SIGNATURE_INVALID")
			return
		}
		status, b, e := c.post(r.Context(), "/api/v1/machine/heartbeats", raw, "")
		if e != nil {
			failure(w, 503, "CENTER_UNAVAILABLE")
			return
		}
		if status == 200 && c.wire.Validate("HeartbeatResult", b) != nil {
			failure(w, 503, "INVALID_CENTER_RESPONSE")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		_, _ = w.Write(b)
	})

	mux.HandleFunc("POST /api/v1/machine/renewals", func(w http.ResponseWriter, r *http.Request) {
		claims, e := c.peer(r)
		if e != nil {
			failure(w, 401, "AUTHENTICATION_REQUIRED")
			return
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
		if e != nil || c.wire.Validate("RenewRequest", raw) != nil {
			failure(w, 422, "SCHEMA_INVALID")
			return
		}
		var signed contracts.RenewRequest
		_ = json.Unmarshal(raw, &signed)
		var h contracts.Renewal
		_ = json.Unmarshal(signed.Payload, &h)
		if h.Tenant != claims.Tenant || h.Origin.SourceID != claims.Source || h.Origin.GenerationID != claims.Generation || h.Origin.SourceKind != claims.Kind || signed.KeyID != claims.KeyID {
			failure(w, 403, "FORBIDDEN")
			return
		}
		canonical, e := wire.Canonical(signed.Payload)
		sum := sha256.Sum256(canonical)
		sig, decode := base64.RawURLEncoding.Strict().DecodeString(signed.Signature)
		if e != nil || decode != nil || hex.EncodeToString(sum[:]) != signed.Digest || !ed25519.Verify(claims.SigningPublic, append([]byte("SURVEYSCAN-RENEWAL-V1\n"), canonical...), sig) {
			failure(w, 422, "SIGNATURE_INVALID")
			return
		}
		status, b, e := c.post(r.Context(), "/api/v1/machine/renewals", raw, "")
		if e != nil {
			failure(w, 503, "CENTER_UNAVAILABLE")
			return
		}
		if status == 200 && c.wire.Validate("EnrollmentResult", b) != nil {
			failure(w, 503, "INVALID_CENTER_RESPONSE")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		_, _ = w.Write(b)
	})

	mux.HandleFunc("POST /api/v1/machine/enroll", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			failure(w, 401, "AUTHENTICATION_REQUIRED")
			return
		}
		headers := r.Header.Values("Authorization")
		if len(headers) != 1 {
			failure(w, 401, "AUTHENTICATION_REQUIRED")
			return
		}
		parts := strings.Fields(headers[0])
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) != 43 {
			failure(w, 401, "AUTHENTICATION_REQUIRED")
			return
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
		if e != nil {
			failure(w, 413, "PAYLOAD_TOO_LARGE")
			return
		}
		if e = c.wire.Validate("EnrollmentRequest", raw); e != nil {
			failure(w, 422, "SCHEMA_INVALID")
			return
		}
		status, b, e := c.post(r.Context(), "/api/v1/machine/enroll", raw, parts[1])
		if e != nil {
			failure(w, 503, "TEMPORARILY_UNAVAILABLE")
			return
		}
		if status != 201 {
			failure(w, status, "ENROLLMENT_REJECTED")
			return
		}
		if e = c.wire.Validate("EnrollmentResult", b); e != nil {
			failure(w, 503, "TEMPORARILY_UNAVAILABLE")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(201)
		_, _ = w.Write(b)
	})
	mux.HandleFunc("POST /api/v1/machine/observations", func(w http.ResponseWriter, r *http.Request) {
		claims, e := c.peer(r)
		if e != nil {
			failure(w, 401, "AUTHENTICATION_REQUIRED")
			return
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 1048576))
		if e != nil {
			failure(w, 413, "PAYLOAD_TOO_LARGE")
			return
		}
		decoded, e := c.decodeBatch(raw)
		if e != nil {
			failure(w, 422, "SCHEMA_INVALID")
			return
		}
		batch := decoded.Batch
		if batch.TenantID != claims.Tenant {
			failure(w, 403, "FORBIDDEN")
			return
		}
		seen := map[string]bool{}
		for _, record := range batch.Records {
			signed, o, canonical, e := c.observation(record)
			if e != nil || o.TenantID != claims.Tenant || o.Origin.SourceID != claims.Source || o.Origin.GenerationID != claims.Generation || o.Origin.SourceKind != "agent" || signed.KeyID != claims.KeyID || seen[o.ID] {
				failure(w, 422, "SCHEMA_INVALID")
				return
			}
			sum := sha256.Sum256(canonical)
			sig, e := base64.RawURLEncoding.Strict().DecodeString(signed.Signature)
			if e != nil || signed.Digest != hex.EncodeToString(sum[:]) || !ed25519.Verify(claims.SigningPublic, append([]byte("SURVEYSCAN-OBSERVATION-V1\n"), canonical...), sig) {
				failure(w, 422, "SIGNATURE_INVALID")
				return
			}
			seen[o.ID] = true
		}
		canonical, e := wire.Canonical(raw)
		if e != nil {
			failure(w, 422, "SCHEMA_INVALID")
			return
		}
		sum := sha256.Sum256(canonical)
		p := packet{Tenant: claims.Tenant, Source: claims.Source, ID: batch.DeliveryID, Digest: hex.EncodeToString(sum[:]), Batch: canonical}
		c.mu.Lock()
		defer c.mu.Unlock()
		for _, suffix := range []string{".pending", ".receipt"} {
			if old, e := readPacket(c.path(p.ID, suffix)); e == nil {
				if old.Tenant != p.Tenant || old.Source != p.Source || old.Digest != p.Digest {
					failure(w, 409, "CONFLICT")
					return
				}
				reply(w, 202, contracts.TransportReceipt{Type: "transport", TenantID: p.Tenant, DeliveryID: p.ID, Digest: p.Digest, Stage: "collector_received", SpoolAction: "retain", RequestID: identifier.New()})
				return
			}
		}
		body, e := marshalPacket(p)
		if e != nil {
			failure(w, 503, "TEMPORARILY_UNAVAILABLE")
			return
		}
		if e = diskspool.Data(c.Config.Spool, c.Config.Limit-diskspool.AckReserve, int64(len(body))); e != nil {
			w.Header().Set("Retry-After", "30")
			failure(w, 429, "SPOOL_FULL")
			return
		}
		if e = atomicWrite(c.path(p.ID, ".pending"), body); e != nil {
			failure(w, 503, "TEMPORARILY_UNAVAILABLE")
			return
		}
		reply(w, 202, contracts.TransportReceipt{Type: "transport", TenantID: p.Tenant, DeliveryID: p.ID, Digest: p.Digest, Stage: "collector_received", SpoolAction: "retain", RequestID: identifier.New()})
	})
	mux.HandleFunc("GET /api/v1/machine/deliveries/{delivery_id}", func(w http.ResponseWriter, r *http.Request) {
		claims, e := c.peer(r)
		if e != nil {
			failure(w, 401, "AUTHENTICATION_REQUIRED")
			return
		}
		id := r.PathValue("delivery_id")
		if !identifier.Valid(id) {
			failure(w, 404, "NOT_FOUND")
			return
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		for _, suffix := range []string{".receipt", ".pending"} {
			p, e := readPacket(c.path(id, suffix))
			if e != nil {
				continue
			}
			if p.Tenant != claims.Tenant || p.Source != claims.Source {
				failure(w, 404, "NOT_FOUND")
				return
			}
			if len(p.Receipt) > 0 {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "no-store")
				_, _ = w.Write(p.Receipt)
				return
			}
			reply(w, 200, contracts.TransportReceipt{Type: "transport", TenantID: p.Tenant, DeliveryID: p.ID, Digest: p.Digest, Stage: "collector_received", SpoolAction: "retain", RequestID: identifier.New()})
			return
		}
		failure(w, 404, "NOT_FOUND")
	})
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, r *http.Request) { reply(w, 200, map[string]string{"status": "ok"}) })
	return mux
}
func (c *Collector) verify(p packet, raw []byte) (bool, error) {
	if c.protocol != nil {
		_, remove, e := c.protocol.VerifyCenterResult(raw, p.Batch, c.Claims.CenterKeyID, c.Claims.CenterPublic)
		return remove, e
	}
	_, remove, e := c.wire.VerifyCenterResult(raw, p.Batch, c.Claims.CenterKeyID, c.Claims.CenterPublic)
	return remove, e
}
func (c *Collector) Pump(ctx context.Context) error {
	c.pump.Lock()
	defer c.pump.Unlock()
	if c.retries == nil {
		c.retries = map[string]*retry.Backoff{}
	}
	c.mu.Lock()
	entries, e := os.ReadDir(c.Config.Spool)
	c.mu.Unlock()
	if e != nil {
		return e
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".pending") {
			continue
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		path := filepath.Join(c.Config.Spool, entry.Name())
		c.mu.Lock()
		p, e := readPacket(path)
		if e != nil {
			c.mu.Unlock()
			return errors.New("spool record unreadable")
		}
		if cached, err := readPacket(c.path(p.ID, ".receipt")); err == nil {
			if cached.ID != p.ID || cached.Source != p.Source || cached.Tenant != p.Tenant || cached.Digest != p.Digest {
				c.mu.Unlock()
				return errors.New("cached receipt binding corrupted")
			}
			remove, verify := c.verify(p, cached.Receipt)
			if verify != nil {
				c.mu.Unlock()
				return errors.New("cached receipt verification failed")
			}
			if remove {
				e = os.Remove(path)
				if e == nil {
					e = diskspool.SyncDir(c.Config.Spool)
				}
			} else {
				e = nil
			}
			c.mu.Unlock()
			if e != nil {
				return e
			}
			continue
		}
		c.mu.Unlock()
		state := c.retries[p.ID]
		if state == nil {
			state = &retry.Backoff{}
			c.retries[p.ID] = state
		}
		if !state.Ready(time.Now()) {
			continue
		}
		_, raw, e := c.post(ctx, "/api/v1/machine/observations", p.Batch, "")
		if e != nil {
			state.Failed(time.Now())
			continue
		}
		remove, e := c.verify(p, raw)
		if e != nil {
			state.Failed(time.Now())
			continue
		}
		delete(c.retries, p.ID)
		cached := p
		cached.Batch = nil
		cached.Receipt = raw
		body, e := marshalPacket(cached)
		if e != nil {
			return e
		}
		c.mu.Lock()
		e = diskspool.Capacity(c.Config.Spool, c.Config.Limit, int64(len(body)))
		if e == nil {
			e = atomicWrite(c.path(p.ID, ".receipt"), body)
		}
		if e == nil && remove {
			e = os.Remove(path)
			if e == nil {
				var dir *os.File
				dir, e = os.Open(c.Config.Spool)
				if e == nil {
					e = dir.Sync()
					dir.Close()
				}
			}
		}
		c.mu.Unlock()
		if e != nil {
			return e
		}
	}
	return nil
}
func (c *Collector) Run(ctx context.Context) error {
	unlock, e := diskspool.Lock(c.Config.Spool)
	if e != nil {
		return e
	}
	defer unlock()
	credentialsUnlock, e := c.lockCredentials()
	if e != nil {
		return e
	}
	defer credentialsUnlock()
	if e = diskspool.RecoverTemps(c.Config.Spool); e != nil {
		return e
	}
	server := &http.Server{Addr: c.Config.Listen, Handler: c.Handler(), TLSConfig: c.TLS, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	defer server.Close()
	finished := make(chan error, 1)
	go func() { finished <- server.ListenAndServeTLS("", "") }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	renewalAt, profileAt, heartbeatAt := time.Time{}, time.Time{}, time.Time{}
	for {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return server.Shutdown(shutdown)
		case e := <-finished:
			if e == http.ErrServerClosed {
				return nil
			}
			return errors.New("collector HTTPS listener failed")
		case <-ticker.C:
			if c.Config.CredentialState != "" {
				if !time.Now().Before(profileAt) {
					task, cancel := context.WithTimeout(ctx, 3*time.Second)
					err := c.pollProfile(task)
					cancel()
					if err != nil && ctx.Err() == nil {
						telemetry.Log(os.Stderr, "collector", "profile_unavailable_cached_or_local")
					}
					profileAt = time.Now().Add(20 * time.Second)
				}
				if !time.Now().Before(heartbeatAt) {
					task, cancel := context.WithTimeout(ctx, 3*time.Second)
					err := c.heartbeat(task)
					cancel()
					if err != nil && ctx.Err() == nil {
						telemetry.Log(os.Stderr, "collector", "heartbeat_failed")
					}
					interval := 60
					if c.profile != nil && c.profile.Managed {
						interval = c.profile.Config.Heartbeat
					}
					heartbeatAt = time.Now().Add(time.Duration(interval) * time.Second)
				}
			}
			if c.Config.CredentialState != "" && !time.Now().Before(renewalAt) && machinecred.Due(c.Config.CredentialState, c.certificate.Load().Leaf.NotAfter, c.clock()) {
				task, cancel := context.WithTimeout(ctx, 15*time.Second)
				err := c.renew(task)
				cancel()
				if err != nil && ctx.Err() == nil {
					telemetry.Log(os.Stderr, "collector", "renewal_pending")
				}
				renewalAt = time.Now().Add(time.Minute)
			}
			task, cancel := context.WithTimeout(ctx, 15*time.Second)
			e := c.Pump(task)
			cancel()
			if e != nil && ctx.Err() == nil {
				telemetry.Log(os.Stderr, "collector", "spool_operation_failed")
			}
		}
	}
}
