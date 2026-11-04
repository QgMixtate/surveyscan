package agent

import (
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
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/diskspool"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/pki"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
	"os"
	"path/filepath"
	"time"
)

// TLS result and matching private key form one atomic commit, never two independent file replacements.
type tlsIdentity struct {
	Result  contracts.EnrollmentResult `json:"result"`
	Private string                     `json:"private_key_pem"`
}
type renewalPending struct {
	Request contracts.RenewRequest `json:"request"`
	Private string                 `json:"private_key_pem"`
}

func (c *Client) Renew(ctx context.Context) error {
	path := filepath.Join(c.cfg.State, "renewal.pending.json")
	var pending renewalPending
	exists, e := loadOptionalJSON(path, &pending)
	if e != nil {
		return e
	}
	if !exists {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: c.claims.Source}}, key)
		if err != nil {
			return err
		}
		private, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}
		req := contracts.ChallengeRequest{Sources: []string{c.claims.Source}, Purpose: "cert_renew"}
		raw, _ := json.Marshal(req)
		code, b, err := request(ctx, c.http, c.cfg.CollectorURL, "POST", "/api/v1/machine/heartbeat-challenges", raw, "")
		if err != nil || code != 200 || c.wire.Validate("ChallengeResponse", b) != nil {
			return errors.New("renewal challenge unavailable")
		}
		var challenges contracts.ChallengeResponse
		_ = json.Unmarshal(b, &challenges)
		if len(challenges.Challenges) != 1 {
			return errors.New("invalid renewal challenge")
		}
		ch := challenges.Challenges[0]
		if ch.Purpose != "cert_renew" || ch.Tenant != c.claims.Tenant || ch.Source != c.claims.Source || ch.Generation != c.claims.Generation || !time.Now().Before(ch.Expires) {
			return errors.New("renewal challenge binding invalid")
		}
		payload := contracts.Renewal{Version: contracts.Version{Major: 1}, ID: identifier.New(), Tenant: c.claims.Tenant, Origin: contracts.Origin{SourceID: c.claims.Source, SourceKind: c.claims.Kind, GenerationID: c.claims.Generation}, Challenge: ch.ID, Nonce: ch.Nonce, CSR: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), Sent: time.Now().UTC()}
		raw, _ = json.Marshal(payload)
		canonical, err := wire.Canonical(raw)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(canonical)
		pending = renewalPending{Request: contracts.RenewRequest{Payload: raw, Digest: hex.EncodeToString(digest[:]), KeyID: c.claims.KeyID, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(c.key, append([]byte("SURVEYSCAN-RENEWAL-V1\n"), canonical...)))}, Private: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))}
		if e = saveJSON(path, pending); e != nil {
			return e
		}
	} else if e != nil {
		return e
	}
	raw, _ := json.Marshal(pending.Request)
	code, b, e := request(ctx, c.http, c.cfg.CollectorURL, "POST", "/api/v1/machine/renewals", raw, "")
	if e != nil {
		return e
	}
	if code != 200 {
		if code == 409 {
			// A missing/expired challenge is not a committed result. Next attempt gets a fresh nonce.
			// A prior committed result is returned by the server before challenge expiry is checked.
			if e = clearRenewal(path); e != nil {
				return e
			}
			return errors.New("renewal challenge expired; retry with a fresh challenge")
		}
		return errors.New("certificate renewal unavailable")
	}
	if c.wire.Validate("EnrollmentResult", b) != nil {
		return errors.New("invalid renewal result")
	}
	var result contracts.EnrollmentResult
	_ = json.Unmarshal(b, &result)
	roots, e := rootsFor(c.cfg)
	if e != nil {
		return e
	}
	claims, e := pki.VerifyEnrollmentResult(result, roots, c.claims.Source, c.key.Public().(ed25519.PublicKey))
	if e != nil || claims.Generation != c.claims.Generation || claims.Tenant != c.claims.Tenant || claims.Kind != c.claims.Kind || claims.Collector != c.claims.Collector || claims.KeyID != c.claims.KeyID || claims.CenterKeyID != c.claims.CenterKeyID || !ed25519.PublicKey(claims.CenterPublic).Equal(ed25519.PublicKey(c.claims.CenterPublic)) {
		return errors.New("renewal identity binding invalid")
	}
	pair, e := tls.X509KeyPair([]byte(result.Chain), []byte(pending.Private))
	if e != nil {
		return errors.New("renewal TLS key mismatch")
	}
	client, e := newHTTP(c.cfg, roots, &pair, claims.Collector)
	if e != nil {
		return e
	}
	if e = saveJSON(filepath.Join(c.cfg.State, "tls-identity.json"), tlsIdentity{Result: result, Private: pending.Private}); e != nil {
		client.CloseIdleConnections()
		return e
	}
	c.http.CloseIdleConnections()
	c.http = client
	c.claims = claims
	// Keep pending on cleanup failure: restart replays the same result, not a new CSR/key.
	if e = clearRenewal(path); e != nil {
		return e
	}
	return nil
}
func clearRenewal(path string) error {
	if e := os.Remove(path); e != nil && !os.IsNotExist(e) {
		return e
	}
	return diskspool.SyncDir(filepath.Dir(path))
}

// RenewOnce shares the daemon lock; never mutates identity underneath a running sender.
func RenewOnce(ctx context.Context, c Config) error {
	unlock, e := lockState(c.State)
	if e != nil {
		return e
	}
	defer unlock()
	client, e := Open(c)
	if e != nil {
		return e
	}
	defer func() { client.http.CloseIdleConnections() }()
	return client.Renew(ctx)
}
func (c *Client) renewalDue(now time.Time) bool {
	if _, e := os.Stat(filepath.Join(c.cfg.State, "renewal.pending.json")); e == nil {
		return true
	}
	var current tlsIdentity
	if e := loadJSON(filepath.Join(c.cfg.State, "tls-identity.json"), &current); e == nil {
		return !now.Before(current.Result.Expires.Add(-time.Hour))
	}
	var initial contracts.EnrollmentResult
	return loadJSON(filepath.Join(c.cfg.State, "identity.json"), &initial) == nil && !now.Before(initial.Expires.Add(-time.Hour))
}

// privatefile.Read intentionally sanitizes OS errors. Inspect absence before strict loading;
// permission/parse/racing disappearance must never silently downgrade to legacy credentials.
func loadOptionalJSON(path string, out any) (bool, error) {
	_, e := os.Lstat(path)
	if os.IsNotExist(e) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	if e = loadJSON(path, out); e != nil {
		return false, e
	}
	return true, nil
}
