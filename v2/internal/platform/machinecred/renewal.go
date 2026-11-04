// Package machinecred shares durable TLS renewal between host agents and site collectors.
package machinecred

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
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/diskspool"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/pki"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/privatefile"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Caller holds its process/writer lock and uses an authenticated HTTPS Post transport.
type Engine struct {
	Directory string
	Claims    pki.Claims
	Signing   ed25519.PrivateKey
	Roots     *x509.CertPool
	Wire      *wire.Validator
	Post      func(context.Context, string, []byte) (int, []byte, error)
}

// TLS result and matching private key form one atomic commit, never two independent file replacements.
type Identity struct {
	Result  contracts.EnrollmentResult `json:"result"`
	Private string                     `json:"private_key_pem"`
}
type pendingRequest struct {
	Request contracts.RenewRequest `json:"request"`
	Private string                 `json:"private_key_pem"`
}

func (c *Engine) Renew(ctx context.Context) error {
	if len(c.Signing) != ed25519.PrivateKeySize || c.Roots == nil || c.Wire == nil || c.Post == nil {
		return errors.New("renewal identity configuration unavailable")
	}
	path := filepath.Join(c.Directory, "renewal.pending.json")
	var pending pendingRequest
	exists, e := ReadOptional(path, &pending)
	if e != nil {
		return e
	}
	if !exists {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: c.Claims.Source}}, key)
		if err != nil {
			return err
		}
		private, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}
		req := contracts.ChallengeRequest{Sources: []string{c.Claims.Source}, Purpose: "cert_renew"}
		raw, _ := json.Marshal(req)
		code, b, err := c.Post(ctx, "/api/v1/machine/heartbeat-challenges", raw)
		if err != nil || code != 200 || c.Wire.Validate("ChallengeResponse", b) != nil {
			return errors.New("renewal challenge unavailable")
		}
		var challenges contracts.ChallengeResponse
		_ = json.Unmarshal(b, &challenges)
		if len(challenges.Challenges) != 1 {
			return errors.New("invalid renewal challenge")
		}
		ch := challenges.Challenges[0]
		if ch.Purpose != "cert_renew" || ch.Tenant != c.Claims.Tenant || ch.Source != c.Claims.Source || ch.Generation != c.Claims.Generation || !time.Now().Before(ch.Expires) {
			return errors.New("renewal challenge binding invalid")
		}
		payload := contracts.Renewal{Version: contracts.Version{Major: 1}, ID: identifier.New(), Tenant: c.Claims.Tenant, Origin: contracts.Origin{SourceID: c.Claims.Source, SourceKind: c.Claims.Kind, GenerationID: c.Claims.Generation}, Challenge: ch.ID, Nonce: ch.Nonce, CSR: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), Sent: time.Now().UTC()}
		raw, _ = json.Marshal(payload)
		canonical, err := wire.Canonical(raw)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(canonical)
		pending = pendingRequest{Request: contracts.RenewRequest{Payload: raw, Digest: hex.EncodeToString(digest[:]), KeyID: c.Claims.KeyID, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(c.Signing, append([]byte("SURVEYSCAN-RENEWAL-V1\n"), canonical...)))}, Private: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))}
		if e = writeJSON(path, pending); e != nil {
			return e
		}
	}
	raw, _ := json.Marshal(pending.Request)
	code, b, e := c.Post(ctx, "/api/v1/machine/renewals", raw)
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
	if c.Wire.Validate("EnrollmentResult", b) != nil {
		return errors.New("invalid renewal result")
	}
	var result contracts.EnrollmentResult
	_ = json.Unmarshal(b, &result)
	roots := c.Roots
	claims, e := pki.VerifyEnrollmentResult(result, roots, c.Claims.Source, c.Signing.Public().(ed25519.PublicKey))
	if e != nil || claims.Generation != c.Claims.Generation || claims.Tenant != c.Claims.Tenant || claims.Kind != c.Claims.Kind || claims.Collector != c.Claims.Collector || claims.KeyID != c.Claims.KeyID || claims.CenterKeyID != c.Claims.CenterKeyID || !ed25519.PublicKey(claims.CenterPublic).Equal(ed25519.PublicKey(c.Claims.CenterPublic)) {
		return errors.New("renewal identity binding invalid")
	}
	_, e = tls.X509KeyPair([]byte(result.Chain), []byte(pending.Private))
	if e != nil {
		return errors.New("renewal TLS key mismatch")
	}
	if e = writeJSON(filepath.Join(c.Directory, "tls-identity.json"), Identity{Result: result, Private: pending.Private}); e != nil {
		return e
	}
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

// ReadOptional distinguishes absence from a damaged/insecure credential. No silent fallback.
func ReadOptional(path string, out any) (bool, error) {
	info, e := os.Lstat(path)
	if os.IsNotExist(e) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	if !info.Mode().IsRegular() {
		return false, errors.New("private credential must be a regular file")
	}
	raw, e := privatefile.Read(path, 65536)
	if e != nil {
		return false, e
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return false, errors.New("invalid private credential state")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return false, errors.New("invalid private credential state")
	}
	return true, nil
}
func writeJSON(path string, value any) error {
	raw, e := json.Marshal(value)
	if e != nil {
		return e
	}
	return diskspool.Atomic(path, raw)
}
func Due(directory string, expiry, now time.Time) bool {
	if _, e := os.Lstat(filepath.Join(directory, "renewal.pending.json")); e == nil {
		return true
	}
	return !now.Before(expiry.Add(-time.Hour))
}
