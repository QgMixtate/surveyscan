package collector

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/diskspool"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/machinecred"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/pki"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/privatefile"
)

func readCredential(cfg Config) ([]byte, []byte, error) {
	if (cfg.CredentialState == "") != (cfg.SigningKey == "") {
		return nil, nil, errors.New("collector renewal requires credential directory and signing key together")
	}
	if cfg.CredentialState != "" {
		if !filepath.IsAbs(cfg.CredentialState) || !filepath.IsAbs(cfg.SigningKey) {
			return nil, nil, errors.New("absolute collector credential paths required")
		}
		spool, e := filepath.Abs(cfg.Spool)
		if e != nil {
			return nil, nil, e
		}
		a := filepath.Clean(cfg.CredentialState)
		b := filepath.Clean(spool)
		if a == b || strings.HasPrefix(a, b+string(os.PathSeparator)) || strings.HasPrefix(b, a+string(os.PathSeparator)) {
			return nil, nil, errors.New("credential directory and spool must not overlap")
		}
		if e = os.MkdirAll(a, 0700); e != nil {
			return nil, nil, e
		}
		info, e := os.Lstat(a)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, nil, errors.New("private collector credential directory required")
		}
		if e = os.Chmod(a, 0700); e != nil {
			return nil, nil, e
		}
		var identity machinecred.Identity
		exists, e := machinecred.ReadOptional(filepath.Join(a, "tls-identity.json"), &identity)
		if e != nil {
			return nil, nil, e
		}
		if exists {
			return []byte(identity.Result.Chain), []byte(identity.Private), nil
		}
	}
	cert, e := os.ReadFile(cfg.Certificate)
	if e != nil || len(cert) > 65536 {
		return nil, nil, errors.New("collector certificate unavailable")
	}
	key, e := privatefile.Read(cfg.PrivateKey, 16384)
	if e != nil {
		return nil, nil, e
	}
	return cert, key, nil
}
func readSigningKey(path string) (ed25519.PrivateKey, error) {
	raw, e := privatefile.Read(path, 16384)
	if e != nil {
		return nil, e
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" || len(strings.TrimSpace(string(rest))) > 0 {
		return nil, errors.New("invalid collector signing key")
	}
	parsed, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		return nil, errors.New("invalid collector signing key")
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("collector origin requires Ed25519 signing key")
	}
	return key, nil
}
func (c *Collector) lockCredentials() (func(), error) {
	if c.Config.CredentialState == "" {
		return func() {}, nil
	}
	unlock, e := diskspool.Lock(c.Config.CredentialState)
	if e != nil {
		return nil, e
	}
	if e = diskspool.RecoverTemps(c.Config.CredentialState); e != nil {
		unlock()
		return nil, e
	}
	var current machinecred.Identity
	exists, e := machinecred.ReadOptional(filepath.Join(c.Config.CredentialState, "tls-identity.json"), &current)
	if e != nil {
		unlock()
		return nil, e
	}
	if exists {
		if e = c.activate(current); e != nil {
			unlock()
			return nil, e
		}
	}
	return unlock, nil
}

// renew is called under the process credential lock. Pair swap is shared by both TLS directions.
func (c *Collector) renew(ctx context.Context) error {
	c.renewMu.Lock()
	defer c.renewMu.Unlock()
	if c.Config.CredentialState == "" {
		return errors.New("collector renewal configuration required")
	}
	engine := machinecred.Engine{Directory: c.Config.CredentialState, Claims: c.Claims, Signing: c.signing, Roots: c.roots, Wire: c.wire, Post: func(ctx context.Context, path string, raw []byte) (int, []byte, error) {
		return c.post(ctx, path, raw, "")
	}}
	if e := engine.Renew(ctx); e != nil {
		return e
	}
	var identity machinecred.Identity
	exists, e := machinecred.ReadOptional(filepath.Join(c.Config.CredentialState, "tls-identity.json"), &identity)
	if e != nil {
		return e
	}
	if !exists {
		return errors.New("renewed collector credential unavailable")
	}
	return c.activate(identity)
}
func (c *Collector) activate(identity machinecred.Identity) error {
	claims, e := pki.VerifyEnrollmentResult(identity.Result, c.roots, c.Claims.Source, c.signing.Public().(ed25519.PublicKey))
	if e != nil || claims.Kind != c.Claims.Kind || claims.Tenant != c.Claims.Tenant || claims.Generation != c.Claims.Generation || claims.Collector != c.Claims.Collector || claims.KeyID != c.Claims.KeyID || claims.CenterKeyID != c.Claims.CenterKeyID || !bytes.Equal(claims.CenterPublic, c.Claims.CenterPublic) {
		return errors.New("renewed collector identity invalid")
	}
	pair, e := tls.X509KeyPair([]byte(identity.Result.Chain), []byte(identity.Private))
	if e != nil {
		return errors.New("renewed collector key mismatch")
	}
	pair.Leaf, e = x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return e
	}
	if _, e = pair.Leaf.Verify(x509.VerifyOptions{Roots: c.roots, DNSName: c.Claims.Source + ".collector.invalid", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); e != nil {
		return errors.New("renewed collector server identity invalid")
	}
	c.certificate.Store(&pair)
	c.client.CloseIdleConnections()
	return nil
}

func (c *Collector) RenewOnce(ctx context.Context) error {
	unlock, e := diskspool.Lock(c.Config.Spool)
	if e != nil {
		return e
	}
	defer unlock()
	unlockCredentials, e := c.lockCredentials()
	if e != nil {
		return e
	}
	defer unlockCredentials()
	return c.renew(ctx)
}
