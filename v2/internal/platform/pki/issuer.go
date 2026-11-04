// Package pki реализует ограниченный issuer для dev/test. Production issuer — C11.
package pki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"math/big"
	"net/url"
	"strings"
	"time"
)

type Claims struct {
	CenterKeyID                                        string
	CenterPublic                                       []byte
	Tenant, Source, Generation, Kind, Collector, KeyID string
	SigningPublic                                      []byte
}
type Issued struct {
	PEM  string
	Leaf *x509.Certificate
}
type Issuer interface {
	Issue(context.Context, *x509.CertificateRequest, Claims) (Issued, error)
}
type Authority struct {
	Certificate *x509.Certificate
	Key         crypto.Signer
	Chain       []byte
}

func ParseCSR(raw string) (*x509.CertificateRequest, string, error) {
	block, rest := pem.Decode([]byte(raw))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, "", domain.Invalid
	}
	csr, e := x509.ParseCertificateRequest(block.Bytes)
	if e != nil || csr.CheckSignature() != nil {
		return nil, "", domain.Invalid
	}
	switch key := csr.PublicKey.(type) {
	case ed25519.PublicKey:
		if len(key) != 32 {
			return nil, "", domain.Invalid
		}
	case *ecdsa.PublicKey:
		if key.Curve.Params().BitSize < 256 {
			return nil, "", domain.Invalid
		}
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 || key.N.BitLen() > 8192 || key.E < 65537 {
			return nil, "", domain.Invalid
		}
	default:
		return nil, "", domain.Invalid
	}
	digest := sha256.Sum256(csr.Raw)
	return csr, hex.EncodeToString(digest[:]), nil
}
func (a *Authority) Issue(ctx context.Context, csr *x509.CertificateRequest, c Claims) (Issued, error) {
	if ctx.Err() != nil {
		return Issued{}, ctx.Err()
	}
	if a.Certificate == nil || a.Key == nil || !a.Certificate.IsCA || !time.Now().Before(a.Certificate.NotAfter) {
		return Issued{}, domain.Invalid
	}
	for _, id := range []string{c.Tenant, c.Source, c.Generation, c.KeyID} {
		if !identifier.Valid(id) {
			return Issued{}, domain.Invalid
		}
	}
	if len(c.SigningPublic) != 32 || (c.Kind != "collector" && c.Kind != "agent" && c.Kind != "portable") {
		return Issued{}, domain.Invalid
	}
	if c.Collector != "" && !identifier.Valid(c.Collector) {
		return Issued{}, domain.Invalid
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return Issued{}, e
	}
	until := time.Now().UTC().Add(24 * time.Hour)
	if a.Certificate.NotAfter.Before(until) {
		until = a.Certificate.NotAfter.UTC()
	}
	identity, _ := url.Parse("spiffe://surveyscan/tenant/" + c.Tenant + "/source/" + c.Source + "/generation/" + c.Generation)
	role, _ := url.Parse("spiffe://surveyscan/kind/" + c.Kind + "/collector/" + c.Collector)
	signing, _ := url.Parse("spiffe://surveyscan/signing/" + c.KeyID + "/" + base64.RawURLEncoding.EncodeToString(c.SigningPublic))
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: c.Source}, NotBefore: time.Now().UTC().Add(-time.Minute), NotAfter: until, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{identity, role, signing}, BasicConstraintsValid: true}
	if c.CenterKeyID != "" {
		if !identifier.Valid(c.CenterKeyID) || len(c.CenterPublic) != 32 {
			return Issued{}, domain.Invalid
		}
		attestation, _ := url.Parse("spiffe://surveyscan/center-result/" + c.CenterKeyID + "/" + base64.RawURLEncoding.EncodeToString(c.CenterPublic))
		cert.URIs = append(cert.URIs, attestation)
	}
	if c.Kind == "collector" {
		cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
		cert.DNSNames = []string{c.Source + ".collector.invalid"}
	}
	der, e := x509.CreateCertificate(rand.Reader, cert, a.Certificate, csr.PublicKey, a.Key)
	if e != nil {
		return Issued{}, e
	}
	leaf, e := x509.ParseCertificate(der)
	if e != nil {
		return Issued{}, e
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	chain = append(chain, a.Chain...)
	return Issued{PEM: string(chain), Leaf: leaf}, nil
}
func ClaimsFromCertificate(cert *x509.Certificate) (Claims, error) {
	var c Claims
	if cert == nil || (len(cert.URIs) != 3 && len(cert.URIs) != 4) {
		return c, domain.Unauthorized
	}
	for _, u := range cert.URIs {
		if u.Scheme != "spiffe" || u.Host != "surveyscan" || u.RawQuery != "" || u.Fragment != "" {
			return c, domain.Unauthorized
		}
		parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
		switch {
		case len(parts) == 6 && parts[0] == "tenant" && parts[2] == "source" && parts[4] == "generation":
			c.Tenant, c.Source, c.Generation = parts[1], parts[3], parts[5]
		case len(parts) == 4 && parts[0] == "kind" && parts[2] == "collector":
			c.Kind, c.Collector = parts[1], parts[3]
		case len(parts) == 3 && parts[0] == "center-result":
			c.CenterKeyID = parts[1]
			key, e := base64.RawURLEncoding.Strict().DecodeString(parts[2])
			if e != nil || !identifier.Valid(c.CenterKeyID) || len(key) != 32 {
				return c, domain.Unauthorized
			}
			c.CenterPublic = key
		case len(parts) == 3 && parts[0] == "signing":
			c.KeyID = parts[1]
			key, e := base64.RawURLEncoding.Strict().DecodeString(parts[2])
			if e != nil {
				return c, domain.Unauthorized
			}
			c.SigningPublic = key
		default:
			return c, domain.Unauthorized
		}
	}
	for _, id := range []string{c.Tenant, c.Source, c.Generation, c.KeyID} {
		if !identifier.Valid(id) {
			return c, domain.Unauthorized
		}
	}
	if len(c.SigningPublic) != 32 {
		return c, domain.Unauthorized
	}
	return c, nil
}
func Fingerprint(c *x509.Certificate) string {
	hash := sha256.Sum256(c.Raw)
	return hex.EncodeToString(hash[:])
}
