package pki

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
)

// VerifyEnrollmentResult использует заранее установленный CA, не root из ответа relay.
func VerifyEnrollmentResult(result contracts.EnrollmentResult, roots *x509.CertPool, source string, signing ed25519.PublicKey) (Claims, error) {
	var claims Claims
	if roots == nil || source != result.SourceID || len(result.Chain) > 32768 {
		return claims, domain.Invalid
	}
	rest := []byte(result.Chain)
	certificates := []*x509.Certificate{}
	for len(bytes.TrimSpace(rest)) > 0 {
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" {
			return claims, domain.Invalid
		}
		cert, e := x509.ParseCertificate(block.Bytes)
		if e != nil {
			return claims, domain.Invalid
		}
		certificates = append(certificates, cert)
		rest = next
	}
	if len(certificates) == 0 {
		return claims, domain.Invalid
	}
	intermediate := x509.NewCertPool()
	for _, c := range certificates[1:] {
		intermediate.AddCert(c)
	}
	if _, e := certificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediate, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
		return claims, domain.Invalid
	}
	claims, e := ClaimsFromCertificate(certificates[0])
	if e != nil || claims.Source != source || claims.Generation != result.GenerationID || claims.KeyID != result.KeyID || claims.CenterKeyID != result.CenterKeyID || !bytes.Equal(claims.SigningPublic, signing) || base64.RawURLEncoding.EncodeToString(claims.CenterPublic) != result.CenterPublicKey || !certificates[0].NotAfter.Equal(result.Expires) {
		return claims, domain.Invalid
	}
	return claims, nil
}
