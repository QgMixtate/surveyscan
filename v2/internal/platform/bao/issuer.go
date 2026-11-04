package bao

import (
	"context"
	"crypto/x509"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/pki"
)

type Issuer struct {
	Client      *Client
	Certificate *x509.Certificate
	Chain       []byte
}

func (i Issuer) Issue(ctx context.Context, csr *x509.CertificateRequest, claims pki.Claims) (pki.Issued, error) {
	a := pki.Authority{Certificate: i.Certificate, Chain: i.Chain, Key: Signer{Client: i.Client, Alias: "ca", Context: ctx}}
	return a.Issue(ctx, csr, claims)
}
