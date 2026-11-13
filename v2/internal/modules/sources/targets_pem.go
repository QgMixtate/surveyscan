package sources

import (
	"crypto/x509"
	"encoding/pem"
)

type pemBlock = pem.Block

func decodePEM(b []byte) (*pem.Block, []byte) { return pem.Decode(b) }

func parseCert(der []byte) (*x509.Certificate, error) { return x509.ParseCertificate(der) }
