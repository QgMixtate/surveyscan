package app

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/audit"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/imports"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/pki"
	"io"
	"net"
	"os"
)

type MachineConfig struct {
	DevMode           bool   `json:"dev_mode"`
	Listen            string `json:"listen"`
	CACertificate     string `json:"ca_certificate_file"`
	CAKey             string `json:"ca_private_key_file"`
	ServerCertificate string `json:"server_certificate_file"`
	ServerKey         string `json:"server_private_key_file"`
	CenterKey         string `json:"center_signing_key_file"`
}
type CenterKeyFile struct {
	ID      string `json:"key_id"`
	Private string `json:"private_key"`
}

func ReadPrivate(path string, max int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, errors.New("private configuration file unavailable")
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > max {
		return nil, errors.New("configuration/key file must be private regular file within size bound")
	}
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(b)) > max {
		return nil, errors.New("private file read failed")
	}
	return b, nil
}
func ConfigureMachine(path string, r *Registry, auth *access.Service) (string, *tls.Config, error) {
	b, e := ReadPrivate(path, 65536)
	if e != nil {
		return "", nil, e
	}
	var cfg MachineConfig
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if e = decoder.Decode(&cfg); e != nil {
		return "", nil, errors.New("invalid machine configuration")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return "", nil, errors.New("invalid machine configuration")
	}
	host, _, e := net.SplitHostPort(cfg.Listen)
	if e != nil || !cfg.DevMode || (host != "127.0.0.1" && host != "localhost" && host != "::1") {
		return "", nil, errors.New("file-backed machine issuer requires explicit loopback dev mode; production issuer is C11")
	}
	caPEM, e := os.ReadFile(cfg.CACertificate)
	if e != nil || len(caPEM) > 65536 {
		return "", nil, errors.New("machine CA certificate unavailable")
	}
	block, rest := pem.Decode(caPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return "", nil, errors.New("invalid CA certificate")
	}
	ca, e := x509.ParseCertificate(block.Bytes)
	if e != nil || !ca.IsCA {
		return "", nil, errors.New("invalid CA certificate")
	}
	private, e := ReadPrivate(cfg.CAKey, 16384)
	if e != nil {
		return "", nil, e
	}
	block, rest = pem.Decode(private)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return "", nil, errors.New("PKCS8 CA key required")
	}
	key, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		return "", nil, errors.New("invalid CA key")
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return "", nil, errors.New("CA signing key required")
	}
	expected, _ := x509.MarshalPKIXPublicKey(ca.PublicKey)
	actual, _ := x509.MarshalPKIXPublicKey(signer.Public())
	if !bytes.Equal(expected, actual) {
		return "", nil, errors.New("CA certificate/key mismatch")
	}
	serverPEM, e := os.ReadFile(cfg.ServerCertificate)
	if e != nil || len(serverPEM) > 65536 {
		return "", nil, errors.New("server certificate unavailable")
	}
	serverKey, e := ReadPrivate(cfg.ServerKey, 16384)
	if e != nil {
		return "", nil, e
	}
	pair, e := tls.X509KeyPair(serverPEM, serverKey)
	if e != nil {
		return "", nil, errors.New("invalid server certificate/key")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return "", nil, e
	}
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); e != nil {
		return "", nil, errors.New("server certificate not trusted by configured CA")
	}
	b, e = ReadPrivate(cfg.CenterKey, 4096)
	if e != nil {
		return "", nil, e
	}
	var center CenterKeyFile
	if e = json.Unmarshal(b, &center); e != nil {
		return "", nil, errors.New("invalid center signing configuration")
	}
	raw, e := base64.RawURLEncoding.Strict().DecodeString(center.Private)
	if e != nil || len(raw) != ed25519.PrivateKeySize || !identifier.Valid(center.ID) {
		return "", nil, errors.New("invalid center signing configuration")
	}
	privateKey := ed25519.PrivateKey(raw)
	if !bytes.Equal(privateKey, ed25519.NewKeyFromSeed(privateKey.Seed())) {
		return "", nil, errors.New("inconsistent center signing key")
	}
	machine := &sources.MachineService{Pool: r.Pool, Auth: auth, Audit: audit.Store{}, Issuer: &pki.Authority{Certificate: ca, Key: signer, Chain: caPEM}, Wire: r.Wire, CenterKeyID: center.ID, CenterPublicKey: base64.RawURLEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))}
	uploads := &imports.UploadService{Pool: r.Pool, Auth: machine, Registry: MachineRegistry{Registry: r, Auth: machine}, Wire: r.Wire, KeyID: center.ID, Key: privateKey}
	r.Machine = &MachineAPI{Sources: machine, Uploads: uploads}
	return cfg.Listen, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, ClientCAs: roots, ClientAuth: tls.VerifyClientCertIfGiven}, nil
}
