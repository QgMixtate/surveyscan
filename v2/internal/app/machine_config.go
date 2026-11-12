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
	"github.com/QgMixtate/surveyscan/v2/internal/modules/inventory"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/bao"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/pki"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

type MachineConfig struct {
	Inventory12 bool `json:"inventory12_enabled"`
	// C26, 3А: порог давности приоритета источников в часах (нет — 24, 0 — только приоритет)
	PriorityStaleHours *int `json:"priority_stale_after_hours,omitempty"`
	// C29: сервис поиска surveyscan-search (loopback) и приватный файл его токена; пусто — только точный поиск по PostgreSQL
	SearchURL         string `json:"search_url,omitempty"`
	SearchTokenFile   string `json:"search_token_file,omitempty"`
	BaoConfig         string `json:"openbao_config_file"`
	CenterKeyID       string `json:"center_signing_key_id"`
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
	if e != nil || (cfg.BaoConfig == "" && (!cfg.DevMode || (host != "127.0.0.1" && host != "localhost" && host != "::1"))) {
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
	var issuer pki.Issuer
	var remote *bao.Client
	if cfg.BaoConfig != "" {
		if cfg.CAKey != "" || cfg.CenterKey != "" || !identifier.Valid(cfg.CenterKeyID) {
			return "", nil, errors.New("OpenBao mode cannot use local private signing keys")
		}
		remote, e = bao.Load(cfg.BaoConfig)
		if e != nil || (!cfg.DevMode && !remote.Secure()) {
			return "", nil, errors.New("invalid scoped OpenBao configuration")
		}
		caPublic, e := remote.Public("ca")
		if e != nil {
			return "", nil, e
		}
		expected, _ := x509.MarshalPKIXPublicKey(ca.PublicKey)
		actual, _ := x509.MarshalPKIXPublicKey(caPublic)
		if !bytes.Equal(expected, actual) {
			return "", nil, errors.New("CA public metadata mismatch")
		}
		issuer = bao.Issuer{Client: remote, Certificate: ca, Chain: caPEM}
	} else {
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
		issuer = &pki.Authority{Certificate: ca, Key: signer, Chain: caPEM}
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
	var centerID string
	var public ed25519.PublicKey
	var privateKey ed25519.PrivateKey
	if remote != nil {
		centerID = cfg.CenterKeyID
		public, e = remote.Public("center")
		if e != nil {
			return "", nil, e
		}
		caPublic, _ := remote.Public("ca")
		if bytes.Equal(public, caPublic) {
			return "", nil, errors.New("CA and receipt keys must differ")
		}
	} else {
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
		privateKey = ed25519.PrivateKey(raw)
		if !bytes.Equal(privateKey, ed25519.NewKeyFromSeed(privateKey.Seed())) {
			return "", nil, errors.New("inconsistent center signing key")
		}

		centerID = center.ID
		public = privateKey.Public().(ed25519.PublicKey)
	}
	if cfg.PriorityStaleHours != nil {
		if *cfg.PriorityStaleHours < 0 || *cfg.PriorityStaleHours > 24*365 {
			return "", nil, errors.New("priority_stale_after_hours must be 0..8760")
		}
		inventory.SetPriorityStaleAfter(time.Duration(*cfg.PriorityStaleHours) * time.Hour)
	}
	if cfg.SearchURL != "" {
		if !strings.HasPrefix(cfg.SearchURL, "http://127.0.0.1:") && !strings.HasPrefix(cfg.SearchURL, "http://[::1]:") {
			return "", nil, errors.New("search_url must be a loopback address")
		}
		token, e := ReadPrivate(cfg.SearchTokenFile, 4096)
		if e != nil {
			return "", nil, e
		}
		r.Search = &SearchClient{BaseURL: cfg.SearchURL, Token: strings.TrimSpace(string(token))}
	}
	var inventoryProtocol *wire.InventoryDecoder
	if cfg.Inventory12 {
		inventoryProtocol, e = r.ConfigureInventoryProtocol12(true)
		if e != nil {
			return "", nil, e
		}
	}
	machine := &sources.MachineService{Pool: r.Pool, Auth: auth, Audit: audit.Store{}, Issuer: issuer, Wire: r.Wire, CenterKeyID: centerID, CenterPublicKey: base64.RawURLEncoding.EncodeToString(public)}
	uploads := &imports.UploadService{Pool: r.Pool, Auth: machine, Registry: MachineRegistry{Registry: r, Auth: machine}, Wire: r.Wire, Protocol: inventoryProtocol, KeyID: centerID, Key: privateKey}
	if remote != nil {
		uploads.Signer = bao.Operation{Client: remote, Alias: "center"}
	}
	r.Machine = &MachineAPI{Sources: machine, Uploads: uploads}
	if remote != nil {
		r.Machine.Maintain = remote.Maintain
		r.Machine.Ready = remote.Check
	}
	return cfg.Listen, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, ClientCAs: roots, ClientAuth: tls.VerifyClientCertIfGiven}, nil
}
