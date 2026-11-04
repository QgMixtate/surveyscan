// Package bao выполняет узкие операции по заранее разрешённым references, без экспорта private keys.
package bao

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/privatefile"
)

var Unavailable = errors.New("OpenBao operation unavailable")
var Denied = errors.New("OpenBao scoped identity or reference denied")
var name = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,95}$`)

type Key struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
	Public  string `json:"public_key"`
}
type SecretRef struct {
	Path  string `json:"path"`
	Field string `json:"field"`
}
type Config struct {
	Address         string               `json:"address"`
	DevLoopbackHTTP bool                 `json:"dev_loopback_http"`
	TLSCAFile       string               `json:"tls_ca_file"`
	TokenFile       string               `json:"token_file"`
	Policy          string               `json:"policy"`
	TransitMount    string               `json:"transit_mount"`
	KVMount         string               `json:"kv_mount"`
	Keys            map[string]Key       `json:"keys"`
	Secrets         map[string]SecretRef `json:"secrets"`
}
type Client struct {
	cfg  Config
	http *http.Client
}

func Load(path string) (*Client, error) {
	raw, e := privatefile.Read(path, 65536)
	if e != nil {
		return nil, Denied
	}
	var cfg Config
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&cfg) != nil {
		return nil, Denied
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, Denied
	}
	return New(cfg)
}
func New(cfg Config) (*Client, error) {
	u, e := url.Parse(cfg.Address)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, Denied
	}
	loop := u.Hostname() == "127.0.0.1" || u.Hostname() == "::1" || u.Hostname() == "localhost"
	if u.Scheme != "https" && !(u.Scheme == "http" && cfg.DevLoopbackHTTP && loop) {
		return nil, Denied
	}
	if !filepath.IsAbs(cfg.TokenFile) || !name.MatchString(cfg.Policy) || cfg.Policy == "root" || cfg.Policy == "default" || !name.MatchString(cfg.TransitMount) {
		return nil, Denied
	}
	for alias, k := range cfg.Keys {
		if !name.MatchString(alias) || !name.MatchString(k.Name) || k.Version < 1 {
			return nil, Denied
		}
		pub, e := base64.RawURLEncoding.Strict().DecodeString(k.Public)
		if e != nil || len(pub) != 32 {
			return nil, Denied
		}
	}
	for alias, ref := range cfg.Secrets {
		if !name.MatchString(alias) || !name.MatchString(cfg.KVMount) || !validPath(ref.Path) || !name.MatchString(ref.Field) {
			return nil, Denied
		}
	}
	cfg.Address = strings.TrimRight(cfg.Address, "/")
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.TLSCAFile != "" {
		raw, e := os.ReadFile(cfg.TLSCAFile)
		if e != nil || len(raw) > 65536 {
			return nil, Denied
		}
		roots, e := x509.SystemCertPool()
		if e != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(raw) {
			return nil, Denied
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	return &Client{cfg: cfg, http: &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func validPath(path string) bool {
	if len(path) > 512 {
		return false
	}
	for _, p := range strings.Split(path, "/") {
		if !name.MatchString(p) {
			return false
		}
	}
	return true
}
func (c *Client) call(ctx context.Context, method, path, token string, value any, out any) error {
	var body io.Reader
	if value != nil {
		raw, e := json.Marshal(value)
		if e != nil {
			return Denied
		}
		body = bytes.NewReader(raw)
	}
	req, e := http.NewRequestWithContext(ctx, method, c.cfg.Address+"/v1/"+path, body)
	if e != nil {
		return Unavailable
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")
	response, e := c.http.Do(req)
	if e != nil {
		return Unavailable
	}
	defer response.Body.Close()
	if response.StatusCode == 401 || response.StatusCode == 403 {
		return Denied
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return Unavailable
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, 1048577))
	if e != nil || len(raw) > 1048576 {
		return Unavailable
	}
	if out != nil && json.Unmarshal(raw, out) != nil {
		return Unavailable
	}
	return nil
}
func (c *Client) token(ctx context.Context) (string, error) {
	raw, e := privatefile.Read(c.cfg.TokenFile, 4096)
	if e != nil {
		return "", Denied
	}
	token := strings.TrimSpace(string(raw))
	if token == "" || strings.ContainsAny(token, "\r\n\x00") {
		return "", Denied
	}
	var info struct {
		Data struct {
			Policies  []string `json:"policies"`
			Identity  []string `json:"identity_policies"`
			TTL       int      `json:"ttl"`
			Renewable bool     `json:"renewable"`
		} `json:"data"`
	}
	if e = c.call(ctx, "GET", "auth/token/lookup-self", token, nil, &info); e != nil {
		return "", e
	}
	if info.Data.TTL <= 0 || !info.Data.Renewable || len(info.Data.Identity) > 0 {
		return "", Denied
	}
	found := false
	for _, policy := range info.Data.Policies {
		if policy == c.cfg.Policy {
			found = true
		} else if policy != "default" {
			return "", Denied
		}
	}
	if !found {
		return "", Denied
	}
	if info.Data.TTL < 60 {
		if e = c.call(ctx, "POST", "auth/token/renew-self", token, map[string]any{"increment": "1h"}, nil); e != nil {
			return "", e
		}
	}
	return token, nil
}
func (c *Client) Secure() bool { return !strings.HasPrefix(c.cfg.Address, "http://") }

func (c *Client) Check(ctx context.Context) error { _, e := c.token(ctx); return e }
func (c *Client) Public(alias string) (ed25519.PublicKey, error) {
	key, ok := c.cfg.Keys[alias]
	if !ok {
		return nil, Denied
	}
	raw, e := base64.RawURLEncoding.Strict().DecodeString(key.Public)
	if e != nil || len(raw) != 32 {
		return nil, Denied
	}
	return ed25519.PublicKey(raw), nil
}
func (c *Client) Sign(ctx context.Context, alias string, input []byte) ([]byte, error) {
	key, ok := c.cfg.Keys[alias]
	if !ok || len(input) > 1048576 {
		return nil, Denied
	}
	public, e := c.Public(alias)
	if e != nil {
		return nil, e
	}
	token, e := c.token(ctx)
	if e != nil {
		return nil, e
	}
	var response struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if e = c.call(ctx, "POST", c.cfg.TransitMount+"/sign/"+key.Name, token, map[string]any{"input": base64.StdEncoding.EncodeToString(input), "key_version": key.Version}, &response); e != nil {
		return nil, e
	}
	parts := strings.Split(response.Data.Signature, ":")
	if len(parts) != 3 || parts[0] != "vault" {
		return nil, Unavailable
	}
	signature, e := base64.StdEncoding.Strict().DecodeString(parts[2])
	if e != nil || len(signature) != 64 || !ed25519.Verify(public, input, signature) {
		return nil, Unavailable
	}
	return signature, nil
}
func (c *Client) Read(ctx context.Context, alias string) ([]byte, error) {
	ref, ok := c.cfg.Secrets[alias]
	if !ok {
		return nil, Denied
	}
	token, e := c.token(ctx)
	if e != nil {
		return nil, e
	}
	var response struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	if e = c.call(ctx, "GET", c.cfg.KVMount+"/data/"+ref.Path, token, nil, &response); e != nil {
		return nil, e
	}
	value, ok := response.Data.Data[ref.Field]
	if !ok || len(value) > 65536 {
		return nil, Unavailable
	}
	return []byte(value), nil
}

type Signer struct {
	Client  *Client
	Alias   string
	Context context.Context
}

func (s Signer) Public() crypto.PublicKey { key, _ := s.Client.Public(s.Alias); return key }
func (s Signer) Sign(_ io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != 0 {
		return nil, Denied
	}
	ctx := s.Context
	if ctx == nil {
		ctx = context.Background()
	}
	return s.Client.Sign(ctx, s.Alias, message)
}

// Operation фиксирует alias на стороне сервера; клиент API не выбирает ключ.
type Operation struct {
	Client *Client
	Alias  string
}

func (o Operation) Sign(ctx context.Context, input []byte) ([]byte, error) {
	signature, e := o.Client.Sign(ctx, o.Alias, input)
	if e != nil {
		return nil, domain.DependencyUnavailable
	}
	return signature, nil
}
func (c *Client) Maintain(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			task, cancel := context.WithTimeout(ctx, 3*time.Second)
			_ = c.Check(task)
			cancel()
		}
	}
}
