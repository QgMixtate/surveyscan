// Package usercli implements a human API client, without database or machine credentials.
package usercli

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/diskspool"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/machinecred"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/privatefile"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

type profile struct {
	Version int       `json:"version"`
	Server  string    `json:"server"`
	CA      string    `json:"ca_file"`
	DevHTTP bool      `json:"dev_loopback_http"`
	Tenant  string    `json:"tenant_id"`
	User    string    `json:"user_id"`
	Cookie  string    `json:"cookie"`
	CSRF    string    `json:"csrf"`
	Expires time.Time `json:"expires_at"`
}
type failure struct {
	status int
	code   string
}

func (f failure) Error() string           { return f.code }
func fail(code int, message string) error { return failure{code, message} }
func client(p profile) (*http.Client, error) {
	u, e := url.Parse(p.Server)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return nil, fail(2, "INVALID_SERVER_ORIGIN")
	}
	loop := u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1"
	if u.Scheme != "https" && !(u.Scheme == "http" && p.DevHTTP && loop) {
		return nil, fail(2, "HTTPS_REQUIRED")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if p.CA != "" {
		raw, e := boundedFile(p.CA, 65536)
		if e != nil || len(raw) > 65536 {
			return nil, fail(2, "INVALID_CA_FILE")
		}
		roots, e := x509.SystemCertPool()
		if e != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(raw) {
			return nil, fail(2, "INVALID_CA_FILE")
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}
func call(ctx context.Context, c *http.Client, p profile, method, path string, body any, extra ...http.Header) ([]byte, *http.Response, error) {
	var input io.Reader
	if body != nil {
		raw, e := json.Marshal(body)
		if e != nil {
			return nil, nil, fail(2, "INVALID_REQUEST")
		}
		input = bytes.NewReader(raw)
	}
	r, e := http.NewRequestWithContext(ctx, method, p.Server+path, input)
	if e != nil {
		return nil, nil, fail(2, "INVALID_REQUEST")
	}
	for _, headers := range extra {
		for key, values := range headers {
			r.Header[key] = values
		}
	}
	r.Header.Set("Accept", "application/json")
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if p.Cookie != "" {
		r.Header.Set("Cookie", p.Cookie)
	}
	if method != "GET" {
		r.Header.Set("Origin", p.Server)
		if p.CSRF != "" {
			r.Header.Set("X-CSRF-Token", p.CSRF)
		}
	}
	response, e := c.Do(r)
	if e != nil {
		return nil, nil, fail(5, "NETWORK_OR_TLS_UNAVAILABLE")
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, 2*1048576+1))
	if e != nil || len(raw) > 2*1048576 {
		return nil, response, fail(5, "INVALID_RESPONSE")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		exit := 6
		switch response.StatusCode {
		case 401, 403:
			exit = 3
		case 404:
			exit = 4
		case 429, 502, 503, 504:
			exit = 5
		}
		return nil, response, fail(exit, fmt.Sprintf("HTTP_%d", response.StatusCode))
	}
	if len(raw) > 0 && !json.Valid(raw) {
		return nil, response, fail(5, "INVALID_JSON_RESPONSE")
	}
	return raw, response, nil
}
func boundedFile(path string, limit int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("bounded regular file required")
	}
	raw, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(raw)) > limit {
		return nil, errors.New("input too large")
	}
	return raw, nil
}
func emit(w io.Writer, v any) error {
	if e := json.NewEncoder(w).Encode(v); e != nil {
		return fail(5, "OUTPUT_UNAVAILABLE")
	}
	return nil
}
func show(w io.Writer, p profile) error {
	return emit(w, map[string]any{"server": p.Server, "tenant_id": p.Tenant, "user_id": p.User, "expires_at": p.Expires, "expired": !time.Now().Before(p.Expires)})
}
func writeNew(path string, p profile) error {
	dir := filepath.Dir(path)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return fail(2, "CONTEXT_UNAVAILABLE")
	}
	raw, e := json.Marshal(p)
	if e != nil {
		return fail(2, "CONTEXT_UNAVAILABLE")
	}
	f, e := os.CreateTemp(dir, ".surveyscan-context-*")
	if e != nil {
		return fail(2, "CONTEXT_UNAVAILABLE")
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(raw); e != nil {
		f.Close()
		return fail(2, "CONTEXT_UNAVAILABLE")
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return fail(2, "CONTEXT_UNAVAILABLE")
	}
	if e = f.Close(); e != nil {
		return fail(2, "CONTEXT_UNAVAILABLE")
	}
	// Publish only a complete private file; never overwrite an existing tenant/session context.
	if e = os.Link(f.Name(), path); e != nil {
		return fail(2, "CONTEXT_ALREADY_EXISTS_OR_UNAVAILABLE")
	}
	if e = diskspool.SyncDir(dir); e != nil {
		return fail(2, "CONTEXT_DURABILITY_UNAVAILABLE")
	}
	return nil
}
func read(path string) (profile, error) {
	var p profile
	exists, e := machinecred.ReadOptional(path, &p)
	if e != nil || !exists || p.Version != 1 || !identifier.Valid(p.Tenant) || !identifier.Valid(p.User) || !strings.HasPrefix(p.Cookie, "surveyscan_session=") || strings.ContainsAny(p.Cookie+p.CSRF, "\r\n\x00") || len(p.Cookie) > 4096 || p.CSRF == "" {
		return p, fail(2, "INVALID_PRIVATE_CONTEXT")
	}
	return p, nil
}
func execute(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 1 && (args[0] == "help" || args[0] == "--help") {
		return emit(out, map[string]any{"commands": []string{"login --server URL --username USER --password-file PRIVATE --context-file PRIVATE [--ca-file CA]", "context show --context-file PRIVATE", "assets list --context-file PRIVATE [--limit 1..200 --cursor CURSOR]", "assets get --context-file PRIVATE --id UUID", "sources list|get|status --context-file PRIVATE [--id UUID]", "profiles get --context-file PRIVATE --id UUID", "profiles set --context-file PRIVATE --id UUID --revision REV --profile-file JSON", "diagnostics --context-file PRIVATE", "local-status --diagnostics-file PRIVATE", "status --context-file PRIVATE", "logout --context-file PRIVATE", "version"}, "output": "JSON by default; --output table for resource commands", "exit_codes": map[string]int{"success": 0, "arguments_or_private_context": 2, "authentication_or_policy": 3, "not_found": 4, "network_tls_timeout_or_dependency": 5, "other_api_failure": 6}})
	}
	if len(args) == 0 {
		return fail(2, "COMMAND_REQUIRED")
	}
	operation := args[0]
	args = args[1:]
	if operation == "assets" || operation == "sources" || operation == "context" || operation == "profiles" {
		if len(args) == 0 {
			return fail(2, "SUBCOMMAND_REQUIRED")
		}
		operation += " " + args[0]
		args = args[1:]
	}
	f := flag.NewFlagSet(operation, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	contextFile := f.String("context-file", "", "")
	diagnosticsFile := f.String("diagnostics-file", "", "")
	server := f.String("server", "", "")
	username := f.String("username", "", "")
	password := f.String("password-file", "", "")
	ca := f.String("ca-file", "", "")
	devHTTP := f.Bool("dev-loopback-http", false, "")
	id := f.String("id", "", "")
	limit := f.Int("limit", 50, "")
	cursor := f.String("cursor", "", "")
	optionsFile := f.String("profile-file", "", "")
	revision := f.String("revision", "", "")
	format := f.String("output", "json", "")
	if f.Parse(args) != nil || f.NArg() != 0 || (*contextFile == "" && operation != "local-status") {
		return fail(2, "INVALID_ARGUMENTS")
	}
	if *format != "json" && *format != "table" {
		return fail(2, "INVALID_OUTPUT_FORMAT")
	}
	if *format == "table" && (operation == "login" || operation == "logout" || operation == "context show" || operation == "local-status") {
		return fail(2, "TABLE_OUTPUT_NOT_SUPPORTED_FOR_COMMAND")
	}
	if operation == "local-status" {
		var d contracts.RuntimeDiagnostics
		exists, e := machinecred.ReadOptional(*diagnosticsFile, &d)
		if e != nil || !exists || d.Collected.IsZero() || d.CertificateExpires.IsZero() {
			return fail(2, "INVALID_DIAGNOSTICS_FILE")
		}
		raw, _ := json.Marshal(d)
		v, e := wire.New()
		if e != nil || v.Validate("RuntimeDiagnostics", raw) != nil {
			return fail(2, "INVALID_DIAGNOSTICS_FILE")
		}
		return emit(out, d)
	}
	if operation != "login" && (*server != "" || *username != "" || *password != "" || *ca != "" || *devHTTP) {
		return fail(2, "LOGIN_FLAGS_NOT_ALLOWED")
	}
	if operation == "login" {
		if _, e := os.Lstat(*contextFile); !os.IsNotExist(e) {
			return fail(2, "CONTEXT_ALREADY_EXISTS_OR_UNAVAILABLE")
		}
		p := profile{Version: 1, Server: *server, CA: *ca, DevHTTP: *devHTTP}
		c, e := client(p)
		if e != nil {
			return e
		}
		defer c.CloseIdleConnections()
		raw, e := privatefile.Read(*password, 1026)
		if e != nil || len(raw) == 0 || *username == "" {
			return fail(2, "PRIVATE_PASSWORD_FILE_REQUIRED")
		}
		secret := strings.TrimRight(string(raw), "\r\n")
		if len(secret) == 0 || len(secret) > 1024 {
			return fail(2, "INVALID_PASSWORD_FILE")
		}
		body, response, e := call(ctx, c, p, "POST", "/api/v1/auth/sessions", map[string]string{"username": *username, "password": secret})
		if e != nil {
			return e
		}
		var session struct {
			Tenant  string    `json:"tenant_id"`
			User    string    `json:"user_id"`
			Expires time.Time `json:"expires_at"`
			CSRF    string    `json:"csrf_token"`
		}
		if json.Unmarshal(body, &session) != nil || !identifier.Valid(session.Tenant) || !identifier.Valid(session.User) || session.CSRF == "" || !time.Now().Before(session.Expires) {
			return fail(5, "INVALID_SESSION_RESPONSE")
		}
		for _, cookie := range response.Cookies() {
			if cookie.Name == "surveyscan_session" {
				if p.Cookie != "" {
					return fail(5, "INVALID_SESSION_COOKIE")
				}
				p.Cookie = cookie.Name + "=" + cookie.Value
			}
		}
		if p.Cookie == "" {
			return fail(5, "SESSION_COOKIE_MISSING")
		}
		p.Tenant = session.Tenant
		p.User = session.User
		p.CSRF = session.CSRF
		p.Expires = session.Expires
		if e = writeNew(*contextFile, p); e != nil {
			_, _, _ = call(ctx, c, p, "DELETE", "/api/v1/auth/session", nil)
			return e
		}
		return show(out, p)
	}
	p, e := read(*contextFile)
	if e != nil {
		return e
	}
	if operation == "context show" {
		return show(out, p)
	}
	c, e := client(p)
	if e != nil {
		return e
	}
	defer c.CloseIdleConnections()
	if operation == "logout" {
		_, _, e = call(ctx, c, p, "DELETE", "/api/v1/auth/session", nil)
		var rejected failure
		if e != nil && (!errors.As(e, &rejected) || rejected.code != "HTTP_401") {
			return e
		}
		if e = os.Remove(*contextFile); e != nil {
			return fail(2, "CONTEXT_UNAVAILABLE")
		}
		if e = diskspool.SyncDir(filepath.Dir(*contextFile)); e != nil {
			return fail(2, "CONTEXT_DURABILITY_UNAVAILABLE")
		}
		return emit(out, map[string]bool{"logged_out": true})
	}
	if !time.Now().Before(p.Expires) {
		return fail(3, "SESSION_EXPIRED")
	}
	if operation == "profiles get" || operation == "profiles set" {
		if !identifier.Valid(*id) {
			return fail(2, "INVALID_RESOURCE_ID")
		}
		method := "GET"
		var body any
		headers := http.Header{}
		if operation == "profiles set" {
			method = "PATCH"
			raw, e := boundedFile(*optionsFile, 4096)
			if e != nil || len(raw) > 4096 || !json.Valid(raw) || *revision == "" {
				return fail(2, "INVALID_PROFILE_FILE_OR_REVISION")
			}
			body = json.RawMessage(raw)
			headers.Set("If-Match", fmt.Sprintf(`"profile:%s:%s"`, *id, *revision))
		}
		raw, _, e := call(ctx, c, p, method, "/api/v1/sources/"+*id+"/profile", body, headers)
		if e != nil {
			return e
		}
		if e = render(out, raw, operation, *format); e != nil {
			return fail(5, "OUTPUT_UNAVAILABLE")
		}
		return nil
	}
	var path string
	switch operation {
	case "assets list", "sources list":
		if *limit < 1 || *limit > 200 || len(*cursor) > 2048 {
			return fail(2, "INVALID_PAGINATION")
		}
		query := url.Values{"limit": []string{fmt.Sprint(*limit)}}
		if *cursor != "" {
			query.Set("cursor", *cursor)
		}
		path = "/api/v1/" + strings.Fields(operation)[0] + "?" + query.Encode()
	case "assets get", "sources get", "sources status":
		if !identifier.Valid(*id) {
			return fail(2, "INVALID_RESOURCE_ID")
		}
		path = "/api/v1/" + strings.Fields(operation)[0] + "/" + *id
	case "diagnostics":
		path = "/api/v1/diagnostics"
	case "status":
		path = "/health/ready"
	default:
		return fail(2, "UNKNOWN_COMMAND")
	}
	raw, _, e := call(ctx, c, p, "GET", path, nil)
	if e != nil {
		return e
	}
	if e = render(out, raw, operation, *format); e != nil {
		return fail(5, "OUTPUT_UNAVAILABLE")
	}
	return nil
}

// Run returns stable process exit codes; errors never echo response bodies or supplied credentials.
func Run(ctx context.Context, args []string, out, errOut io.Writer) int {
	e := execute(ctx, args, out)
	if e == nil {
		return 0
	}
	var f failure
	if !errors.As(e, &f) {
		f = failure{5, "OPERATION_UNAVAILABLE"}
	}
	_ = emit(errOut, map[string]string{"error": f.code})
	return f.status
}
