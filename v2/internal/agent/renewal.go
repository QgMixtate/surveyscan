package agent

import (
	"context"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/machinecred"
	"os"
	"path/filepath"
	"time"
)

type tlsIdentity = machinecred.Identity

func (c *Client) Renew(ctx context.Context) error {
	roots, e := rootsFor(c.cfg)
	if e != nil {
		return e
	}
	engine := machinecred.Engine{Directory: c.cfg.State, Claims: c.claims, Signing: c.key, Roots: roots, Wire: c.wire, Post: func(ctx context.Context, path string, raw []byte) (int, []byte, error) {
		return request(ctx, c.http, c.cfg.CollectorURL, "POST", path, raw, "")
	}}
	if e = engine.Renew(ctx); e != nil {
		return e
	}
	fresh, e := Open(c.cfg)
	if e != nil {
		return e
	}
	c.http.CloseIdleConnections()
	c.http = fresh.http
	c.claims = fresh.claims
	return nil
}

// RenewOnce shares the daemon lock; never mutates identity underneath a running sender.
func RenewOnce(ctx context.Context, c Config) error {
	unlock, e := lockState(c.State)
	if e != nil {
		return e
	}
	defer unlock()
	client, e := Open(c)
	if e != nil {
		return e
	}
	defer func() { client.http.CloseIdleConnections() }()
	return client.Renew(ctx)
}
func (c *Client) renewalDue(now time.Time) bool {
	if _, e := os.Stat(filepath.Join(c.cfg.State, "renewal.pending.json")); e == nil {
		return true
	}
	var current tlsIdentity
	if e := loadJSON(filepath.Join(c.cfg.State, "tls-identity.json"), &current); e == nil {
		return !now.Before(current.Result.Expires.Add(-time.Hour))
	}
	var initial contracts.EnrollmentResult
	return loadJSON(filepath.Join(c.cfg.State, "identity.json"), &initial) == nil && !now.Before(initial.Expires.Add(-time.Hour))
}

func loadOptionalJSON(path string, out any) (bool, error) { return machinecred.ReadOptional(path, out) }
