package agent

import (
	"context"
	"errors"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/sourceprofile"
	"os"
	"path/filepath"
)

func (c *Client) applyProfile(next contracts.ProfilePayload) error {
	// E1 host adapter currently collects these three read-only sections together.
	if len(next.Config.Sections) != 3 {
		return errors.New("unsupported profile capabilities")
	}
	seen := map[string]bool{}
	for _, section := range next.Config.Sections {
		seen[section] = true
	}
	if !seen["identity"] || !seen["os"] || !seen["network"] {
		return errors.New("unsupported profile capabilities")
	}
	if next.Managed {
		c.cfg.HeartbeatSeconds = next.Config.Heartbeat
		c.cfg.InventorySeconds = next.Config.Inventory
		c.cfg.Jitter = next.Config.Jitter
		c.cfg.Limit = next.Config.SpoolBytes
	}
	c.profile = &next
	return nil
}
func (c *Client) loadProfile() error {
	path := filepath.Join(c.cfg.State, "profile.json")
	if _, e := os.Lstat(path); os.IsNotExist(e) {
		return nil
	} else if e != nil {
		return e
	}
	next, e := sourceprofile.Cached(path, c.wire, c.claims)
	if e != nil {
		return e
	}
	return c.applyProfile(next)
}
func (c *Client) PollProfile(ctx context.Context) (bool, error) {
	if e := verifyHostBinding(c.cfg, c.claims.Source, c.key); e != nil {
		return false, e
	}
	raw, next, e := sourceprofile.Poll(ctx, c.wire, c.claims, c.key, c.profile, func(ctx context.Context, path string, raw []byte) (int, []byte, error) {
		return request(ctx, c.http, c.cfg.CollectorURL, "POST", path, raw, "")
	})
	if e != nil {
		return false, e
	}
	changed := next.Managed && (c.profile == nil || c.profile.Config.Revision != next.Config.Revision)
	// Validate before committing. Retain the previous effective config on any I/O failure.
	before, old := c.cfg, c.profile
	if e = c.applyProfile(next); e != nil {
		return false, e
	}
	if next.Managed {
		if e = writeAtomic(filepath.Join(c.cfg.State, "profile.json"), raw); e != nil {
			c.cfg = before
			c.profile = old
			return false, e
		}
	}
	return changed, nil
}
