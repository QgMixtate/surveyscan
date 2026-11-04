package collector

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/machinecred"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/sourceprofile"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/telemetry"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func (c *Collector) loadProfile() error {
	path := filepath.Join(c.Config.CredentialState, "profile.json")
	if _, e := os.Lstat(path); os.IsNotExist(e) {
		return nil
	} else if e != nil {
		return e
	}
	next, e := sourceprofile.Cached(path, c.wire, c.Claims)
	if e != nil {
		return e
	}
	c.profile = &next
	if next.Managed {
		c.mu.Lock()
		c.Config.Limit = next.Config.SpoolBytes
		c.mu.Unlock()
	}
	return nil
}
func (c *Collector) pollProfile(ctx context.Context) error {
	c.mu.Lock()
	diagnostics, e := telemetry.Snapshot(c.Config.Spool, c.certificate.Load().Leaf.NotAfter)
	c.mu.Unlock()
	if e != nil {
		return e
	}
	if e = telemetry.Write(c.Config.CredentialState, diagnostics); e != nil {
		return e
	}
	raw, next, e := sourceprofile.Poll(ctx, c.wire, c.Claims, c.signing, c.profile, func(ctx context.Context, path string, raw []byte) (int, []byte, error) {
		return c.post(ctx, path, raw, "")
	}, diagnostics)
	if e != nil {
		return e
	}
	if next.Managed {
		if e = atomicWrite(filepath.Join(c.Config.CredentialState, "profile.json"), raw); e != nil {
			return e
		}
		c.mu.Lock()
		c.Config.Limit = next.Config.SpoolBytes
		c.mu.Unlock()
	}
	c.profile = &next
	return nil
}
func (c *Collector) heartbeat(ctx context.Context) error {
	raw, _ := json.Marshal(contracts.ChallengeRequest{Sources: []string{c.Claims.Source}, Purpose: "heartbeat"})
	code, raw, e := c.post(ctx, "/api/v1/machine/heartbeat-challenges", raw, "")
	if e != nil || code != 200 || c.wire.Validate("ChallengeResponse", raw) != nil {
		return errors.New("collector heartbeat challenge unavailable")
	}
	var challenges contracts.ChallengeResponse
	_ = json.Unmarshal(raw, &challenges)
	if len(challenges.Challenges) != 1 {
		return errors.New("collector heartbeat challenge invalid")
	}
	ch := challenges.Challenges[0]
	if ch.Source != c.Claims.Source || ch.Tenant != c.Claims.Tenant || ch.Generation != c.Claims.Generation || ch.Purpose != "heartbeat" || !time.Now().Before(ch.Expires) {
		return errors.New("collector heartbeat challenge invalid")
	}
	var state struct {
		Sequence string `json:"sequence"`
	}
	path := filepath.Join(c.Config.CredentialState, "heartbeat-sequence.json")
	exists, e := machinecred.ReadOptional(path, &state)
	if e != nil {
		return e
	}
	if !exists {
		state.Sequence = "0"
	}
	sequence, e := strconv.ParseUint(state.Sequence, 10, 64)
	if e != nil || sequence == math.MaxUint64 {
		return errors.New("collector heartbeat counter unavailable")
	}
	state.Sequence = strconv.FormatUint(sequence+1, 10)
	raw, _ = json.Marshal(state)
	if e = atomicWrite(path, raw); e != nil {
		return e
	}
	payload := contracts.Heartbeat{Version: contracts.Version{Major: 1}, ID: identifier.New(), Tenant: c.Claims.Tenant, Origin: contracts.Origin{SourceID: c.Claims.Source, SourceKind: c.Claims.Kind, GenerationID: c.Claims.Generation}, Challenge: ch.ID, Nonce: ch.Nonce, Sequence: state.Sequence, Sent: time.Now().UTC()}
	raw, _ = json.Marshal(payload)
	message, digest, e := sourceprofile.Message(raw, "SURVEYSCAN-HEARTBEAT-V1\n")
	if e != nil {
		return e
	}
	signature := ed25519.Sign(c.signing, message)
	frame := contracts.SignedHeartbeat{Payload: raw, Digest: digest, KeyID: c.Claims.KeyID, Signature: base64.RawURLEncoding.EncodeToString(signature)}
	raw, _ = json.Marshal(frame)
	code, raw, e = c.post(ctx, "/api/v1/machine/heartbeats", raw, "")
	if e != nil || code != 200 || c.wire.Validate("HeartbeatResult", raw) != nil {
		return errors.New("collector heartbeat not accepted")
	}
	var accepted contracts.HeartbeatResult
	_ = json.Unmarshal(raw, &accepted)
	if accepted.ID != payload.ID {
		return errors.New("collector heartbeat response mismatch")
	}
	return nil
}
