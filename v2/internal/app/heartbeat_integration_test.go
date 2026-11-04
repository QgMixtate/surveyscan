//go:build integration

package app_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

func heartbeatChallenge(t *testing.T, u *uploadFixture) contracts.Challenge {
	t.Helper()
	result, e := u.sources.Challenges(u.f.ctx, u.fingerprint, contracts.ChallengeRequest{Sources: []string{u.source}, Purpose: "heartbeat"})
	if e != nil {
		t.Fatal(e)
	}
	return result.Challenges[0]
}
func heartbeatPayload(u *uploadFixture, c contracts.Challenge, seq string) contracts.Heartbeat {
	return contracts.Heartbeat{Version: contracts.Version{Major: 1}, ID: identifier.New(), Tenant: tenant, Origin: u.observation("1").Origin, Challenge: c.ID, Nonce: c.Nonce, Sequence: seq, Sent: time.Now().UTC()}
}
func signedHeartbeat(t *testing.T, u *uploadFixture, h contracts.Heartbeat) []byte {
	t.Helper()
	raw, _ := json.Marshal(h)
	canonical, e := wire.Canonical(raw)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(canonical)
	b, _ := json.Marshal(contracts.SignedHeartbeat{Payload: raw, Digest: hex.EncodeToString(sum[:]), KeyID: u.f.keyID, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(u.f.key, append([]byte("SURVEYSCAN-HEARTBEAT-V1\n"), canonical...)))})
	return b
}
func TestC08HeartbeatExactRetryNoFreshnessAndConcurrentConsume(t *testing.T) {
	u := uploadSetup(t)
	c := heartbeatChallenge(t, u)
	again := heartbeatChallenge(t, u)
	if again.ID != c.ID {
		t.Fatal("active nonce superseded")
	}
	raw := signedHeartbeat(t, u, heartbeatPayload(u, c, "1"))
	var wg sync.WaitGroup
	results := make(chan contracts.HeartbeatResult, 2)
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := u.sources.Heartbeat(u.f.ctx, u.fingerprint, raw)
			results <- r
			errs <- e
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	var first contracts.HeartbeatResult
	for r := range results {
		if first.ID == "" {
			first = r
		} else if first != r {
			t.Fatal("retry changed accepted time")
		}
	}
	time.Sleep(10 * time.Millisecond)
	replay, e := u.sources.Heartbeat(u.f.ctx, u.fingerprint, raw)
	if e != nil || first != replay {
		t.Fatal("replayed heartbeat became new contact", e)
	}
	source, e := u.sources.View(u.f.ctx, u.f.identity, u.source)
	if e != nil || source.LastContact == nil || !source.LastContact.Equal(first.Accepted) || source.LastInventory != nil {
		t.Fatal("source contact/freshness conflated", e)
	}
	count(t, u.f, "inventory.observations", 0)
	count(t, u.f, "assets.assets", 0)
	count(t, u.f, "sources.heartbeat_receipts", 1)
	reused := signedHeartbeat(t, u, heartbeatPayload(u, c, "2"))
	if _, e = u.sources.Heartbeat(u.f.ctx, u.fingerprint, reused); !errors.Is(e, domain.Conflict) {
		t.Fatal("consumed nonce reused", e)
	}
	fresh := heartbeatChallenge(t, u)
	if fresh.ID == c.ID {
		t.Fatal("no fresh nonce after consumption")
	}
	if _, e = u.sources.Heartbeat(u.f.ctx, u.fingerprint, signedHeartbeat(t, u, heartbeatPayload(u, fresh, "2"))); e != nil {
		t.Fatal(e)
	}
	replay, e = u.sources.Heartbeat(u.f.ctx, u.fingerprint, raw)
	if e != nil || replay != first {
		t.Fatal("old exact replay failed after supersession", e)
	}
}
func TestC08HeartbeatExpirySequenceSignatureAndRevocation(t *testing.T) {
	u := uploadSetup(t)
	c := heartbeatChallenge(t, u)
	_, e := u.f.pool.Exec(u.f.ctx, "UPDATE sources.heartbeat_state SET issued_at=clock_timestamp()-interval '5 minutes',expires_at=clock_timestamp()-interval '1 second'")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = u.sources.Heartbeat(u.f.ctx, u.fingerprint, signedHeartbeat(t, u, heartbeatPayload(u, c, "1"))); !errors.Is(e, domain.Conflict) {
		t.Fatal("expired challenge accepted", e)
	}
	c = heartbeatChallenge(t, u)
	h := heartbeatPayload(u, c, "7")
	raw := signedHeartbeat(t, u, h)
	var forged contracts.SignedHeartbeat
	_ = json.Unmarshal(raw, &forged)
	forged.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	bad, _ := json.Marshal(forged)
	if _, e = u.sources.Heartbeat(u.f.ctx, u.fingerprint, bad); e == nil {
		t.Fatal("forged heartbeat signature accepted")
	}
	if _, e = u.sources.Heartbeat(u.f.ctx, u.fingerprint, raw); e != nil {
		t.Fatal(e)
	}
	c = heartbeatChallenge(t, u)
	if _, e = u.sources.Heartbeat(u.f.ctx, u.fingerprint, signedHeartbeat(t, u, heartbeatPayload(u, c, "6"))); !errors.Is(e, domain.Conflict) {
		t.Fatal("heartbeat sequence regression accepted", e)
	}
	if e = u.sources.Revoke(u.f.ctx, u.f.identity, u.source); e != nil {
		t.Fatal(e)
	}
	if _, e = u.sources.Heartbeat(u.f.ctx, u.fingerprint, raw); !errors.Is(e, domain.Unauthorized) {
		t.Fatal("revoked replay accepted", e)
	}
}
func TestC08HeartbeatForeignSourceAndTenantCannotRefresh(t *testing.T) {
	u := uploadSetup(t)
	if _, e := u.sources.Challenges(u.f.ctx, u.fingerprint, contracts.ChallengeRequest{Sources: []string{identifier.New()}, Purpose: "heartbeat"}); !errors.Is(e, domain.Unauthorized) {
		t.Fatal("foreign challenge", e)
	}
	c := heartbeatChallenge(t, u)
	h := heartbeatPayload(u, c, "1")
	h.Tenant = otherTenant
	if _, e := u.sources.Heartbeat(u.f.ctx, u.fingerprint, signedHeartbeat(t, u, h)); !errors.Is(e, domain.Unauthorized) {
		t.Fatal("foreign tenant heartbeat", e)
	}
	count(t, u.f, "sources.heartbeat_receipts", 0)
}
