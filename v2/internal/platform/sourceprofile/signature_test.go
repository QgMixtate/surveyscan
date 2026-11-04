package sourceprofile

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/pki"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func fixture(t *testing.T) (*wire.Validator, pki.Claims, ed25519.PrivateKey, contracts.ProfilePayload) {
	t.Helper()
	v, e := wire.New()
	if e != nil {
		t.Fatal(e)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	claims := pki.Claims{Source: identifier.New(), Tenant: identifier.New(), Generation: identifier.New(), Kind: "agent", Collector: identifier.New(), CenterKeyID: identifier.New(), CenterPublic: pub}
	payload := contracts.ProfilePayload{Version: contracts.Version{Major: 1}, Tenant: claims.Tenant, Origin: contracts.Origin{SourceID: claims.Source, SourceKind: claims.Kind, GenerationID: claims.Generation}, Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Issued: time.Now().UTC(), Expires: time.Now().UTC().Add(time.Minute), Managed: true, Config: contracts.MachineConfig{SourceID: claims.Source, CollectorID: &claims.Collector, Revision: "2", Sections: []string{"identity", "os", "network"}, Heartbeat: 30, Inventory: 60, SpoolBytes: 1048576}}
	return v, claims, key, payload
}
func signed(t *testing.T, p contracts.ProfilePayload, claims pki.Claims, key ed25519.PrivateKey, prefix string) []byte {
	t.Helper()
	raw, _ := json.Marshal(p)
	message, digest, e := Message(raw, prefix)
	if e != nil {
		t.Fatal(e)
	}
	frame := contracts.ProfileFrame{Payload: raw, Digest: digest, KeyID: claims.CenterKeyID, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message))}
	raw, _ = json.Marshal(frame)
	return raw
}
func TestProfileResponseNonceScopeDomainAndExpiry(t *testing.T) {
	v, claims, key, p := fixture(t)
	raw := signed(t, p, claims, key, ResponseDomain)
	if _, e := VerifyResponse(v, raw, claims, p.Nonce, true); e != nil {
		t.Fatal(e)
	}
	if _, e := VerifyResponse(v, raw, claims, "another-nonce", true); e == nil {
		t.Fatal("replayed response accepted for a fresh nonce")
	}
	other := claims
	other.Source = identifier.New()
	if _, e := VerifyResponse(v, raw, other, p.Nonce, true); e == nil {
		t.Fatal("other source response accepted")
	}
	if _, e := VerifyResponse(v, signed(t, p, claims, key, RequestDomain), claims, p.Nonce, true); e == nil {
		t.Fatal("wrong signature domain accepted")
	}
	p.Issued = time.Now().Add(-3 * time.Minute)
	p.Expires = time.Now().Add(-time.Minute)
	raw = signed(t, p, claims, key, ResponseDomain)
	if _, e := VerifyResponse(v, raw, claims, p.Nonce, true); e == nil {
		t.Fatal("expired response accepted as fresh")
	}
	if _, e := VerifyResponse(v, raw, claims, p.Nonce, false); e != nil {
		t.Fatal("public cached operating profile lost during offline", e)
	}
}
func TestProfilePollRejectsDowngradeAndSameRevisionConflict(t *testing.T) {
	v, claims, key, current := fixture(t)
	_, originKey, _ := ed25519.GenerateKey(rand.Reader)
	claims.KeyID = identifier.New()
	for _, revision := range []string{"1", "2"} {
		post := func(ctx context.Context, path string, raw []byte) (int, []byte, error) {
			var frame contracts.ProfileFrame
			_ = json.Unmarshal(raw, &frame)
			var req contracts.ProfileRequestPayload
			_ = json.Unmarshal(frame.Payload, &req)
			next := current
			next.Nonce = req.Nonce
			next.Config.Revision = revision
			next.Managed = revision != "1"
			next.Config.Inventory = 120
			return 200, signed(t, next, claims, key, ResponseDomain), nil
		}
		if _, _, e := Poll(context.Background(), v, claims, originKey, &current, post); e == nil {
			t.Fatal("downgrade or conflicting same revision accepted", revision)
		}
	}
}
func TestCachedProfileTamperingAndSymlinkRefused(t *testing.T) {
	v, claims, key, p := fixture(t)
	path := filepath.Join(t.TempDir(), "profile.json")
	raw := signed(t, p, claims, key, ResponseDomain)
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := Cached(path, v, claims); e != nil {
		t.Fatal(e)
	}
	var frame contracts.ProfileFrame
	_ = json.Unmarshal(raw, &frame)
	p.Config.Inventory = 86400
	frame.Payload, _ = json.Marshal(p)
	forged, _ := json.Marshal(frame)
	if e := os.WriteFile(path, forged, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := Cached(path, v, claims); e == nil {
		t.Fatal("tampered profile accepted")
	}
	link := path + ".link"
	if e := os.Symlink(path, link); e != nil {
		t.Fatal(e)
	}
	if _, e := Cached(link, v, claims); e == nil {
		t.Fatal("symlinked cache accepted")
	}
}
