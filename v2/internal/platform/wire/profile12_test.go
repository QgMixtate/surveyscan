package wire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/diskspool"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

func profileFixture12(t *testing.T) contracts.InventoryProfile12 {
	t.Helper()
	collector := identifier.New()
	source := identifier.New()
	nonce, _ := NewInventoryNonce()
	config, err := InventoryConfigFromCommon12(contracts.MachineConfig{SourceID: source, CollectorID: &collector, Revision: "2", Heartbeat: 30, Inventory: 60, Jitter: 10, SpoolBytes: 524288})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	return contracts.InventoryProfile12{Version: contracts.Version{Major: 1, Minor: 2}, Tenant: identifier.New(), Origin: contracts.Origin{SourceID: source, SourceKind: "agent", GenerationID: identifier.New()}, Nonce: nonce, Issued: now, Expires: now.Add(2 * time.Minute), Managed: true, Config: config}
}
func TestInventoryProfile12SignaturesScopeFreshnessAndPolicy(t *testing.T) {
	public, key, _ := ed25519.GenerateKey(rand.Reader)
	keyID := identifier.New()
	base := profileFixture12(t)
	verify := func(raw []byte, p contracts.InventoryProfile12) error {
		_, err := VerifyInventoryProfile12(raw, p.Tenant, p.Origin, p.Config.CollectorID, p.Nonce, keyID, public)
		return err
	}
	raw, err := SignInventoryProfile12(base, InventoryProfileResponseDomain12, keyID, key)
	if err != nil || verify(raw, base) != nil {
		t.Fatal("valid profile rejected", err, verify(raw, base))
	}

	api, err := contracts.C15API12Files.ReadFile("c15.openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(api))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	id := "urn:surveyscan:c15:profile-openapi-test"
	if err = compiler.AddResource(id, doc); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(id + "#/components/schemas/InventoryProfile12SignedResponse")
	if err != nil {
		t.Fatal(err)
	}
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err = schema.Validate(value); err != nil {
		t.Fatal("published profile schema rejects runtime", err)
	}
	for name, mutate := range map[string]func(*contracts.InventoryProfile12){
		"old-profile-version":  func(p *contracts.InventoryProfile12) { p.Version.Minor = 0 },
		"unsupported-platform": func(p *contracts.InventoryProfile12) { p.Config.Platform = "linux/amd64" },
		"wrong-budget":         func(p *contracts.InventoryProfile12) { p.Config.CollectionSeconds = 30 },
		"wrong-worker-budget":  func(p *contracts.InventoryProfile12) { p.Config.WorkerSeconds = 3600 },
		"duplicate-section": func(p *contracts.InventoryProfile12) {
			p.Config.Sections = append([]string{}, p.Config.Sections...)
			p.Config.Sections[11] = "identity"
		},
		"wrong-origin-source":      func(p *contracts.InventoryProfile12) { p.Config.SourceID = identifier.New() },
		"wrong-managed-state":      func(p *contracts.InventoryProfile12) { p.Managed = false },
		"unsafe-profile-revision":  func(p *contracts.InventoryProfile12) { p.Config.Revision = "18446744073709551616" },
		"leading-zero-revision":    func(p *contracts.InventoryProfile12) { p.Config.Revision = "02" },
		"inconsistent-spool-limit": func(p *contracts.InventoryProfile12) { p.Config.Limits.BatchBytes = 786432 },
		"authoritative-deletion":   func(p *contracts.InventoryProfile12) { p.Config.SnapshotMode = "complete" },
		"expired": func(p *contracts.InventoryProfile12) {
			p.Issued = p.Issued.Add(-time.Hour)
			p.Expires = p.Expires.Add(-time.Hour)
		},
		"future": func(p *contracts.InventoryProfile12) {
			p.Issued = p.Issued.Add(time.Hour)
			p.Expires = p.Expires.Add(time.Hour)
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := base
			mutate(&p)
			raw, err := SignInventoryProfile12(p, InventoryProfileResponseDomain12, keyID, key)
			if err == nil && verify(raw, base) == nil {
				t.Fatal("invalid signed profile accepted")
			}
		})
	}
	for _, prefix := range []string{InventoryProfileRequestDomain12} {
		raw, _ := SignInventoryProfile12(base, prefix, keyID, key)
		if verify(raw, base) == nil {
			t.Fatal("cross-role signature accepted")
		}
	}
	changed := base
	changed.Nonce, _ = NewInventoryNonce()
	if verify(raw, changed) == nil {
		t.Fatal("nonce replay")
	}
	changed = base
	changed.Origin.GenerationID = identifier.New()
	if verify(raw, changed) == nil {
		t.Fatal("cross-generation replay")
	}
	changed = base
	changed.Tenant = identifier.New()
	if verify(raw, changed) == nil {
		t.Fatal("cross-tenant replay")
	}
	changed = base
	changed.Config.CollectorID = identifier.New()
	if verify(raw, changed) == nil {
		t.Fatal("wrong collector assignment")
	}
	if _, err = VerifyInventoryProfile12(raw, base.Tenant, base.Origin, base.Config.CollectorID, base.Nonce, keyID, make(ed25519.PublicKey, 32)); err == nil {
		t.Fatal("untrusted center key accepted")
	}
	legacy, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Validate("SignedProfile", raw) == nil {
		t.Fatal("frozen C12 accepted1.2")
	}
	var frame map[string]any
	_ = json.Unmarshal(raw, &frame)
	frame["command"] = "canary-private"
	bad, _ := RecordJSON(frame)
	if verify(bad, base) == nil {
		t.Fatal("unknown executable field accepted")
	}
}
func TestInventoryProfile12SpoolBudgetAndSchemaParity(t *testing.T) {
	if diskspool.AckReserve != 65536 {
		t.Fatal("protocol ACK reserve must track durable storage")
	}
	for _, limit := range []int64{524288, 1048576, 1073741824} {
		offer, err := InventorySpoolOffer12(limit)
		if err != nil || int64(offer.BatchBytes) > limit-diskspool.AckReserve-4096 || offer.CanonicalBytes >= offer.SignedBytes || offer.SignedBytes >= offer.BatchBytes {
			t.Fatal("invalid budget", offer, err)
		}
	}
	for _, limit := range []int64{0, 524287, 1073741825} {
		if _, err := InventorySpoolOffer12(limit); err == nil {
			t.Fatal("unbounded spool accepted")
		}
	}
	a, _ := contracts.InventoryProfile12Files.ReadFile("c15-profile.schema.json")
	b, err := os.ReadFile("../../../../docs/plans/surveyscan-v2/contracts/C15/profile.schema.json")
	if err != nil || !bytes.Equal(a, b) {
		t.Fatal("schema copies diverged", err)
	}
}
