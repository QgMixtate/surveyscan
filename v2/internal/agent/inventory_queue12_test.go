package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

// allSectionsFixture берёт допустимое наблюдение 1.2 из корпуса контракта C15.
func allSectionsFixture(t *testing.T) contracts.Observation {
	t.Helper()
	b, err := os.ReadFile("../../../docs/plans/surveyscan-v2/contracts/C15/fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		ID      string          `json:"id"`
		Payload json.RawMessage `json:"payload"`
	}
	if err = json.Unmarshal(b, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, f := range fixtures {
		if f.ID == "all-sections" {
			var o contracts.Observation
			if err = json.Unmarshal(f.Payload, &o); err != nil || len(o.Sections) != 12 {
				t.Fatal("fixture", err)
			}
			return o
		}
	}
	t.Fatal("all-sections fixture missing")
	return contracts.Observation{}
}

func TestBuildBatch12SignsAllSectionsAndPassesTheNegotiatedTransport(t *testing.T) {
	o := allSectionsFixture(t)
	public, key, _ := ed25519.GenerateKey(rand.Reader)
	id := batchIdentity12{Tenant: o.TenantID, Origin: o.Origin, Site: o.Scope.SiteID, Scope: o.Scope.ScopeID, KeyID: identifier.New(), Key: key}
	limits := wire.InventoryMaximum12()
	transport, err := wire.NewInventoryTransport12(limits)
	if err != nil {
		t.Fatal(err)
	}
	delivery, raw, err := buildBatch12(id, transport, "7", o.Candidates, o.Sections, o.CollectedAt)
	if err != nil || !identifier.Valid(delivery) {
		t.Fatal("batch rejected", err)
	}
	batch, _, err := transport.Batch(raw)
	if err != nil || batch.DeliveryID != delivery || batch.Version.Minor != 2 || len(batch.Records) != 1 {
		t.Fatal("batch envelope", err)
	}
	trust := wire.InventoryTrust12{Tenant: o.TenantID, Origin: o.Origin, KeyID: id.KeyID, PublicKey: public}
	observed, err := transport.Verify(batch.Records[0], trust)
	if err != nil || observed.Sequence != "7" || len(observed.Sections) != 12 || observed.Version.Minor != 2 {
		t.Fatal("signed observation did not verify against the agent identity", err)
	}
	// Подпись чужого ключа не должна проходить: границы доверия задаёт удостоверение, а не секции.
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	trust.PublicKey = other
	if _, err = transport.Verify(batch.Records[0], trust); err == nil {
		t.Fatal("observation verified with a foreign key")
	}
}

func TestBuildBatch12RespectsNegotiatedByteBounds(t *testing.T) {
	o := allSectionsFixture(t)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	id := batchIdentity12{Tenant: o.TenantID, Origin: o.Origin, Site: o.Scope.SiteID, Scope: o.Scope.ScopeID, KeyID: identifier.New(), Key: key}
	small := wire.InventoryMaximum12()
	small.CanonicalBytes, small.SignedBytes, small.BatchBytes = 2048, 4096, 8192
	transport, err := wire.NewInventoryTransport12(small)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = buildBatch12(id, transport, "1", o.Candidates, o.Sections, o.CollectedAt); err == nil {
		t.Fatal("oversized observation accepted under small negotiated limits")
	}
	if _, _, err = buildBatch12(id, nil, "1", o.Candidates, o.Sections, o.CollectedAt); err == nil {
		t.Fatal("missing transport accepted")
	}
	id.Key = nil
	full, _ := wire.NewInventoryTransport12(wire.InventoryMaximum12())
	if _, _, err = buildBatch12(id, full, "1", o.Candidates, o.Sections, o.CollectedAt); err == nil {
		t.Fatal("unsigned batch accepted")
	}
}
