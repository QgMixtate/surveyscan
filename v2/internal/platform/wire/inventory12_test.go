package wire

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/contracts"
)

func inventory12Fixtures(t *testing.T) []struct {
	ID      string          `json:"id"`
	Valid   bool            `json:"expected_valid"`
	Payload json.RawMessage `json:"payload"`
} {
	t.Helper()
	b, err := os.ReadFile("../../../../docs/plans/surveyscan-v2/contracts/C15/fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		ID      string          `json:"id"`
		Valid   bool            `json:"expected_valid"`
		Payload json.RawMessage `json:"payload"`
	}
	if err = json.Unmarshal(b, &fixtures); err != nil {
		t.Fatal(err)
	}
	return fixtures
}

func TestInventory12ContractCorpus(t *testing.T) {
	v, err := NewInventory12()
	if err != nil {
		t.Fatal(err)
	}
	old, err := New()
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range inventory12Fixtures(t) {
		t.Run(fixture.ID, func(t *testing.T) {
			canonical, err := v.Payload(fixture.Payload)
			if (err == nil) != fixture.Valid {
				t.Fatalf("valid=%v: %v", fixture.Valid, err)
			}
			if fixture.Valid {
				if old.Validate("Observation", fixture.Payload) == nil {
					t.Fatal("legacy C03 unexpectedly accepted observation 1.2")
				}
				if again, err := v.Payload(canonical); err != nil || !bytes.Equal(again, canonical) {
					t.Fatal("valid payload lost canonical stability")
				}
			}
		})
	}
}

func TestInventory12SemanticCounterexamples(t *testing.T) {
	v, err := NewInventory12()
	if err != nil {
		t.Fatal(err)
	}
	var base []byte
	for _, fixture := range inventory12Fixtures(t) {
		if fixture.ID == "all-sections" {
			base = fixture.Payload
		}
	}
	if len(base) == 0 {
		t.Fatal("missing full inventory fixture")
	}
	for name, mutate := range map[string]func(map[string]any, []any){
		"sequence-overflow": func(p map[string]any, _ []any) { p["source_sequence"] = "18446744073709551616" },
		"future-section":    func(_ map[string]any, s []any) { s[0].(map[string]any)["collected_at"] = "2099-01-01T00:00:00Z" },
		"unknown-native-status": func(_ map[string]any, s []any) {
			s[0].(map[string]any)["status"] = "unknown"
		},
		"prefix-family": func(_ map[string]any, s []any) {
			row := s[2].(map[string]any)["records"].([]any)[0].(map[string]any)
			row["addresses"] = []any{map[string]any{"ip": "192.0.2.1", "prefix": 64}}
		},
		"invalid-dns": func(_ map[string]any, s []any) {
			s[2].(map[string]any)["records"].([]any)[0].(map[string]any)["dns_servers"] = []any{"not-an-ip"}
		},
		"route-family": func(_ map[string]any, s []any) {
			s[8].(map[string]any)["records"].([]any)[0].(map[string]any)["destination"] = "192.0.2.0/24"
		},
		"neighbor-family": func(_ map[string]any, s []any) {
			s[11].(map[string]any)["records"].([]any)[0].(map[string]any)["family"] = "ipv4"
		},
	} {
		t.Run(name, func(t *testing.T) {
			var payload map[string]any
			if err := json.Unmarshal(base, &payload); err != nil {
				t.Fatal(err)
			}
			mutate(payload, payload["sections"].([]any))
			b, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := v.Payload(b); err == nil {
				t.Fatal("invalid payload accepted")
			}
		})
	}
	for _, b := range [][]byte{nil, []byte(strings.Repeat(" ", Inventory12MaxPayload+1)), bytes.Replace(base, []byte(`"tenant_id":`), []byte(`"tenant_id":null,"tenant_id":`), 1)} {
		if _, err := v.Payload(b); err == nil {
			t.Fatal("empty, oversized or duplicate-key payload accepted")
		}
	}
}

func TestInventory12EmbeddedDraftParity(t *testing.T) {
	a, err := contracts.C15Files.ReadFile("c15.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../../../../docs/plans/surveyscan-v2/contracts/C15/observation.schema.json")
	if err != nil || !bytes.Equal(a, b) {
		t.Fatal("embedded C15 schema diverged from reviewed draft")
	}
}
