package wire

import (
	"encoding/json"
	"testing"
)

func TestInventory12WorkerSectionUsesDraftSchema(t *testing.T) {
	v, err := NewInventory12()
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range inventory12Fixtures(t) {
		if fixture.ID != "all-sections" {
			continue
		}
		var payload struct {
			Sections []json.RawMessage `json:"sections"`
		}
		if json.Unmarshal(fixture.Payload, &payload) != nil {
			t.Fatal("fixture unavailable")
		}
		for _, b := range payload.Sections {
			section, err := v.Section(b)
			if err != nil || section.Count != len(section.Records) {
				t.Fatal("valid draft section rejected")
			}
			var invalid map[string]any
			json.Unmarshal(b, &invalid)
			invalid["record_count"] = 500
			bad, _ := json.Marshal(invalid)
			if _, err = v.Section(bad); err == nil {
				t.Fatal("worker count mismatch accepted")
			}
		}
	}
	if _, err := v.Section([]byte(`{"name":"updates","password":"canary"}`)); err == nil {
		t.Fatal("arbitrary worker fields accepted")
	}
}
