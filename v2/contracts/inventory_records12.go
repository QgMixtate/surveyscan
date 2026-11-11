package contracts

import (
	"encoding/json"
	"time"
)

// RecordFact12 carries a typed JSON field and that field's own provenance.
// record_key is a provider locator, never a global asset or component UID.
type RecordFact12 struct {
	Record   string          `json:"record_key"`
	Field    string          `json:"field"`
	Value    json.RawMessage `json:"value"`
	Evidence FactEvidence    `json:"evidence"`
}

// RecordState12: status и last_attempt — лучшая из последних попыток источников актива
// (partial > unavailable > unsupported > not_requested); Sources — последняя попытка каждого источника (R-027).
type RecordState12 struct {
	Status         string            `json:"status"`
	ClockUncertain bool              `json:"clock_uncertain"`
	Attempt        FactEvidence      `json:"last_attempt"`
	Sources        []SectionSource12 `json:"sources,omitempty"`
}

type SectionSource12 struct {
	SourceID  string    `json:"source_id"`
	Status    string    `json:"status"`
	Collected time.Time `json:"collected_at"`
}

type RecordFactPage12 struct {
	Version    Version        `json:"schema_version"`
	Tenant     string         `json:"tenant_id"`
	Asset      string         `json:"asset_uid"`
	Section    string         `json:"section"`
	Revision   string         `json:"projection_revision"`
	State      *RecordState12 `json:"section_state"`
	Items      []RecordFact12 `json:"items"`
	NextCursor *string        `json:"next_cursor"`
}

func InventorySection12(name string) bool {
	switch name {
	case "identity", "os", "network", "hardware", "software", "updates", "services", "users_groups", "routes_ports", "resources", "protection", "neighbors":
		return true
	}
	return false
}
