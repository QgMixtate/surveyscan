package contracts

import "time"

type SubjectSummary struct {
	ID   string `json:"subject_id"`
	Kind string `json:"kind"`
	Name string `json:"name"`
}
type FactEvidence struct {
	Observation string    `json:"observation_id"`
	Origin      Origin    `json:"origin"`
	Sequence    string    `json:"source_sequence"`
	Collected   time.Time `json:"collected_at"`
	Clock       string    `json:"clock_quality"`
}
type CurrentFact struct {
	Section   string       `json:"section"`
	Key       string       `json:"key"`
	Value     string       `json:"value"`
	Interface *string      `json:"interface_name"`
	Evidence  FactEvidence `json:"evidence"`
}
type SectionDetail struct {
	Name           string        `json:"name"`
	Status         string        `json:"status"`
	ClockUncertain bool          `json:"clock_uncertain"`
	Attempt        *FactEvidence `json:"last_attempt"`
	Success        *FactEvidence `json:"last_success"`
}
type SourceSummary struct {
	Source
	ContactStatus string `json:"contact_status"`
	Generation    string `json:"generation_id"`
}
type InventoryDetail struct {
	Version     Version         `json:"schema_version"`
	Tenant      string          `json:"tenant_id"`
	Asset       string          `json:"asset_uid"`
	Snapshot    Asset           `json:"asset"`
	Accountable SubjectSummary  `json:"accountable"`
	Facts       []CurrentFact   `json:"facts"`
	Sections    []SectionDetail `json:"sections"`
	Sources     []SourceSummary `json:"sources"`
}
