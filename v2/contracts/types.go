package contracts

import (
	"encoding/json"
	"time"
)

type Version struct {
	Major int `json:"major"`
	Minor int `json:"minor"`
}
type Origin struct {
	SourceID     string `json:"source_id"`
	SourceKind   string `json:"source_kind"`
	GenerationID string `json:"generation_id"`
}
type SourceRecord struct {
	Namespace string `json:"namespace"`
	LocalID   string `json:"source_local_id"`
}
type Scope struct {
	SiteID  string `json:"site_id"`
	ScopeID string `json:"network_scope_id"`
}
type Candidate struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Value     string `json:"value"`
}
type Section struct {
	Name        string           `json:"name"`
	CollectedAt time.Time        `json:"collected_at"`
	Status      string           `json:"status"`
	Complete    bool             `json:"collection_complete"`
	Reason      string           `json:"reason_code"`
	Count       int              `json:"record_count"`
	Records     []map[string]any `json:"records"`
}
type Observation struct {
	Version     Version      `json:"schema_version"`
	ID          string       `json:"observation_id"`
	TenantID    string       `json:"tenant_id"`
	Origin      Origin       `json:"origin"`
	Record      SourceRecord `json:"source_record"`
	Scope       Scope        `json:"scope"`
	Sequence    string       `json:"source_sequence"`
	CollectedAt time.Time    `json:"collected_at"`
	Clock       string       `json:"clock_quality"`
	Candidates  []Candidate  `json:"identity_candidates"`
	Sections    []Section    `json:"sections"`
	Asserted    *string      `json:"asserted_asset_uid,omitempty"`
}
type SignedObservation struct {
	Payload   json.RawMessage `json:"payload"`
	Digest    string          `json:"digest"`
	KeyID     string          `json:"key_id"`
	Signature string          `json:"signature"`
}
type Business struct {
	DisplayName *string  `json:"display_name"`
	Purpose     *string  `json:"purpose"`
	Criticality string   `json:"criticality"`
	Tags        []string `json:"tags"`
}
type BusinessPatch struct {
	DisplayName *string   `json:"display_name,omitempty"`
	Purpose     *string   `json:"purpose,omitempty"`
	Criticality *string   `json:"criticality,omitempty"`
	Tags        *[]string `json:"tags,omitempty"`
}
type SectionState struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}
type Asset struct {
	TenantID      string         `json:"tenant_id"`
	UID           string         `json:"asset_uid"`
	SiteID        string         `json:"site_id"`
	Revision      string         `json:"business_revision"`
	Business      Business       `json:"business"`
	Hostname      *string        `json:"observed_hostname"`
	OS            *string        `json:"observed_os"`
	LastInventory *time.Time     `json:"last_inventory_at"`
	Freshness     string         `json:"freshness"`
	Accountable   string         `json:"accountable_subject_id"`
	Sections      []SectionState `json:"section_states"`
}
type AssetPage struct {
	Items      []Asset `json:"items"`
	NextCursor *string `json:"next_cursor"`
}
