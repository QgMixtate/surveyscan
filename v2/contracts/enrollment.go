package contracts

import (
	"encoding/json"
	"time"
)

type EnrollmentGrantRequest struct {
	TenantID    string  `json:"tenant_id"`
	SourceID    string  `json:"source_id"`
	Kind        string  `json:"source_kind"`
	SiteID      string  `json:"site_id"`
	CollectorID *string `json:"collector_id"`
	TTL         int     `json:"ttl_seconds"`
	CSRHash     string  `json:"csr_sha256"`
	PublicKey   string  `json:"signing_public_key"`
	// InventoryPlatform — необязательная платформа агента (только source_kind=agent); по умолчанию windows/amd64.
	InventoryPlatform string `json:"inventory_platform,omitempty"`
}
type EnrollmentGrant struct {
	ID       string    `json:"grant_id"`
	SourceID string    `json:"source_id"`
	Expires  time.Time `json:"expires_at"`
	Token    string    `json:"enrollment_token"`
}
type EnrollmentRequest struct {
	GrantID   string `json:"grant_id"`
	SourceID  string `json:"source_id"`
	CSR       string `json:"csr_pem"`
	PublicKey string `json:"signing_public_key"`
}
type EnrollmentResult struct {
	SourceID        string    `json:"source_id"`
	GenerationID    string    `json:"generation_id"`
	Chain           string    `json:"certificate_chain_pem"`
	Expires         time.Time `json:"expires_at"`
	KeyID           string    `json:"signing_key_id"`
	CenterKeyID     string    `json:"center_result_key_id"`
	CenterPublicKey string    `json:"center_result_public_key"`
}
type MachineConfig struct {
	SourceID    string   `json:"source_id"`
	CollectorID *string  `json:"collector_id"`
	Revision    string   `json:"profile_revision"`
	Sections    []string `json:"sections"`
	Heartbeat   int      `json:"heartbeat_seconds"`
	Inventory   int      `json:"inventory_seconds"`
	Jitter      int      `json:"jitter_percent"`
	SpoolBytes  int64    `json:"spool_limit_bytes"`
}

type Source struct {
	TenantID      string     `json:"tenant_id"`
	SourceID      string     `json:"source_id"`
	Kind          string     `json:"source_kind"`
	SiteID        string     `json:"site_id"`
	State         string     `json:"state"`
	LastContact   *time.Time `json:"last_contact_at"`
	LastInventory *time.Time `json:"last_successful_inventory_at"`
}
type SourcePage struct {
	Items      []Source `json:"items"`
	NextCursor *string  `json:"next_cursor"`
}

type Batch struct {
	Version    Version           `json:"schema_version"`
	TenantID   string            `json:"tenant_id"`
	DeliveryID string            `json:"delivery_id"`
	Records    []json.RawMessage `json:"records"`
}
type RecordResult struct {
	SourceID      string  `json:"origin_source_id"`
	ObservationID string  `json:"observation_id"`
	Digest        string  `json:"observation_digest"`
	Disposition   string  `json:"disposition"`
	AssetID       *string `json:"asset_uid"`
	Reason        string  `json:"reason_code"`
	SpoolAction   string  `json:"spool_action"`
}
type CenterResult struct {
	Version     Version        `json:"schema_version"`
	ReceiptID   string         `json:"receipt_id"`
	TenantID    string         `json:"tenant_id"`
	DeliveryID  string         `json:"delivery_id"`
	BatchDigest string         `json:"batch_digest"`
	CommittedAt time.Time      `json:"committed_at"`
	Revision    string         `json:"result_revision"`
	Status      string         `json:"status"`
	Results     []RecordResult `json:"results"`
}
type SignedCenterResult struct {
	Payload   CenterResult `json:"payload"`
	Digest    string       `json:"digest"`
	KeyID     string       `json:"key_id"`
	Signature string       `json:"signature"`
}
type TransportReceipt struct {
	Type        string `json:"receipt_type"`
	TenantID    string `json:"tenant_id"`
	DeliveryID  string `json:"delivery_id"`
	Digest      string `json:"batch_digest"`
	Stage       string `json:"stage"`
	SpoolAction string `json:"spool_action"`
	RequestID   string `json:"request_id"`
}
