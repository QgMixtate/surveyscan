package contracts

import (
	"encoding/json"
	"time"
)

type ProfileOptions struct {
	Heartbeat  int   `json:"heartbeat_seconds"`
	Inventory  int   `json:"inventory_seconds"`
	Jitter     int   `json:"jitter_percent"`
	SpoolBytes int64 `json:"spool_limit_bytes"`
}
type SourceProfile struct {
	Tenant            string        `json:"tenant_id"`
	Source            string        `json:"source_id"`
	State             string        `json:"source_state"`
	Managed           bool          `json:"managed"`
	Config            MachineConfig `json:"config"`
	Applied           *string       `json:"applied_revision"`
	LastConfigContact *time.Time    `json:"last_config_contact_at"`
	LastContact       *time.Time    `json:"last_contact_at"`
	LastInventory     *time.Time    `json:"last_successful_inventory_at"`
}
type RuntimeDiagnostics struct {
	Collected          time.Time  `json:"collected_at"`
	PendingFiles       int        `json:"pending_files"`
	PendingBytes       int64      `json:"pending_bytes"`
	OldestPending      *time.Time `json:"oldest_pending_at"`
	DiskAvailable      *int64     `json:"disk_available_bytes"`
	CertificateExpires time.Time  `json:"certificate_expires_at"`
}
type ProfileRequestPayload struct {
	Diagnostics *RuntimeDiagnostics `json:"diagnostics,omitempty"`
	Version     Version             `json:"schema_version"`
	Tenant      string              `json:"tenant_id"`
	Origin      Origin              `json:"origin"`
	Nonce       string              `json:"nonce"`
	Sent        time.Time           `json:"sent_at"`
	Applied     *string             `json:"applied_revision"`
}
type ProfilePayload struct {
	Version Version       `json:"schema_version"`
	Tenant  string        `json:"tenant_id"`
	Origin  Origin        `json:"origin"`
	Nonce   string        `json:"nonce"`
	Issued  time.Time     `json:"issued_at"`
	Expires time.Time     `json:"expires_at"`
	Managed bool          `json:"managed"`
	Config  MachineConfig `json:"config"`
}
type ProfileFrame struct {
	Payload   json.RawMessage `json:"payload"`
	Digest    string          `json:"digest"`
	KeyID     string          `json:"key_id"`
	Signature string          `json:"signature"`
}
