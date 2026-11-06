package contracts

import "time"

type InventoryLimits12 struct {
	CanonicalBytes int `json:"canonical_bytes"`
	SignedBytes    int `json:"signed_bytes"`
	BatchBytes     int `json:"batch_bytes"`
	Records        int `json:"max_records"`
}

type InventoryCapabilities struct {
	Version       Version            `json:"schema_version"`
	Issuer        string             `json:"issuer"`
	Tenant        string             `json:"tenant_id"`
	Audience      Origin             `json:"audience"`
	Nonce         string             `json:"nonce"`
	Issued        time.Time          `json:"issued_at"`
	Expires       time.Time          `json:"expires_at"`
	Observations  []Version          `json:"observation_versions"`
	Batches       []Version          `json:"batch_versions"`
	Limits12      *InventoryLimits12 `json:"inventory12_limits"`
	SnapshotModes []string           `json:"inventory12_snapshot_modes"`
}

type SignedInventoryCapabilities struct {
	Payload   InventoryCapabilities `json:"payload"`
	Digest    string                `json:"digest"`
	KeyID     string                `json:"key_id"`
	Signature string                `json:"signature"`
}
