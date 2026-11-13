package contracts

import (
	"embed"
	"time"
)

//go:embed c15-profile.schema.json
var InventoryProfile12Files embed.FS

const InventoryPolicy12 = "windows-amd64-partial-baseline-v1"
const InventoryPlatform12 = "windows/amd64"
const InventoryPolicyLinux12 = "linux-amd64-partial-baseline-v1"
const InventoryPlatformLinux12 = "linux/amd64"

// C51.03: сетевое устройство по SNMPv3 (собирает collector): identity, network, neighbors; остальное unsupported.
const InventoryPolicyNetwork12 = "network-snmp-partial-baseline-v1"
const InventoryPlatformNetwork12 = "network/snmp"

// InventoryPolicyFor12 возвращает политику для платформы; ok=false для неподдержанной платформы.
// Пара policy_id/platform в конфиге должна совпадать с этим соответствием.
func InventoryPolicyFor12(platform string) (string, bool) {
	switch platform {
	case InventoryPlatform12:
		return InventoryPolicy12, true
	case InventoryPlatformLinux12:
		return InventoryPolicyLinux12, true
	case InventoryPlatformNetwork12:
		return InventoryPolicyNetwork12, true
	}
	return "", false
}

type InventoryRevision12 struct {
	Common string `json:"common_revision"`
	Policy string `json:"policy_id"`
}
type InventoryConfig12 struct {
	SourceID          string            `json:"source_id"`
	CollectorID       string            `json:"collector_id"`
	Revision          string            `json:"profile_revision"`
	Policy            string            `json:"policy_id"`
	Platform          string            `json:"platform"`
	Sections          []string          `json:"sections"`
	Heartbeat         int               `json:"heartbeat_seconds"`
	Inventory         int               `json:"inventory_seconds"`
	Jitter            int               `json:"jitter_percent"`
	SpoolBytes        int64             `json:"spool_limit_bytes"`
	WorkerSeconds     int               `json:"worker_timeout_seconds"`
	CollectionSeconds int               `json:"collection_timeout_seconds"`
	SnapshotMode      string            `json:"snapshot_mode"`
	Observation       Version           `json:"observation_version"`
	Batch             Version           `json:"batch_version"`
	Limits            InventoryLimits12 `json:"inventory12_limits"`
}
type InventoryProfileRequest12 struct {
	Version  Version              `json:"schema_version"`
	Tenant   string               `json:"tenant_id"`
	Origin   Origin               `json:"origin"`
	Nonce    string               `json:"nonce"`
	Sent     time.Time            `json:"sent_at"`
	Platform string               `json:"platform"`
	Applied  *InventoryRevision12 `json:"applied"`
}
type InventoryProfile12 struct {
	Version Version           `json:"schema_version"`
	Tenant  string            `json:"tenant_id"`
	Origin  Origin            `json:"origin"`
	Nonce   string            `json:"nonce"`
	Issued  time.Time         `json:"issued_at"`
	Expires time.Time         `json:"expires_at"`
	Managed bool              `json:"managed"`
	Config  InventoryConfig12 `json:"config"`
}
type SourceInventoryProfile12 struct {
	Enabled     bool                 `json:"enabled"`
	Tenant      string               `json:"tenant_id"`
	Source      string               `json:"source_id"`
	Generation  string               `json:"generation_id"`
	Config      InventoryConfig12    `json:"config"`
	Managed     bool                 `json:"managed"`
	Applied     *InventoryRevision12 `json:"applied"`
	LastContact *time.Time           `json:"last_profile_contact_at"`
}
