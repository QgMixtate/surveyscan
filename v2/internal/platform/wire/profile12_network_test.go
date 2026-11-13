package wire

import (
	"testing"

	"github.com/QgMixtate/surveyscan/v2/contracts"
)

// C51.03: профиль 1.2 строится и для платформы сетевого устройства network/snmp с её политикой.
func TestInventoryConfigNetworkPlatform(t *testing.T) {
	collector := "00000000-0000-4000-8000-000000000051"
	c, err := InventoryConfigForPlatform12(contracts.MachineConfig{SourceID: "00000000-0000-4000-8000-000000000052", CollectorID: &collector, Revision: "2", Heartbeat: 30, Inventory: 60, Jitter: 10, SpoolBytes: 524288}, contracts.InventoryPlatformNetwork12)
	if err != nil || c.Platform != "network/snmp" || c.Policy != "network-snmp-partial-baseline-v1" {
		t.Fatal(c.Platform, c.Policy, err)
	}
}
