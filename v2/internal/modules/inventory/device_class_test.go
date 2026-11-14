package inventory

import "testing"

func TestDeviceClass(t *testing.T) {
	for _, c := range []struct {
		hw, os   string
		hv, noOS bool
		want     string
	}{
		{"VMware Virtual Platform", "Ubuntu 24.04", false, false, "virtual_machine"},
		{"Dell PowerEdge", "Windows Server 2019", true, false, "hypervisor"},
		{"", "VMware ESXi 8.0", false, false, "hypervisor"},
		{"", "Windows 11 Pro", false, false, "workstation"},
		{"", "", false, true, "network"},
		{"", "", false, false, "unknown"},
	} {
		if got := deviceClass(c.hw, c.os, c.hv, c.noOS).Class; got != c.want {
			t.Fatalf("%+v: got %s", c, got)
		}
	}
}
