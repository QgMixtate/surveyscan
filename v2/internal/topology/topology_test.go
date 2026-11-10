package topology

import (
	"net/netip"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/internal/remote/snmpnet"
)

func sw(id, mac string, ifs ...snmpnet.Interface) Device {
	return Device{ID: id, Result: snmpnet.Result{Interfaces: append([]snmpnet.Interface{{Index: 100, Name: "mgmt", MAC: mac}}, ifs...)}}
}

func find(g Graph, layer, a, b string) *Link {
	for i := range g.Links {
		l := &g.Links[i]
		if l.Layer == layer && ((l.A.Node == a && l.B.Node == b) || (l.A.Node == b && l.B.Node == a)) {
			return l
		}
	}
	return nil
}

func TestLLDPBothSidesConfirmedOneSideProbable(t *testing.T) {
	core := sw("core", "aa:00:00:00:00:01", snmpnet.Interface{Index: 1, Name: "Gi1"}, snmpnet.Interface{Index: 2, Name: "Gi2"})
	acc := sw("acc", "aa:00:00:00:00:02", snmpnet.Interface{Index: 1, Name: "Gi24"})
	core.Result.Neighbors = []snmpnet.Neighbor{{LocalPort: 1, ChassisID: "aa:00:00:00:00:02", PortID: "Gi24"}, {LocalPort: 2, ChassisID: "bb:00:00:00:00:09", PortID: "eth0"}}
	acc.Result.Neighbors = []snmpnet.Neighbor{{LocalPort: 1, ChassisID: "aa:00:00:00:00:01", PortID: "Gi1"}}
	g := Build([]Device{core, acc}, 0)
	l := find(g, "L2", "core", "acc")
	if l == nil || l.Level != Confirmed || len(l.Evidence) != 2 {
		t.Fatalf("%+v", l)
	}
	ext := find(g, "L2", "core", "ext:bb:00:00:00:00:09")
	if ext == nil || ext.Level != Probable || len(ext.Evidence) != 1 {
		t.Fatalf("unknown neighbor must be a probable external node: %+v", ext)
	}
}

func TestFDBOnlyOnAccessPorts(t *testing.T) {
	acc := sw("acc", "aa:00:00:00:00:02", snmpnet.Interface{Index: 1, Name: "Gi1"}, snmpnet.Interface{Index: 2, Name: "Gi2"}, snmpnet.Interface{Index: 24, Name: "Gi24"})
	acc.Result.Neighbors = []snmpnet.Neighbor{{LocalPort: 24, ChassisID: "aa:00:00:00:00:01", PortID: "Gi1"}}
	acc.Result.FDB = []snmpnet.FDBEntry{
		{MAC: "cc:00:00:00:00:01", IfIndex: 1, Port: 1},                                                                                                   // access: один MAC
		{MAC: "cc:00:00:00:00:02", IfIndex: 24, Port: 24},                                                                                                 // uplink с LLDP — не привязывать
		{MAC: "cc:00:00:00:00:03", IfIndex: 2, Port: 2}, {MAC: "cc:00:00:00:00:04", IfIndex: 2, Port: 2}, {MAC: "cc:00:00:00:00:05", IfIndex: 2, Port: 2}, // за портом свитч/хаб
		{MAC: "aa:00:00:00:00:02", IfIndex: 100, Port: 99, Status: 4}, // self
	}
	g := Build([]Device{acc}, 2)
	if find(g, "L2", "acc", "mac:cc:00:00:00:00:01") == nil {
		t.Fatal("single MAC on access port must attach")
	}
	for _, m := range []string{"cc:00:00:00:00:02", "cc:00:00:00:00:03", "cc:00:00:00:00:05", "aa:00:00:00:00:02"} {
		if find(g, "L2", "acc", "mac:"+m) != nil {
			t.Fatalf("%s must not be attributed to a single port", m)
		}
	}
	if len(g.Unattributed) != 4 {
		t.Fatal("trunk/multi-MAC addresses must be reported as unattributed:", g.Unattributed)
	}
}

func TestConflictingPeersAreFlaggedNotErased(t *testing.T) {
	a := sw("a", "aa:00:00:00:00:01", snmpnet.Interface{Index: 1, Name: "Gi1"})
	a.Result.Neighbors = []snmpnet.Neighbor{{LocalPort: 1, ChassisID: "bb:00:00:00:00:01", PortID: "p1"}, {LocalPort: 1, ChassisID: "bb:00:00:00:00:02", PortID: "p2"}}
	g := Build([]Device{a}, 0)
	flagged := 0
	for _, l := range g.Links {
		flagged += len(l.Conflicts)
	}
	if len(g.Links) != 2 || flagged == 0 {
		t.Fatalf("two peers on one port must stay and be flagged: %+v", g.Links)
	}
}

func TestL3SharedSubnetIsWeak(t *testing.T) {
	r1 := sw("r1", "aa:00:00:00:00:01", snmpnet.Interface{Index: 1, Name: "e0", Addresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}})
	r2 := sw("r2", "aa:00:00:00:00:02", snmpnet.Interface{Index: 1, Name: "e0", Addresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")}})
	g := Build([]Device{r1, r2}, 0)
	l1, l2 := find(g, "L3", "r1", "subnet:10.0.0.0/24"), find(g, "L3", "r2", "subnet:10.0.0.0/24")
	if l1 == nil || l2 == nil || l1.Level != Weak {
		t.Fatal("shared subnet must be weak evidence", g.Links)
	}
}
