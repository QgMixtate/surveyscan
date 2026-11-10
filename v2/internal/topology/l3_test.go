package topology

import (
	"net/netip"
	"strings"
	"testing"
)

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func TestBuildL3SubnetsGatewaysAndConflicts(t *testing.T) {
	g := BuildL3([]L3Host{
		{ID: "a", Name: "app", Interfaces: []L3Interface{{Name: "eth0", Addrs: []netip.Prefix{pfx("10.0.0.10/24"), pfx("127.0.0.1/8"), pfx("fe80::1/64")}}},
			Gateways: []L3Gateway{{Addr: netip.MustParseAddr("10.0.0.1"), Detail: "default via 10.0.0.1"}}},
		{ID: "r", Name: "router", Interfaces: []L3Interface{{Name: "lan", Addrs: []netip.Prefix{pfx("10.0.0.1/24")}}, {Name: "dmz", Addrs: []netip.Prefix{pfx("10.0.1.1/24")}}}},
		{ID: "b", Name: "web", Interfaces: []L3Interface{{Name: "eth0", Addrs: []netip.Prefix{pfx("10.0.1.20/24")}}},
			Gateways: []L3Gateway{{Addr: netip.MustParseAddr("10.0.1.254"), Detail: "default via 10.0.1.254"}, {Addr: netip.MustParseAddr("192.168.9.1")}}},
		{ID: "c", Name: "clone", Interfaces: []L3Interface{{Name: "eth0", Addrs: []netip.Prefix{pfx("10.0.1.20/24")}}}},
	})
	nodes := map[string]Node{}
	for _, n := range g.Nodes {
		nodes[n.ID] = n
	}
	for _, id := range []string{"host:a", "host:r", "host:b", "host:c", "subnet:10.0.0.0/24", "subnet:10.0.1.0/24", "gw:10.0.1.254"} {
		if _, ok := nodes[id]; !ok {
			t.Fatal("missing node", id, g.Nodes)
		}
	}
	if _, ok := nodes["subnet:127.0.0.0/8"]; ok {
		t.Fatal("loopback must be ignored")
	}
	if _, ok := nodes["gw:192.168.9.1"]; ok {
		t.Fatal("gateway outside host subnets must not be linked")
	}
	if !nodes["host:r"].Router {
		t.Fatal("gateway matching an inventoried asset must mark it as router")
	}
	var routerLink, conflicts int
	for _, l := range g.Links {
		if l.A.Node == "subnet:10.0.0.0/24" && l.B.Node == "host:r" && l.Level == Probable {
			routerLink++
		}
		for _, c := range l.Conflicts {
			if strings.Contains(c, "10.0.1.20") {
				conflicts++
			}
		}
	}
	if routerLink != 1 || conflicts != 2 {
		t.Fatalf("router link=%d conflicts=%d %+v", routerLink, conflicts, g.Links)
	}
}
