package collector

import (
	"context"
	"testing"
	"time"
)

func TestRunDiscoveryLimitsAndMerge(t *testing.T) {
	for _, bad := range []discoveryJob{{CIDR: "10.0.0.0/21", Probes: []string{"tcp"}, Ports: []int{22}, Rate: 50, TimeoutMS: 1000},
		{CIDR: "127.0.0.0/30", Probes: []string{"tcp"}, Ports: []int{22}, Rate: 51, TimeoutMS: 1000},
		{CIDR: "fd00::/120", Probes: []string{"tcp"}, Ports: []int{22}, Rate: 50, TimeoutMS: 1000}} {
		if _, _, _, err := runDiscovery(context.Background(), bad); err == nil {
			t.Fatalf("job outside D-13 accepted: %+v", bad)
		}
	}
	old := arpTable
	defer func() { arpTable = old }()
	arpTable = func() (string, error) {
		return "IP address       HW type     Flags       HW address            Mask     Device\n127.0.0.2        0x1         0x2         AA:BB:CC:DD:EE:02     *        lo\n10.9.9.9         0x1         0x2         aa:bb:cc:dd:ee:09     *        eth0\n", nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	n, hosts, errs, err := runDiscovery(ctx, discoveryJob{CIDR: "127.0.0.0/30", Probes: []string{"tcp", "arp"}, Ports: []int{22, 80}, Rate: 50, TimeoutMS: 300})
	if err != nil || n != 2 || len(errs) != 0 {
		t.Fatalf("run: n=%d errs=%v err=%v", n, errs, err)
	}
	// loopback отвечает RST на закрытые порты — узлы .1 и .2 живы; 10.9.9.9 из ARP вне подсети отброшен
	if len(hosts) != 2 || hosts[0].IP != "127.0.0.1" || hosts[1].IP != "127.0.0.2" || hosts[1].MAC == nil || *hosts[1].MAC != "aa:bb:cc:dd:ee:02" {
		t.Fatalf("hosts %+v", hosts)
	}
}
