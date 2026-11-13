package discovery

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func ip(s string) netip.Addr    { return netip.MustParseAddr(s) }

func TestScopeNeverExpands(t *testing.T) {
	s := Scope{Include: []netip.Prefix{pfx("10.0.0.0/24")}, Exclude: []netip.Prefix{pfx("10.0.0.128/25")}}
	if !s.Allowed(ip("10.0.0.5")) || s.Allowed(ip("10.0.0.200")) || s.Allowed(ip("10.0.1.5")) || s.Allowed(ip("192.168.1.1")) {
		t.Fatal("scope boundaries wrong")
	}
	hosts, err := s.Hosts()
	if err != nil || len(hosts) != 127 || hosts[0] != ip("10.0.0.1") || hosts[len(hosts)-1] != ip("10.0.0.127") {
		t.Fatal(len(hosts), err)
	}
	if _, err = (Scope{Include: []netip.Prefix{pfx("10.0.0.0/16")}, MaxHosts: 100}).Hosts(); err == nil {
		t.Fatal("MaxHosts must bound the sweep")
	}
	if _, err = ProbeTCP(context.Background(), s, []netip.Addr{ip("8.8.8.8")}, ProbeOptions{}); !errors.Is(err, ErrOutOfScope) {
		t.Fatal("out-of-scope probe must be refused:", err)
	}
}

func TestProbeTCPFindsLiveHostAndRefusedCountsAsAlive(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			c.Close()
		}
	}()
	port := l.Addr().(*net.TCPAddr).Port
	s := Scope{Include: []netip.Prefix{pfx("127.0.0.0/8")}}
	obs, err := ProbeTCP(context.Background(), s, []netip.Addr{ip("127.0.0.1")}, ProbeOptions{Ports: []int{port}, Timeout: time.Second})
	if err != nil || len(obs) != 1 || obs[0].Source != "probe-tcp" || obs[0].Detail != "open="+itoa(port) {
		t.Fatal(obs, err)
	}
	// закрытый порт на живом хосте: RST = хост существует
	obs, _ = ProbeTCP(context.Background(), s, []netip.Addr{ip("127.0.0.1")}, ProbeOptions{Ports: []int{1}, Timeout: time.Second})
	if len(obs) != 1 || obs[0].Detail != "open=" {
		t.Fatal("refused must prove presence:", obs)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

func TestMergeNewRepeatOverlapAndConflict(t *testing.T) {
	s := Scope{Include: []netip.Prefix{pfx("10.0.0.0/24")}}
	t0 := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	obs := []Observation{
		{IP: ip("10.0.0.1"), Source: "probe-tcp", At: t0},                                          // только IP
		{IP: ip("10.0.0.1"), MAC: "aa:aa:aa:aa:aa:01", Source: "arp", At: t0.Add(time.Minute)},     // повышение до MAC
		{IP: ip("10.0.0.1"), MAC: "aa:aa:aa:aa:aa:01", Source: "arp", At: t0.Add(2 * time.Minute)}, // повтор
		{IP: ip("10.0.0.2"), MAC: "aa:aa:aa:aa:aa:02", Hostname: "web", Source: "dhcp", At: t0},
		{IP: ip("10.0.0.9"), MAC: "aa:aa:aa:aa:aa:02", Source: "snmp-arp", At: t0}, // multihomed
		{IP: ip("10.0.0.1"), MAC: "aa:aa:aa:aa:aa:03", Source: "snmp-arp", At: t0}, // IP-конфликт
		{IP: ip("172.16.0.5"), MAC: "aa:aa:aa:aa:aa:04", Source: "arp", At: t0},    // вне scope
	}
	hosts, dropped := Merge(s, obs)
	if dropped != 1 {
		t.Fatal("dropped", dropped)
	}
	by := map[string]Host{}
	for _, h := range hosts {
		by[h.MAC] = h
	}
	h1 := by["aa:aa:aa:aa:aa:01"]
	if len(hosts) != 3 || len(h1.IPs) != 1 || len(h1.Sources) != 2 || !h1.LastSeen.Equal(t0.Add(2*time.Minute)) || !h1.FirstSeen.Equal(t0) {
		t.Fatalf("%+v / %d hosts", h1, len(hosts))
	}
	if len(h1.Conflicts) != 1 || h1.Conflicts[0] != "IP_CONFLICT:10.0.0.1" || len(by["aa:aa:aa:aa:aa:03"].Conflicts) != 1 {
		t.Fatal("ip conflict must be flagged on both hosts:", h1.Conflicts, by["aa:aa:aa:aa:aa:03"].Conflicts)
	}
	if c := by["aa:aa:aa:aa:aa:02"].Conflicts; len(c) != 1 || c[0] != "MULTIHOMED" || by["aa:aa:aa:aa:aa:02"].Hostnames[0] != "web" {
		t.Fatal(by["aa:aa:aa:aa:aa:02"])
	}
}

func TestParsers(t *testing.T) {
	arp := "IP address       HW type     Flags       HW address            Mask     Device\n10.0.0.1 0x1 0x2 AA:BB:CC:00:00:01 * eth0\n10.0.0.2 0x1 0x0 00:00:00:00:00:00 * eth0\n"
	o := ParseProcARP(arp, time.Time{})
	if len(o) != 1 || o[0].MAC != "aa:bb:cc:00:00:01" {
		t.Fatal(o)
	}
	d := ParseDHCPLeases("# c\n10.0.0.5 AA:BB:CC:00:00:05 pc5\nbad line\n10.0.0.6 aa:bb:cc:00:00:06 *\n", time.Time{})
	if len(d) != 2 || d[0].Hostname != "pc5" || d[1].Hostname != "" {
		t.Fatal(d)
	}
}

func TestProbeICMPLoopbackAndScope(t *testing.T) {
	scope := Scope{Include: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/30")}}
	if _, err := ProbeICMP(context.Background(), scope, []netip.Addr{netip.MustParseAddr("10.0.0.1")}, time.Millisecond, 10*time.Millisecond); err != ErrOutOfScope {
		t.Fatal("address outside scope must be refused", err)
	}
	got, err := ProbeICMP(context.Background(), scope, []netip.Addr{netip.MustParseAddr("127.0.0.1")}, 10*time.Millisecond, 500*time.Millisecond)
	if err == ErrICMPNotPermitted {
		t.Skip("no ICMP permission in this environment (reported explicitly, as required)")
	}
	if err != nil || len(got) != 1 || got[0].IP != netip.MustParseAddr("127.0.0.1") || got[0].Source != "icmp" {
		t.Fatalf("loopback echo: %v %+v", err, got)
	}
}
