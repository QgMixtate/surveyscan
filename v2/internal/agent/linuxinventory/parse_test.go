package linuxinventory

import (
	"strings"
	"testing"
)

func find(rows []Row, key string, val any) Row {
	for _, r := range rows {
		if r[key] == val {
			return r
		}
	}
	return nil
}

func TestHardware(t *testing.T) {
	cpu := "processor\t: 0\nmodel name\t: Test CPU\nprocessor\t: 1\nmodel name\t: Test CPU\n"
	rows := Hardware(cpu, "MemTotal:        2048 kB\nMemFree: 1 kB\n")
	if c := find(rows, "kind", "cpu"); c == nil || c["logical_processors"] != 2 || c["model"] != "Test CPU" {
		t.Fatalf("cpu %v", rows)
	}
	if m := find(rows, "kind", "memory"); m == nil || m["bytes"] != uint64(2048*1024) {
		t.Fatalf("mem %v", rows)
	}
	if len(Hardware("", "")) != 0 {
		t.Fatal("empty input must give no rows")
	}
}

func TestPackagesOnlyInstalled(t *testing.T) {
	st := "Package: bash\nStatus: install ok installed\nArchitecture: amd64\nVersion: 5.2-1\nDescription: x\n continued\n\nPackage: old\nStatus: deinstall ok config-files\nVersion: 1\n\nPackage: half\nStatus: install ok half-configured\nVersion: 2\n"
	rows := Packages(st)
	if len(rows) != 1 || rows[0]["name"] != "bash" || rows[0]["version"] != "5.2-1" || rows[0]["architecture"] != "amd64" {
		t.Fatalf("%v", rows)
	}
}

func TestAccountsNoSecrets(t *testing.T) {
	rows := Accounts("root:x:0:0:root:/root:/bin/bash\n# c\nbad:line\nsvc:$6$hash:101:101::/n:/usr/sbin/nologin\n", "wheel:x:10:root,svc\n")
	if find(rows, "name", "root") == nil || find(rows, "kind", "membership") == nil {
		t.Fatalf("%v", rows)
	}
	for _, r := range rows {
		for _, v := range r {
			if s, ok := v.(string); ok && strings.Contains(s, "$6$") {
				t.Fatal("password field leaked")
			}
		}
	}
	if len(rows) != 5 { // 2 users + 1 group + 2 memberships
		t.Fatalf("rows %d %v", len(rows), rows)
	}
}

func TestMountsSkipsPseudo(t *testing.T) {
	mi := "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n23 22 0:5 / /proc rw - proc proc rw\n30 22 8:2 / /mnt/my\\040disk ro - xfs /dev/sdb1 ro\n"
	rows := Mounts(mi)
	if len(rows) != 2 || rows[1]["name"] != "/mnt/my disk" || rows[1]["read_only"] != true || rows[0]["read_only"] != false {
		t.Fatalf("%v", rows)
	}
}

func TestSocketsAndRoutes(t *testing.T) {
	tcp := "  sl  local_address rem_address   st\n   0: 0100007F:0016 00000000:0000 0A 0:0\n   1: 0A00A8C0:C350 0100A8C0:01BB 01 0:0\n   2: 0100007F:0050 00000000:0000 FF 0:0\n"
	rows := Sockets("tcp", tcp, false)
	if len(rows) != 2 {
		t.Fatalf("%v", rows)
	}
	l := find(rows, "state", "LISTEN")
	if l == nil || l["local_address"] != "127.0.0.1" || l["local_port"] != uint64(22) {
		t.Fatalf("%v", l)
	}
	e := find(rows, "state", "ESTABLISHED")
	if e["remote_address"] != "192.168.0.1" || e["remote_port"] != uint64(443) {
		t.Fatalf("%v", e)
	}
	udp := "  sl local rem st\n   0: 00000000:0035 00000000:0000 07 0:0\n"
	if u := Sockets("udp", udp, false); len(u) != 1 || u[0]["state"] != nil {
		t.Fatalf("%v", u)
	}
	v6 := "  sl a b st\n   0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 0:0\n"
	if r := Sockets("tcp", v6, true); len(r) != 1 || r[0]["local_address"] != "::1" {
		t.Fatalf("%v", r)
	}
	rt := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\n eth0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\n"
	routes := Routes(rt)
	if len(routes) != 2 || routes[0]["destination"] != "0.0.0.0/0" || routes[0]["gateway"] != "192.168.0.1" || routes[1]["destination"] != "192.168.0.0/24" {
		t.Fatalf("%v", routes)
	}
}

func TestMalformedInputIsIgnored(t *testing.T) {
	if len(Sockets("tcp", "h\nzz\n1: xx yy 0A\n", false)) != 0 || len(Routes("h\na b c\n")) != 0 || len(Mounts("garbage")) != 0 {
		t.Fatal("malformed input produced rows")
	}
}
