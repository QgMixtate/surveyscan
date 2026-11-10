package linuxinventory

import "testing"

func TestIdentityOSNetwork(t *testing.T) {
	id := Identity("web01\n", "0123456789abcdef0123456789ABCDEF\n")
	if len(id) != 1 || id[0]["hostname"] != "web01" || id[0]["machine_uuid"] != "01234567-89ab-cdef-0123-456789abcdef" {
		t.Fatal(id)
	}
	if len(Identity("", "x")) != 0 || Identity("h", "short")[0]["machine_uuid"] != nil {
		t.Fatal("bad identity input")
	}
	os := OS("NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=ubuntu\n", "x86_64\n")
	if len(os) != 1 || os[0]["name"] != "Ubuntu" || os[0]["version"] != "24.04" || os[0]["architecture"] != "amd64" {
		t.Fatal(os)
	}
	if len(OS("NAME=A\nVERSION_ID=1\n", "riscv64")) != 0 {
		t.Fatal("unknown arch must not be invented")
	}
	link := "1: lo: <LOOPBACK> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT\\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n" +
		"2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT\\    link/ether 52:54:00:12:34:56 brd ff:ff:ff:ff:ff:ff\n"
	addr := "1: lo    inet 127.0.0.1/8 scope host lo\n2: eth0    inet 192.168.1.5/24 brd 192.168.1.255 scope global eth0\n2: eth0    inet6 fe80::1/64 scope link\n2: eth0    inet6 2001:db8::5/64 scope global\n"
	n := Network(link, addr)
	if len(n) != 1 || n[0]["name"] != "eth0" || n[0]["mac"] != "52:54:00:12:34:56" || n[0]["mtu"] != 1500 || len(n[0]["addresses"].([]map[string]any)) != 2 {
		t.Fatal(n)
	}
}
