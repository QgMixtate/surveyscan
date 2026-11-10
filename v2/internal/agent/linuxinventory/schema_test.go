package linuxinventory

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

// Вывод парсеров обязан проходить настоящую схему наблюдения (контракт C15), а не только мои ожидания.
func TestParserOutputPassesObservationSchema(t *testing.T) {
	b, err := os.ReadFile("../../../../docs/plans/surveyscan-v2/contracts/C15/fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		ID      string                `json:"id"`
		Payload contracts.Observation `json:"payload"`
	}
	if err = json.Unmarshal(b, &fixtures); err != nil {
		t.Fatal(err)
	}
	var o contracts.Observation
	for _, f := range fixtures {
		if f.ID == "all-sections" {
			o = f.Payload
		}
	}
	if len(o.Sections) == 0 {
		t.Fatal("fixture missing")
	}
	cpu := "processor\t: 0\nmodel name\t: Test CPU\n"
	pkgs := "Package: bash\nStatus: install ok installed\nArchitecture: all\nVersion: 5.2-1\n"
	tcp := "  sl a b st\n   0: 0100007F:0016 00000000:0000 0A 0:0\n"
	rt := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\n"
	mi := "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n"
	rows := map[string][]map[string]any{
		"hardware":     append(Hardware(cpu, "MemTotal: 2048 kB\n"), DMI(map[string]string{"bios_vendor": "SeaBIOS", "product_uuid": "4c4c4544-0000-1000-8000-b2c04f000000"})...),
		"services":     SystemdServices("ssh.service loaded active running SSH\n", "ssh.service enabled enabled\n"),
		"software":     append(append(Packages(pkgs), RPMPackages("bash\t5.1-2\tx86_64\n")...), APKPackages("P:musl\nV:1.2\nA:x86_64\n")...),
		"users_groups": Accounts("root:x:0:0:root:/root:/bin/bash\nsvc:x:101:101::/n:\n", "wheel:x:10:root,svc\n"),
		"routes_ports": append(Sockets("tcp", tcp, false), Routes(rt)...),
		"resources":    Mounts(mi),
	}
	for i := range o.Sections {
		if r, ok := rows[o.Sections[i].Name]; ok {
			if len(r) == 0 {
				t.Fatal("parser produced no rows for", o.Sections[i].Name)
			}
			o.Sections[i].Records = r
			o.Sections[i].Count = len(r)
		}
	}
	v, err := wire.NewInventory12()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = v.Payload(raw); err != nil {
		t.Fatal("parser output rejected by observation schema:", err)
	}
}
