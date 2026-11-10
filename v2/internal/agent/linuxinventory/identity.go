package linuxinventory

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

var machineIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Identity разбирает вывод `hostname` и /etc/machine-id в строку секции identity.
// Пусто, если имя узла непригодно (секция тогда не выдумывается).
func Identity(hostname, machineID string) []Row {
	h := clean(strings.TrimSpace(hostname), 255)
	if h == "" {
		return []Row{}
	}
	row := Row{"hostname": h}
	if id := strings.ToLower(strings.TrimSpace(machineID)); machineIDPattern.MatchString(id) {
		row["machine_uuid"] = id[:8] + "-" + id[8:12] + "-" + id[12:16] + "-" + id[16:20] + "-" + id[20:]
	}
	return []Row{row}
}

// OS разбирает os-release (данные, не shell) и `uname -m`. Архитектура вне схемы (amd64/arm64/386) → пусто.
func OS(osRelease, uname string) []Row {
	values := map[string]string{}
	for _, l := range lines(osRelease) {
		l = strings.TrimSpace(l)
		k, v, ok := strings.Cut(l, "=")
		if !ok || strings.HasPrefix(l, "#") || (k != "NAME" && k != "VERSION_ID" && k != "ID") {
			continue
		}
		if strings.HasPrefix(v, "\"") {
			u, err := strconv.Unquote(v)
			if err != nil {
				return []Row{}
			}
			v = u
		} else {
			v = strings.Trim(v, "'")
		}
		values[k] = v
	}
	name, version := values["NAME"], values["VERSION_ID"]
	if name == "" {
		name = values["ID"]
	}
	arch := map[string]string{"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64", "i386": "386", "i686": "386"}[strings.TrimSpace(uname)]
	if clean(name, 128) == "" || clean(version, 128) == "" || arch == "" {
		return []Row{}
	}
	return []Row{{"name": name, "version": version, "architecture": arch}}
}

// Network собирает интерфейсы из `ip -o link show` и `ip -o addr show`. lo пропускается.
func Network(link, addr string) []Row {
	type nic struct {
		index int
		mac   string
		mtu   int
		addrs []map[string]any
	}
	nics := map[string]*nic{}
	order := []string{}
	get := func(name string) *nic {
		if n, ok := nics[name]; ok {
			return n
		}
		n := &nic{}
		nics[name] = n
		order = append(order, name)
		return n
	}
	for _, l := range lines(link) {
		f := strings.Fields(l)
		if len(f) < 3 {
			continue
		}
		idx, err := strconv.Atoi(strings.TrimSuffix(f[0], ":"))
		name := strings.TrimSuffix(strings.SplitN(f[1], "@", 2)[0], ":")
		if err != nil || idx < 1 || name == "lo" || clean(name, 128) == "" {
			continue
		}
		n := get(name)
		n.index = idx
		for i := 2; i+1 < len(f); i++ {
			switch f[i] {
			case "mtu":
				n.mtu, _ = strconv.Atoi(f[i+1])
			case "link/ether":
				if m := strings.ToLower(f[i+1]); len(m) == 17 && m != "00:00:00:00:00:00" && regexp.MustCompile(`^([0-9a-f]{2}:){5}[0-9a-f]{2}$`).MatchString(m) {
					n.mac = m
				}
			}
		}
	}
	for _, l := range lines(addr) {
		f := strings.Fields(l)
		if len(f) < 4 || (f[2] != "inet" && f[2] != "inet6") {
			continue
		}
		name := strings.SplitN(f[1], "@", 2)[0]
		if name == "lo" {
			continue
		}
		p, err := netip.ParsePrefix(f[3])
		if err != nil || p.Addr().IsLinkLocalUnicast() {
			continue
		}
		n := get(name)
		if len(n.addrs) < 64 {
			n.addrs = append(n.addrs, map[string]any{"ip": p.Addr().String(), "prefix": p.Bits()})
		}
	}
	rows := []Row{}
	for _, name := range order {
		n := nics[name]
		if len(rows) >= maxRows {
			break
		}
		row := Row{"name": name, "addresses": n.addrs}
		if n.addrs == nil {
			row["addresses"] = []map[string]any{}
		}
		if n.mac != "" {
			row["mac"] = n.mac
		}
		if n.mtu > 0 {
			row["mtu"] = n.mtu
		}
		if n.index > 0 {
			row["interface_index"] = n.index
		}
		rows = append(rows, row)
	}
	return rows
}
