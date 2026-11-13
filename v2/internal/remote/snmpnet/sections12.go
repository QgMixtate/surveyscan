package snmpnet

import (
	"strings"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
)

// C51.03: результат SNMP сетевого устройства в 12 разделов профиля 1.2 (платформа network/snmp). Передаются
// identity (sysName), network (интерфейсы с адресами, MAC, MTU, индексом) и neighbors (таблица ARP устройства).
// Остальное — unsupported: строк для sysDescr/модели (os требует архитектуру amd64/arm64/386), LLDP, FDB и VLAN
// в контракте C15 нет; значения не выдумываются.

var sectionOrder12 = []string{"identity", "os", "network", "hardware", "software", "updates", "services", "users_groups", "routes_ports", "resources", "protection", "neighbors"}

func Sections12(r Result, at time.Time) []contracts.Section {
	at = at.UTC()
	part := func(name string, rows []map[string]any, status Status) contracts.Section {
		if len(rows) == 0 {
			reason := "SOURCE_UNAVAILABLE"
			if status == StatusEmpty {
				return contracts.Section{Name: name, CollectedAt: at, Status: "ok", Records: []map[string]any{}}
			}
			return contracts.Section{Name: name, CollectedAt: at, Status: "unavailable", Reason: reason, Records: []map[string]any{}}
		}
		return contracts.Section{Name: name, CollectedAt: at, Status: "partial", Reason: "REMOTE_SNMP_PARTIAL", Count: len(rows), Records: rows}
	}
	have := map[string]contracts.Section{}
	name := strings.TrimSpace(r.System.Name)
	identity := []map[string]any{}
	if name != "" && len(name) <= 255 {
		row := map[string]any{"hostname": strings.SplitN(name, ".", 2)[0]}
		if strings.Contains(name, ".") {
			row["fqdn"] = name
		}
		identity = append(identity, row)
	}
	have["identity"] = part("identity", identity, r.Tables["system"])
	nets := []map[string]any{}
	for _, i := range r.Interfaces {
		n := i.Name
		if n == "" {
			n = i.Descr
		}
		if n == "" || len(n) > 256 {
			continue
		}
		addrs := []any{}
		for _, a := range i.Addresses {
			if len(addrs) < 64 {
				addrs = append(addrs, map[string]any{"ip": a.Addr().String(), "prefix": a.Bits()})
			}
		}
		row := map[string]any{"name": n, "addresses": addrs}
		if i.MAC != "" {
			row["mac"] = i.MAC
		}
		if i.MTU > 0 {
			row["mtu"] = i.MTU
		}
		if i.Index > 0 {
			row["interface_index"] = i.Index
		}
		nets = append(nets, row)
	}
	have["network"] = part("network", nets, r.Tables["if_table"])
	neigh := []map[string]any{}
	for _, a := range r.ARP {
		if !a.IP.IsValid() || !a.IP.Is4() || a.IfIndex <= 0 {
			continue
		}
		row := map[string]any{"family": "ipv4", "address": a.IP.String(), "interface_index": a.IfIndex}
		if a.MAC != "" {
			row["mac"] = a.MAC
		}
		neigh = append(neigh, row)
	}
	have["neighbors"] = part("neighbors", neigh, r.Tables["arp"])
	out := make([]contracts.Section, 0, len(sectionOrder12))
	for _, n := range sectionOrder12 {
		if s, ok := have[n]; ok {
			out = append(out, s)
			continue
		}
		out = append(out, contracts.Section{Name: n, CollectedAt: at, Status: "unsupported", Reason: "SECTION_UNSUPPORTED", Records: []map[string]any{}})
	}
	return out
}

// Candidates12 — признаки идентификации устройства: имя (sysName). Сильных идентификаторов SNMP не даёт.
func Candidates12(sections []contracts.Section) []contracts.Candidate {
	for _, s := range sections {
		if s.Name != "identity" {
			continue
		}
		for _, r := range s.Records {
			if h, ok := r["hostname"].(string); ok && h != "" {
				return []contracts.Candidate{{Kind: "hostname", Namespace: "dns", Value: h}}
			}
		}
	}
	return []contracts.Candidate{}
}
