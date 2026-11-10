package topology

import (
	"fmt"
	"net/netip"
	"sort"
)

// L3Host — актив с наблюдаемыми интерфейсами (из инвентаризации агентов/SSH/WinRM/portable).
type L3Host struct {
	ID, Name, OS string
	Interfaces   []L3Interface
	Gateways     []L3Gateway // шлюзы из маршрутов (0.0.0.0/0, ::/0) и настроек интерфейсов
}

type L3Interface struct {
	Name, MAC, Source string
	Addrs             []netip.Prefix // адрес хоста с длиной префикса (не маскированный)
}

type L3Gateway struct {
	Addr   netip.Addr
	Detail string // откуда известен шлюз
}

// Node — узел схемы: host:<asset>, subnet:<cidr>, gw:<ip>.
type Node struct {
	ID     string
	Kind   string // host | subnet | gateway
	Label  string
	Detail string
	Router bool // host, который является шлюзом для других
}

// L3Graph — схема L3, построенная только из наблюдаемых фактов. Рёбра несут доказательства и уверенность.
type L3Graph struct {
	Nodes []Node
	Links []Link
}

// usable: адрес участвует в схеме, если это не loopback/link-local/multicast/unspecified и префикс осмыслен.
func usable(p netip.Prefix) bool {
	a := p.Addr()
	if !p.IsValid() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() || a.IsInterfaceLocalMulticast() {
		return false
	}
	if a.Is4() {
		return p.Bits() >= 8 && p.Bits() <= 30
	}
	return p.Bits() >= 32 && p.Bits() <= 64
}

// BuildL3 строит схему: хост — подсеть (адрес на интерфейсе), подсеть — шлюз (маршрут по умолчанию/настройка).
// Шлюз, совпавший с адресом известного актива, становится этим активом (роль маршрутизатора), иначе — узел gw.
// Один IP у нескольких активов не склеивается, а помечается конфликтом на ребре.
func BuildL3(hosts []L3Host) L3Graph {
	var g L3Graph
	nodes := map[string]*Node{}
	add := func(n Node) *Node {
		if existing := nodes[n.ID]; existing != nil {
			return existing
		}
		nodes[n.ID] = &n
		return nodes[n.ID]
	}
	owners := map[netip.Addr][]string{} // IP → активы
	type membership struct{ host, subnet, detail, source string }
	var members []membership
	for _, h := range hosts {
		label := h.Name
		if label == "" {
			label = "Без имени"
		}
		add(Node{ID: "host:" + h.ID, Kind: "host", Label: label, Detail: h.OS})
		for _, i := range h.Interfaces {
			for _, p := range i.Addrs {
				if !usable(p) {
					continue
				}
				subnet := p.Masked()
				add(Node{ID: "subnet:" + subnet.String(), Kind: "subnet", Label: subnet.String()})
				owners[p.Addr()] = append(owners[p.Addr()], h.ID)
				members = append(members, membership{h.ID, subnet.String(), fmt.Sprintf("%s %s", i.Name, p), i.Source})
			}
		}
	}
	links := map[string]*Link{}
	link := func(layer string, a, b Endpoint, ev Evidence, level Confidence) *Link {
		key := layer + "|" + a.Node + "|" + a.Port + "|" + b.Node
		l := links[key]
		if l == nil {
			l = &Link{Layer: layer, A: a, B: b, Level: level}
			links[key] = l
		}
		l.Evidence = append(l.Evidence, ev)
		return l
	}
	for _, m := range members {
		link("L3", Endpoint{Node: "host:" + m.host}, Endpoint{Node: "subnet:" + m.subnet}, Evidence{Source: "interface-address", Device: m.source, Detail: m.detail}, Probable)
	}
	for ip, list := range owners {
		uniq := map[string]bool{}
		for _, id := range list {
			uniq[id] = true
		}
		if len(uniq) < 2 {
			continue
		}
		ids := make([]string, 0, len(uniq))
		for id := range uniq {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, l := range links {
			for _, id := range ids {
				if l.A.Node == "host:"+id {
					for _, ev := range l.Evidence {
						if p, err := netip.ParsePrefix(lastField(ev.Detail)); err == nil && p.Addr() == ip {
							l.Conflicts = append(l.Conflicts, fmt.Sprintf("IP %s наблюдается у %d активов", ip, len(ids)))
						}
					}
				}
			}
		}
	}
	for _, h := range hosts {
		// подсети хоста — чтобы привязать шлюз к той, в которой он лежит
		var own []netip.Prefix
		for _, i := range h.Interfaces {
			for _, p := range i.Addrs {
				if usable(p) {
					own = append(own, p.Masked())
				}
			}
		}
		for _, gw := range h.Gateways {
			if !gw.Addr.IsValid() || gw.Addr.IsUnspecified() {
				continue
			}
			var subnet netip.Prefix
			for _, p := range own {
				if p.Contains(gw.Addr) {
					subnet = p
					break
				}
			}
			if !subnet.IsValid() {
				continue // шлюз вне известных подсетей хоста — связь не выводится
			}
			target := "gw:" + gw.Addr.String()
			level := Weak
			if ids := owners[gw.Addr]; len(ids) == 1 {
				target = "host:" + ids[0]
				nodes[target].Router = true
				level = Probable
			} else {
				add(Node{ID: target, Kind: "gateway", Label: gw.Addr.String(), Detail: "шлюз (устройство не инвентаризовано)"})
			}
			link("L3", Endpoint{Node: "subnet:" + subnet.String()}, Endpoint{Node: target, Port: "gateway"}, Evidence{Source: "route", Device: h.ID, Detail: gw.Detail}, level)
		}
	}
	for _, n := range nodes {
		g.Nodes = append(g.Nodes, *n)
	}
	sort.Slice(g.Nodes, func(i, j int) bool { return g.Nodes[i].ID < g.Nodes[j].ID })
	for _, l := range links {
		g.Links = append(g.Links, *l)
	}
	sort.Slice(g.Links, func(i, j int) bool {
		if g.Links[i].A.Node != g.Links[j].A.Node {
			return g.Links[i].A.Node < g.Links[j].A.Node
		}
		return g.Links[i].B.Node < g.Links[j].B.Node
	})
	return g
}

func lastField(s string) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ' ' {
			return s[i+1:]
		}
	}
	return s
}
