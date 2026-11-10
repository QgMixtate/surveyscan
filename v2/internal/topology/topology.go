// Package topology — доказательная топология L2/L3 из SNMP-инвентаря устройств (C22).
// Каждое ребро несёт доказательства (источник, устройство, порт) и уверенность; противоречия не стираются,
// а помечаются конфликтом. Порты с LLDP-соседом (uplink/trunk) не используются для привязки хостов по FDB.
package topology

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/QgMixtate/surveyscan/v2/internal/remote/snmpnet"
)

type Confidence string

const (
	Confirmed Confidence = "confirmed" // подтверждено с обеих сторон независимыми наблюдениями
	Probable  Confidence = "probable"  // одно прямое наблюдение (LLDP с одной стороны / единственный MAC на порту)
	Weak      Confidence = "weak"      // косвенно (общая подсеть)
)

type Device struct {
	ID     string
	Result snmpnet.Result
}

type Endpoint struct {
	Node string // ID устройства, "mac:<mac>", "subnet:<cidr>" или "ext:<chassis>"
	Port string // имя порта, если применимо
}

type Evidence struct {
	Source string // lldp | fdb | ip-subnet
	Device string
	Detail string
}

type Link struct {
	Layer     string // L2 | L3
	A, B      Endpoint
	Evidence  []Evidence
	Level     Confidence
	Conflicts []string
}

type Graph struct {
	Links []Link
	// Unattributed — MAC на портах с соседями/множеством MAC: место подключения не выводится.
	Unattributed []string
}

type portKey struct{ dev, port string }

func ifName(i snmpnet.Interface) string {
	if i.Name != "" {
		return i.Name
	}
	return i.Descr
}

// Build строит граф. MaxMACPerAccessPort: порт с большим числом MAC считается транком/uplink (по умолчанию 2).
func Build(devices []Device, maxMACPerAccessPort int) Graph {
	if maxMACPerAccessPort <= 0 {
		maxMACPerAccessPort = 2
	}
	// индексы устройств
	byMAC := map[string]string{}      // MAC интерфейса или chassis → ID устройства
	nameOfIdx := map[portKey]string{} // dev + ifIndex(as string) → имя порта
	for _, d := range devices {
		for _, i := range d.Result.Interfaces {
			if i.MAC != "" {
				byMAC[i.MAC] = d.ID
			}
			nameOfIdx[portKey{d.ID, fmt.Sprint(i.Index)}] = ifName(i)
		}
	}
	links := map[string]*Link{}
	add := func(layer string, a, b Endpoint, ev Evidence, level Confidence) {
		// ключ не зависит от направления
		ka, kb := a.Node+"|"+a.Port, b.Node+"|"+b.Port
		if ka > kb {
			a, b = b, a
			ka, kb = kb, ka
		}
		key := layer + "/" + ka + "/" + kb
		if l, ok := links[key]; ok {
			l.Evidence = append(l.Evidence, ev)
			if level == Confirmed || (level == Probable && l.Level == Weak) {
				l.Level = level
			}
			return
		}
		links[key] = &Link{Layer: layer, A: a, B: b, Evidence: []Evidence{ev}, Level: level}
	}
	uplink := map[portKey]bool{}
	// L2 по LLDP
	for _, d := range devices {
		for _, n := range d.Result.Neighbors {
			local := nameOfIdx[portKey{d.ID, fmt.Sprint(n.LocalPort)}]
			if local == "" {
				local = fmt.Sprintf("port%d", n.LocalPort)
			}
			uplink[portKey{d.ID, local}] = true
			peer := byMAC[strings.ToLower(n.ChassisID)]
			node, level := "ext:"+n.ChassisID, Probable
			if peer != "" {
				node = peer
			}
			add("L2", Endpoint{d.ID, local}, Endpoint{node, n.PortID}, Evidence{"lldp", d.ID, fmt.Sprintf("%s sees %s/%s", local, n.ChassisID, n.PortID)}, level)
		}
	}
	// двустороннее подтверждение LLDP: оба конца известных устройств сообщают одно ребро
	for _, l := range links {
		seenFrom := map[string]bool{}
		for _, e := range l.Evidence {
			if e.Source == "lldp" {
				seenFrom[e.Device] = true
			}
		}
		if len(seenFrom) >= 2 {
			l.Level = Confirmed
		}
	}
	// конфликт: один локальный порт указывает на разные удалённые концы
	remote := map[string][]string{}
	for _, l := range links {
		for _, e := range l.Evidence {
			if e.Source == "lldp" {
				local := Endpoint{e.Device, ""}
				var other Endpoint
				if l.A.Node == e.Device {
					local, other = l.A, l.B
				} else {
					local, other = l.B, l.A
				}
				k := local.Node + "|" + local.Port
				remote[k] = append(remote[k], other.Node+"|"+other.Port)
			}
		}
	}
	for _, l := range links {
		for _, end := range []Endpoint{l.A, l.B} {
			k := end.Node + "|" + end.Port
			if r := uniq(remote[k]); len(r) > 1 && uplink[portKey{end.Node, end.Port}] {
				l.Conflicts = append(l.Conflicts, "PORT_MULTIPLE_PEERS:"+k)
			}
		}
		sort.Strings(l.Conflicts)
		l.Conflicts = uniq(l.Conflicts)
	}
	// L2 по FDB: только access-порты (нет LLDP-соседа, MAC немного)
	var unattr []string
	for _, d := range devices {
		perPort := map[string][]string{}
		for _, f := range d.Result.FDB {
			name := nameOfIdx[portKey{d.ID, fmt.Sprint(f.IfIndex)}]
			if name == "" {
				name = fmt.Sprintf("port%d", f.Port)
			}
			if f.Status == 4 { // self: собственный MAC устройства
				continue
			}
			perPort[name] = append(perPort[name], f.MAC)
		}
		for port, macs := range perPort {
			if uplink[portKey{d.ID, port}] || len(macs) > maxMACPerAccessPort {
				unattr = append(unattr, macs...)
				continue
			}
			for _, m := range macs {
				node := "mac:" + m
				if dev := byMAC[m]; dev != "" && dev != d.ID {
					node = dev
				}
				add("L2", Endpoint{d.ID, port}, Endpoint{node, ""}, Evidence{"fdb", d.ID, fmt.Sprintf("%s learned on %s", m, port)}, Probable)
			}
		}
	}
	// L3: устройства в одной подсети (слабое косвенное доказательство)
	subnets := map[netip.Prefix][]Endpoint{}
	for _, d := range devices {
		for _, i := range d.Result.Interfaces {
			for _, p := range i.Addresses {
				if !p.Addr().IsLoopback() {
					subnets[p.Masked()] = append(subnets[p.Masked()], Endpoint{d.ID, ifName(i)})
				}
			}
		}
	}
	for p, eps := range subnets {
		for _, e := range eps {
			add("L3", Endpoint{e.Node, e.Port}, Endpoint{"subnet:" + p.String(), ""}, Evidence{"ip-subnet", e.Node, fmt.Sprintf("%s on %s", p, e.Port)}, Weak)
		}
	}
	g := Graph{Unattributed: uniq(unattr)}
	for _, l := range links {
		g.Links = append(g.Links, *l)
	}
	sort.Slice(g.Links, func(i, j int) bool {
		a, b := g.Links[i], g.Links[j]
		return a.Layer+a.A.Node+a.A.Port+a.B.Node+a.B.Port < b.Layer+b.A.Node+b.A.Port+b.B.Node+b.B.Port
	})
	return g
}

func uniq(in []string) []string {
	sort.Strings(in)
	out := in[:0]
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}
