// Package discovery — многоисточниковое обнаружение (C20): строгий scope, активные TCP/ARP-пробы с лимитами,
// импорт авторизованных таблиц (ARP/DHCP/DNS/FDB) и сведение наблюдений в хосты. Scope не расширяется:
// адреса вне scope отбрасываются и при пробах, и при импорте. ICMP требует привилегий и здесь не реализован.
package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

var ErrOutOfScope = errors.New("discovery: address is outside the authorized scope")

// Scope — разрешённые сети. Exclude приоритетнее Include. MaxHosts ограничивает размер прохода.
type Scope struct {
	Tenant, Site string
	Include      []netip.Prefix
	Exclude      []netip.Prefix
	MaxHosts     int
}

func (s Scope) Allowed(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range s.Exclude {
		if p.Contains(a) {
			return false
		}
	}
	for _, p := range s.Include {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Hosts перечисляет адреса scope (только IPv4) для активного прохода; сеть и broadcast /24 и уже опускаются.
func (s Scope) Hosts() ([]netip.Addr, error) {
	max := s.MaxHosts
	if max <= 0 {
		max = 1024
	}
	out := []netip.Addr{}
	for _, p := range s.Include {
		if !p.Addr().Is4() {
			continue
		}
		p = p.Masked()
		for a := p.Addr(); p.Contains(a); a = a.Next() {
			if p.Bits() < 31 && (a == p.Addr() || !p.Contains(a.Next())) {
				continue
			}
			if !s.Allowed(a) {
				continue
			}
			if len(out) >= max {
				return out, fmt.Errorf("discovery: scope exceeds MaxHosts=%d", max)
			}
			out = append(out, a)
		}
	}
	return out, nil
}

// Observation — одно наблюдение об адресе из любого источника.
type Observation struct {
	IP       netip.Addr
	MAC      string // нижний регистр aa:bb:..., пусто если неизвестен
	Hostname string
	Source   string // probe-tcp | arp | snmp-arp | snmp-fdb | dhcp | dns | ...
	Detail   string // например открытые порты
	At       time.Time
}

// ProbeOptions — ограничения активного прохода.
type ProbeOptions struct {
	Ports       []int
	Timeout     time.Duration
	Concurrency int
	MinInterval time.Duration // пауза между запусками проб (общая)
}

// ProbeTCP пробует TCP-подключения к портам хостов scope. Хост «жив», если порт принял соединение или ответил RST
// (connection refused): оба факта доказывают наличие хоста, таймаут — нет. Адрес вне scope → ErrOutOfScope.
func ProbeTCP(ctx context.Context, scope Scope, hosts []netip.Addr, o ProbeOptions) ([]Observation, error) {
	if o.Timeout <= 0 {
		o.Timeout = time.Second
	}
	if o.Concurrency <= 0 || o.Concurrency > 256 {
		o.Concurrency = 32
	}
	if len(o.Ports) == 0 {
		o.Ports = []int{22, 80, 443, 445, 3389}
	}
	for _, h := range hosts {
		if !scope.Allowed(h) {
			return nil, ErrOutOfScope
		}
	}
	var (
		mu   sync.Mutex
		out  []Observation
		wg   sync.WaitGroup
		sem  = make(chan struct{}, o.Concurrency)
		tick <-chan time.Time
	)
	if o.MinInterval > 0 {
		t := time.NewTicker(o.MinInterval)
		defer t.Stop()
		tick = t.C
	}
	for _, h := range hosts {
		if tick != nil {
			select {
			case <-tick:
			case <-ctx.Done():
				wg.Wait()
				return out, ctx.Err()
			}
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return out, ctx.Err()
		}
		wg.Add(1)
		go func(h netip.Addr) {
			defer wg.Done()
			defer func() { <-sem }()
			open := []string{}
			alive := false
			for _, port := range o.Ports {
				d := net.Dialer{Timeout: o.Timeout}
				c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(h.String(), fmt.Sprint(port)))
				if err == nil {
					c.Close()
					alive = true
					open = append(open, fmt.Sprint(port))
				} else if strings.Contains(err.Error(), "refused") {
					alive = true
				}
			}
			if alive {
				mu.Lock()
				out = append(out, Observation{IP: h, Source: "probe-tcp", Detail: "open=" + strings.Join(open, ","), At: time.Now().UTC()})
				mu.Unlock()
			}
		}(h)
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].IP.Less(out[j].IP) })
	return out, ctx.Err()
}

// ParseProcARP разбирает /proc/net/arp (локальный ARP-кэш): только полные записи (флаг 0x2) с ненулевым MAC.
func ParseProcARP(text string, at time.Time) []Observation {
	out := []Observation{}
	for i, l := range strings.Split(text, "\n") {
		f := strings.Fields(l)
		if i == 0 || len(f) < 4 {
			continue
		}
		ip, err := netip.ParseAddr(f[0])
		mac := strings.ToLower(f[3])
		if err != nil || f[2] != "0x2" || mac == "00:00:00:00:00:00" || len(mac) != 17 {
			continue
		}
		out = append(out, Observation{IP: ip, MAC: mac, Source: "arp", At: at})
	}
	return out
}

// ParseDHCPLeases разбирает упрощённый импорт аренд: строки «ip mac hostname» (пустые и # игнорируются).
func ParseDHCPLeases(text string, at time.Time) []Observation {
	out := []Observation{}
	for _, l := range strings.Split(text, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 || strings.HasPrefix(f[0], "#") {
			continue
		}
		ip, err := netip.ParseAddr(f[0])
		mac := strings.ToLower(f[1])
		if err != nil || len(mac) != 17 {
			continue
		}
		o := Observation{IP: ip, MAC: mac, Source: "dhcp", At: at}
		if len(f) >= 3 && f[2] != "*" {
			o.Hostname = f[2]
		}
		out = append(out, o)
	}
	return out
}

// Host — результат сведения: идентичность по MAC (если есть), иначе по IP.
type Host struct {
	MAC       string
	IPs       []netip.Addr
	Hostnames []string
	Sources   []string
	FirstSeen time.Time
	LastSeen  time.Time
	Conflicts []string // IP_CONFLICT:<ip> — один IP с разными MAC; MULTIHOMED — один MAC, несколько IP
}

// Merge сводит наблюдения в хосты. Вне scope — отбрасывается (счётчик dropped). Повторные наблюдения не создают
// дубликатов; один IP с разными MAC помечается конфликтом у обоих хостов (не склеивается молча).
func Merge(scope Scope, obs []Observation) (hosts []Host, dropped int) {
	byKey := map[string]*Host{}
	order := []string{}
	macOfIP := map[netip.Addr]map[string]bool{}
	for _, o := range obs {
		if !o.IP.IsValid() || !scope.Allowed(o.IP) {
			dropped++
			continue
		}
		ip := o.IP.Unmap()
		key := o.MAC
		if key == "" {
			// без MAC: присоединяем к уже известному по IP хосту, иначе создаём «по IP»
			for _, k := range order {
				if hasIP(byKey[k], ip) {
					key = k
					break
				}
			}
			if key == "" {
				key = "ip:" + ip.String()
			}
		} else if h, ok := byKey["ip:"+ip.String()]; ok { // раньше был известен только IP: повышаем до MAC
			delete(byKey, "ip:"+ip.String())
			for i, k := range order {
				if k == "ip:"+ip.String() {
					order[i] = key
				}
			}
			if _, exists := byKey[key]; !exists {
				h.MAC = key
				byKey[key] = h
			} else {
				mergeInto(byKey[key], h)
			}
		}
		h, ok := byKey[key]
		if !ok {
			h = &Host{FirstSeen: o.At}
			if !strings.HasPrefix(key, "ip:") {
				h.MAC = key
			}
			byKey[key] = h
			order = append(order, key)
		}
		if !hasIP(h, ip) {
			h.IPs = append(h.IPs, ip)
		}
		if o.Hostname != "" && !contains(h.Hostnames, o.Hostname) {
			h.Hostnames = append(h.Hostnames, o.Hostname)
		}
		if !contains(h.Sources, o.Source) {
			h.Sources = append(h.Sources, o.Source)
		}
		if h.FirstSeen.IsZero() || (!o.At.IsZero() && o.At.Before(h.FirstSeen)) {
			h.FirstSeen = o.At
		}
		if o.At.After(h.LastSeen) {
			h.LastSeen = o.At
		}
		if o.MAC != "" {
			if macOfIP[ip] == nil {
				macOfIP[ip] = map[string]bool{}
			}
			macOfIP[ip][o.MAC] = true
		}
	}
	for ip, macs := range macOfIP {
		if len(macs) > 1 {
			for m := range macs {
				if h := byKey[m]; h != nil {
					h.Conflicts = appendUnique(h.Conflicts, "IP_CONFLICT:"+ip.String())
				}
			}
		}
	}
	for _, k := range order {
		h := byKey[k]
		if h.MAC != "" && len(h.IPs) > 1 {
			h.Conflicts = appendUnique(h.Conflicts, "MULTIHOMED")
		}
		sort.Slice(h.IPs, func(i, j int) bool { return h.IPs[i].Less(h.IPs[j]) })
		sort.Strings(h.Hostnames)
		sort.Strings(h.Sources)
		sort.Strings(h.Conflicts)
		hosts = append(hosts, *h)
	}
	sort.Slice(hosts, func(i, j int) bool {
		if len(hosts[i].IPs) == 0 || len(hosts[j].IPs) == 0 {
			return len(hosts[i].IPs) > len(hosts[j].IPs)
		}
		return hosts[i].IPs[0].Less(hosts[j].IPs[0])
	})
	return hosts, dropped
}

func mergeInto(dst, src *Host) {
	for _, ip := range src.IPs {
		if !hasIP(dst, ip) {
			dst.IPs = append(dst.IPs, ip)
		}
	}
	for _, n := range src.Hostnames {
		dst.Hostnames = appendUnique(dst.Hostnames, n)
	}
	for _, s := range src.Sources {
		dst.Sources = appendUnique(dst.Sources, s)
	}
	if !src.FirstSeen.IsZero() && (dst.FirstSeen.IsZero() || src.FirstSeen.Before(dst.FirstSeen)) {
		dst.FirstSeen = src.FirstSeen
	}
	if src.LastSeen.After(dst.LastSeen) {
		dst.LastSeen = src.LastSeen
	}
}
func hasIP(h *Host, ip netip.Addr) bool {
	for _, x := range h.IPs {
		if x == ip {
			return true
		}
	}
	return false
}
func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
func appendUnique(l []string, s string) []string {
	if contains(l, s) {
		return l
	}
	return append(l, s)
}
