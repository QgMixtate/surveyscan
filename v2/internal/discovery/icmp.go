package discovery

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// ErrICMPNotPermitted — у процесса нет права на ICMP: ни сырого сокета (CAP_NET_RAW), ни непривилегированного
// ICMP (sysctl net.ipv4.ping_group_range). Это явная ошибка обследования, не «узлов нет» (D-13).
var ErrICMPNotPermitted = errors.New("icmp not permitted")

// ProbeICMP отправляет ICMP echo каждому адресу scope не чаще interval и ждёт ответы до timeout после последнего
// запроса. Сначала сырой сокет (CAP_NET_RAW), затем непривилегированный ICMP-сокет Linux.
func ProbeICMP(ctx context.Context, scope Scope, hosts []netip.Addr, interval, timeout time.Duration) ([]Observation, error) {
	for _, h := range hosts {
		if !scope.Allowed(h) {
			return nil, ErrOutOfScope
		}
	}
	network, conn := "ip4", (*icmp.PacketConn)(nil)
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		network = "udp4"
		if c, err = icmp.ListenPacket("udp4", "0.0.0.0"); err != nil {
			return nil, ErrICMPNotPermitted
		}
	}
	conn = c
	defer conn.Close()
	id := os.Getpid() & 0xffff
	var mu sync.Mutex
	seen := map[netip.Addr]time.Time{}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { // приём ответов
		defer close(done)
		buf := make([]byte, 1500)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, peer, err := conn.ReadFrom(buf)
			select {
			case <-stop:
				return
			default:
			}
			if err != nil {
				continue
			}
			m, err := icmp.ParseMessage(1, buf[:n])
			if err != nil || m.Type != ipv4.ICMPTypeEchoReply {
				continue
			}
			var ip net.IP
			switch a := peer.(type) {
			case *net.IPAddr:
				ip = a.IP
			case *net.UDPAddr:
				ip = a.IP
			}
			addr, ok := netip.AddrFromSlice(ip)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if network == "ip4" { // для сырого сокета — только наши запросы
				if e, ok := m.Body.(*icmp.Echo); !ok || e.ID != id {
					continue
				}
			}
			if scope.Allowed(addr) {
				mu.Lock()
				seen[addr] = time.Now().UTC()
				mu.Unlock()
			}
		}
	}()
	tick := time.NewTicker(interval)
	defer tick.Stop()
	var sendErr error
	for i, h := range hosts {
		select {
		case <-ctx.Done():
			sendErr = ctx.Err()
		case <-tick.C:
		}
		if sendErr != nil {
			break
		}
		msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: id, Seq: i & 0xffff, Data: []byte("surveyscan")}}
		b, _ := msg.Marshal(nil)
		var dst net.Addr = &net.IPAddr{IP: h.AsSlice()}
		if network == "udp4" {
			dst = &net.UDPAddr{IP: h.AsSlice()}
		}
		_, _ = conn.WriteTo(b, dst)
	}
	if sendErr == nil {
		select {
		case <-ctx.Done():
			sendErr = ctx.Err()
		case <-time.After(timeout):
		}
	}
	close(stop)
	<-done
	out := []Observation{}
	for a, at := range seen {
		out = append(out, Observation{IP: a, Source: "icmp", At: at})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP.Less(out[j].IP) })
	return out, sendErr
}
