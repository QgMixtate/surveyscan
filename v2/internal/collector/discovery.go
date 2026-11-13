package collector

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/discovery"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/telemetry"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

// C51.02 (контракт contracts/c51-discovery.schema.json, ADR D13): collector сам забирает у центра задания
// обследования своих подсетей, выполняет пробы с ограничениями D-13 и сдаёт подписанный результат. Настройка
// collector вручную не нужна: подсети, пробы и расписание задаются в Web.

const discoverySignaturePrefix = "SURVEYSCAN-DISCOVERY-V1\n"

type discoveryJob struct {
	Run       string   `json:"run_id"`
	Network   string   `json:"network_id"`
	CIDR      string   `json:"cidr"`
	Probes    []string `json:"probes"`
	Ports     []int    `json:"ports"`
	Rate      int      `json:"rate_per_second"`
	TimeoutMS int      `json:"timeout_ms"`
}

type foundHost struct {
	IP    string  `json:"ip"`
	MAC   *string `json:"mac,omitempty"`
	Ports []int   `json:"ports"`
	ICMP  bool    `json:"icmp"`
}

type discoveryResult struct {
	Major      int         `json:"major"`
	ResultID   string      `json:"result_id"`
	Tenant     string      `json:"tenant_id"`
	Source     string      `json:"source_id"`
	Generation string      `json:"generation_id"`
	Run        string      `json:"run_id"`
	StartedAt  time.Time   `json:"started_at"`
	FinishedAt time.Time   `json:"finished_at"`
	Addresses  int         `json:"addresses"`
	Hosts      []foundHost `json:"hosts"`
	Errors     []string    `json:"errors"`
}

// arpTable читает таблицу соседей (Linux); подменяется в тестах.
var arpTable = func() (string, error) {
	b, e := os.ReadFile("/proc/net/arp")
	return string(b), e
}

// runDiscovery выполняет задание. Ошибки вида «проба:причина» не прерывают другие пробы.
func runDiscovery(ctx context.Context, job discoveryJob) (addresses int, hosts []foundHost, errs []string, e error) {
	prefix, e := netip.ParsePrefix(job.CIDR)
	if e != nil || !prefix.Addr().Is4() || prefix.Bits() < 22 || job.Rate < 1 || job.Rate > 50 || job.TimeoutMS < 100 || job.TimeoutMS > 5000 {
		return 0, nil, nil, errors.New("invalid discovery job") // за пределами D-13 не выполняем даже по просьбе центра
	}
	scope := discovery.Scope{Include: []netip.Prefix{prefix}, MaxHosts: 1024}
	addrs, e := scope.Hosts()
	if e != nil {
		return 0, nil, nil, e
	}
	timeout := time.Duration(job.TimeoutMS) * time.Millisecond
	var obs []discovery.Observation
	ports := map[netip.Addr][]int{}
	icmpSeen := map[netip.Addr]bool{}
	for _, p := range job.Probes {
		switch p {
		case "icmp":
			got, err := discovery.ProbeICMP(ctx, scope, addrs, time.Second/time.Duration(job.Rate), timeout)
			if errors.Is(err, discovery.ErrICMPNotPermitted) {
				errs = append(errs, "icmp:not_permitted")
			} else if err != nil {
				errs = append(errs, "icmp:failed")
			}
			for _, o := range got {
				icmpSeen[o.IP] = true
			}
			obs = append(obs, got...)
		case "tcp":
			// одна «проба» = одна попытка соединения: интервал между узлами — число портов / предел в секунду
			interval := time.Duration(len(job.Ports)) * time.Second / time.Duration(job.Rate)
			got, err := discovery.ProbeTCP(ctx, scope, addrs, discovery.ProbeOptions{Ports: job.Ports, Timeout: timeout, Concurrency: 16, MinInterval: interval})
			if err != nil {
				errs = append(errs, "tcp:failed")
			}
			for _, o := range got {
				for _, x := range strings.Split(strings.TrimPrefix(o.Detail, "open="), ",") {
					if n, err := strconv.Atoi(x); err == nil {
						ports[o.IP] = append(ports[o.IP], n)
					}
				}
			}
			obs = append(obs, got...)
		}
	}
	if contains(job.Probes, "arp") { // после остальных проб таблица соседей заполнена ответившими узлами сегмента
		text, err := arpTable()
		if err != nil {
			errs = append(errs, "arp:unavailable")
		} else {
			obs = append(obs, discovery.ParseProcARP(text, time.Now().UTC())...)
		}
	}
	merged, _ := discovery.Merge(scope, obs)
	byIP := map[netip.Addr]*foundHost{}
	for _, h := range merged {
		for _, ip := range h.IPs {
			if !prefix.Contains(ip) {
				continue
			}
			f := byIP[ip]
			if f == nil {
				f = &foundHost{IP: ip.String(), Ports: []int{}}
				byIP[ip] = f
			}
			if h.MAC != "" {
				m := h.MAC
				f.MAC = &m
			}
		}
	}
	for ip, f := range byIP {
		f.Ports = append(f.Ports, ports[ip]...)
		sort.Ints(f.Ports)
		f.ICMP = icmpSeen[ip]
		hosts = append(hosts, *f)
	}
	sort.Slice(hosts, func(i, j int) bool {
		a, _ := netip.ParseAddr(hosts[i].IP)
		b, _ := netip.ParseAddr(hosts[j].IP)
		return a.Less(b)
	})
	return len(addrs), hosts, errs, nil
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// discoveryTick — одно обращение к центру: взять задание, выполнить, сдать подписанный результат.
func (c *Collector) discoveryTick(ctx context.Context) error {
	code, raw, e := c.post(ctx, "/api/v1/machine/discovery-jobs", []byte("{}"), "")
	if e != nil {
		return e
	}
	if code == 404 || code == 501 {
		return nil // центр без C51
	}
	if code != 200 {
		return errors.New("discovery job request rejected")
	}
	var got struct {
		Job *discoveryJob `json:"job"`
	}
	if e = json.Unmarshal(raw, &got); e != nil {
		return e
	}
	if got.Job == nil {
		return nil
	}
	started := time.Now().UTC()
	work, cancel := context.WithTimeout(ctx, 30*time.Minute)
	addresses, hosts, errs, e := runDiscovery(work, *got.Job)
	cancel()
	if e != nil {
		errs = append(errs, "job:invalid")
	}
	if hosts == nil {
		hosts = []foundHost{}
	}
	if errs == nil {
		errs = []string{}
	}
	payload, _ := json.Marshal(discoveryResult{Major: 1, ResultID: identifier.New(), Tenant: c.Claims.Tenant, Source: c.Claims.Source, Generation: c.Claims.Generation,
		Run: got.Job.Run, StartedAt: started, FinishedAt: time.Now().UTC(), Addresses: addresses, Hosts: hosts, Errors: errs})
	canonical, e := wire.Canonical(payload)
	if e != nil {
		return e
	}
	sum := sha256.Sum256(canonical)
	signature := ed25519.Sign(c.signing, append([]byte(discoverySignaturePrefix), canonical...))
	body, _ := json.Marshal(map[string]any{"payload": json.RawMessage(payload), "payload_sha256": hex.EncodeToString(sum[:]), "key_id": c.Claims.KeyID, "signature": base64.RawURLEncoding.EncodeToString(signature)})
	submit, done := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer done()
	if code, _, e = c.post(submit, "/api/v1/machine/discovery-results", body, ""); e != nil || code != 200 {
		return errors.New("discovery result not accepted")
	}
	telemetry.Log(os.Stderr, "collector", "discovery_run_submitted")
	return nil
}

// discoveryLoop — раз в 30 с, одно обследование за раз.
func (c *Collector) discoveryLoop(ctx context.Context, busy *atomic.Bool) {
	if !busy.CompareAndSwap(false, true) {
		return
	}
	defer busy.Store(false)
	if e := c.discoveryTick(ctx); e != nil && ctx.Err() == nil {
		telemetry.Log(os.Stderr, "collector", "discovery_unavailable")
	}
}
