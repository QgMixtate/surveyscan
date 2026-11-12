package app

import (
	"context"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	accessport "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/inventory"
	"github.com/QgMixtate/surveyscan/v2/internal/topology"
	"github.com/jackc/pgx/v5"
)

// Схема сети L3 из наблюдаемых фактов (C22). Только чтение; ничего не опрашивает в сети.
const topologyMaxAssets = 2000

type TopologyNode struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"` // host | subnet | gateway
	Label  string `json:"label"`
	Detail string `json:"detail,omitempty"`
	Asset  string `json:"asset_uid,omitempty"`
	Router bool   `json:"router,omitempty"`
}

type TopologyEvidence struct {
	Source string `json:"source"`
	Detail string `json:"detail"`
	Origin string `json:"origin,omitempty"`
}

type TopologyLink struct {
	A         string             `json:"a"`
	B         string             `json:"b"`
	Role      string             `json:"role,omitempty"` // gateway
	Layer     string             `json:"layer"`
	Level     string             `json:"confidence"`
	Evidence  []TopologyEvidence `json:"evidence"`
	Conflicts []string           `json:"conflicts,omitempty"`
}

type Topology struct {
	Tenant    string         `json:"tenant_id"`
	Generated time.Time      `json:"generated_at"`
	Nodes     []TopologyNode `json:"nodes"`
	Links     []TopologyLink `json:"links"`
	Truncated bool           `json:"truncated"`
	Hosts     int            `json:"hosts_with_network_facts"`
}

// C30.03: схема строится по всем сетевым фактам тенанта — дорого (стенд нагрузки: p50 24 с при 2 000 хостах и
// 100 пользователях). Результат кэшируется на тенант на topologyCacheTTL, одновременные запросы ждут одно вычисление;
// права проверяются на каждом запросе, возраст схемы виден в generated_at.
const topologyCacheTTL = 30 * time.Second

type topologyEntry struct {
	at    time.Time
	value Topology
	err   error
	ready chan struct{}
}

type topologyCache struct {
	mu      sync.Mutex
	entries map[string]*topologyEntry // текущее (возможно, ещё считающееся) вычисление
	last    map[string]*topologyEntry // последнее успешное — отдаётся во время пересчёта
}

func (r *Registry) Topology(ctx context.Context, id accessport.Identity) (Topology, error) {
	tx, e := r.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}) // авторизация обновляет сессию — не read-only
	if e != nil {
		return Topology{}, e
	}
	if _, e = r.Auth.Authorize(ctx, tx, id.CredentialID, id.TenantID, "assets:read"); e != nil {
		tx.Rollback(ctx)
		return Topology{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return Topology{}, e
	}
	c := &r.topology
	c.mu.Lock()
	if c.entries == nil {
		c.entries, c.last = map[string]*topologyEntry{}, map[string]*topologyEntry{}
	}
	entry := c.entries[id.TenantID]
	if entry == nil || isDone(entry.ready) && (entry.err != nil || time.Since(entry.at) > topologyCacheTTL) {
		if entry != nil && entry.err == nil {
			c.last[id.TenantID] = entry // устаревшая схема отдаётся, пока считается новая
		}
		next := &topologyEntry{ready: make(chan struct{})}
		c.entries[id.TenantID] = next
		go func() {
			compute, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
			defer cancel()
			next.value, next.err = r.computeTopology(compute, id.TenantID)
			next.at = time.Now()
			close(next.ready)
		}()
		entry = next
	}
	stale := c.last[id.TenantID]
	c.mu.Unlock()
	if !isDone(entry.ready) && stale != nil {
		return stale.value, nil
	}
	select {
	case <-entry.ready:
		return entry.value, entry.err
	case <-ctx.Done():
		return Topology{}, ctx.Err()
	}
}

func isDone(ch chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func (r *Registry) computeTopology(ctx context.Context, tenant string) (Topology, error) {
	out := Topology{Tenant: tenant, Generated: time.Now().UTC(), Nodes: []TopologyNode{}, Links: []TopologyLink{}}
	tx, e := r.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	hosts, truncated, e := r.Inventory.NetworkHosts(ctx, tx, tenant, topologyMaxAssets)
	if e != nil {
		return out, e
	}
	out.Truncated, out.Hosts = truncated, len(hosts)
	graph := topology.BuildL3(l3Hosts(hosts))
	for _, n := range graph.Nodes {
		node := TopologyNode{ID: n.ID, Kind: n.Kind, Label: n.Label, Detail: n.Detail, Router: n.Router}
		if n.Kind == "host" {
			node.Asset = n.ID[len("host:"):]
		}
		out.Nodes = append(out.Nodes, node)
	}
	for _, l := range graph.Links {
		link := TopologyLink{A: l.A.Node, B: l.B.Node, Role: l.B.Port, Layer: l.Layer, Level: string(l.Level), Conflicts: l.Conflicts, Evidence: []TopologyEvidence{}}
		for _, ev := range l.Evidence {
			item := TopologyEvidence{Source: ev.Source, Detail: ev.Detail}
			if ev.Source == "interface-address" {
				item.Origin = ev.Device
			}
			link.Evidence = append(link.Evidence, item)
		}
		out.Links = append(out.Links, link)
	}
	return out, tx.Commit(ctx)
}

func l3Hosts(hosts []inventory.NetworkHost) []topology.L3Host {
	out := make([]topology.L3Host, 0, len(hosts))
	for _, h := range hosts {
		l := topology.L3Host{ID: h.Asset, Name: h.Hostname, OS: h.OS}
		seen := map[netip.Addr]bool{}
		who := h.Hostname
		if who == "" {
			who = h.Asset[:8]
		}
		gateway := func(raw, detail string) {
			detail = who + ": " + detail
			if a, err := netip.ParseAddr(raw); err == nil && !seen[a] {
				seen[a] = true
				l.Gateways = append(l.Gateways, topology.L3Gateway{Addr: a, Detail: detail})
			}
		}
		for _, i := range h.Interfaces {
			li := topology.L3Interface{Name: i.Name, MAC: i.MAC, Source: i.Source}
			for _, a := range i.Addresses {
				if p, err := netip.ParsePrefix(a.IP + "/" + strconv.Itoa(a.Prefix)); err == nil {
					li.Addrs = append(li.Addrs, p)
				}
			}
			l.Interfaces = append(l.Interfaces, li)
			for _, g := range i.Gateways {
				gateway(g, "шлюз в настройках интерфейса "+i.Name)
			}
		}
		for _, r := range h.Routes {
			if r.Destination == "0.0.0.0/0" || r.Destination == "::/0" {
				gateway(r.Gateway, "маршрут по умолчанию via "+r.Gateway+" ("+r.Interface+")")
			}
		}
		out = append(out, l)
	}
	return out
}

func (r *Registry) topologyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.RawQuery != "" {
			access.APIError(w, 400, "INVALID_QUERY")
			return
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(req.Context()), 20*time.Second)
		defer cancel()
		id, _ := access.Identity(req.Context())
		out, e := r.Topology(ctx, id)
		if e != nil {
			registryError(w, e)
			return
		}
		registryJSON(w, out)
	})
}
