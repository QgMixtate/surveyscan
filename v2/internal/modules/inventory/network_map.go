package inventory

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

// NetworkAddress — адрес интерфейса, как его сообщил источник.
type NetworkAddress struct {
	IP     string `json:"ip"`
	Prefix int    `json:"prefix"`
}

// NetworkInterface — наблюдаемый интерфейс актива (проекции 1.0 и 1.2).
type NetworkInterface struct {
	Name      string
	MAC       string
	Addresses []NetworkAddress
	Gateways  []string
	Source    string // source_id, сообщивший интерфейс
}

// NetworkHost — сетевые факты одного актива для схемы сети.
type NetworkHost struct {
	Asset      string
	Hostname   string
	OS         string
	Interfaces []NetworkInterface
	Routes     []NetworkRoute
}

// NetworkRoute — маршрут из routes_ports (kind=route).
type NetworkRoute struct {
	Destination string
	Gateway     string
	Interface   string
}

// NetworkHosts читает сетевые факты активов tenant (не более limit активов, упорядочено по asset_uid).
// Вызывать в транзакции после авторизации assets:read. truncated=true, если активов больше limit.
func (Store) NetworkHosts(ctx context.Context, tx pgx.Tx, tenant string, limit int) ([]NetworkHost, bool, error) {
	hosts := map[string]*NetworkHost{}
	order := []string{}
	get := func(asset string) *NetworkHost {
		h := hosts[asset]
		if h == nil {
			h = &NetworkHost{Asset: asset}
			hosts[asset] = h
			order = append(order, asset)
		}
		return h
	}
	// Проекция 1.2: network (по записи — имя/mac/адреса/шлюзы), identity/os (имя, ОС), routes_ports kind=route.
	rows, err := tx.Query(ctx, `SELECT f.asset_uid::text,f.section_name,f.record_key,f.field_name,f.value,o.source_id::text FROM inventory.record_facts12 f JOIN inventory.observations o ON o.tenant_id=f.tenant_id AND o.observation_id=f.observation_id
WHERE f.tenant_id=$1 AND f.asset_uid IN (SELECT DISTINCT asset_uid FROM inventory.record_facts12 WHERE tenant_id=$1 AND section_name='network' UNION SELECT DISTINCT asset_uid FROM inventory.current_facts WHERE tenant_id=$1 AND section_name='network' ORDER BY 1 LIMIT $2+1)
AND (f.section_name='network' AND f.field_name IN ('name','mac','addresses','gateways')
 OR f.section_name='identity' AND f.field_name='hostname' OR f.section_name='os' AND f.field_name IN ('name','version')
 OR f.section_name='routes_ports' AND f.field_name IN ('kind','destination','gateway','interface'))`, tenant, limit)
	if err != nil {
		return nil, false, err
	}
	type rec struct {
		section, source string
		fields          map[string]json.RawMessage
	}
	records := map[string]map[string]*rec{}
	for rows.Next() {
		var asset, section, key, field, source string
		var value json.RawMessage
		if err = rows.Scan(&asset, &section, &key, &field, &value, &source); err != nil {
			rows.Close()
			return nil, false, err
		}
		get(asset)
		if records[asset] == nil {
			records[asset] = map[string]*rec{}
		}
		r := records[asset][section+"/"+key]
		if r == nil {
			r = &rec{section: section, source: source, fields: map[string]json.RawMessage{}}
			records[asset][section+"/"+key] = r
		}
		r.fields[field] = value
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, false, err
	}
	text := func(raw json.RawMessage) string {
		var s string
		_ = json.Unmarshal(raw, &s)
		return s
	}
	for asset, recs := range records {
		h := hosts[asset]
		keys := make([]string, 0, len(recs))
		for k := range recs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			r := recs[k]
			switch r.section {
			case "identity":
				if h.Hostname == "" {
					h.Hostname = text(r.fields["hostname"])
				}
			case "os":
				h.OS = strings.TrimSpace(text(r.fields["name"]) + " " + text(r.fields["version"]))
			case "network":
				n := NetworkInterface{Name: text(r.fields["name"]), MAC: text(r.fields["mac"]), Source: r.source}
				_ = json.Unmarshal(r.fields["addresses"], &n.Addresses)
				_ = json.Unmarshal(r.fields["gateways"], &n.Gateways)
				h.Interfaces = append(h.Interfaces, n)
			case "routes_ports":
				if text(r.fields["kind"]) == "route" {
					h.Routes = append(h.Routes, NetworkRoute{Destination: text(r.fields["destination"]), Gateway: text(r.fields["gateway"]), Interface: text(r.fields["interface"])})
				}
			}
		}
	}
	// Проекция 1.0: current_facts network (<интерфейс>.addresses/.mac), identity.hostname, os.
	rows, err = tx.Query(ctx, `SELECT c.asset_uid::text,c.section_name,c.fact_key,c.value,o.source_id::text FROM inventory.current_facts c JOIN inventory.observations o ON o.tenant_id=c.tenant_id AND o.observation_id=c.observation_id
WHERE c.tenant_id=$1 AND c.section_name IN ('network','identity','os') AND c.asset_uid IN (SELECT DISTINCT asset_uid FROM inventory.record_facts12 WHERE tenant_id=$1 AND section_name='network' UNION SELECT DISTINCT asset_uid FROM inventory.current_facts WHERE tenant_id=$1 AND section_name='network' ORDER BY 1 LIMIT $2+1)`, tenant, limit)
	if err != nil {
		return nil, false, err
	}
	legacy := map[string]map[string]*NetworkInterface{}
	osFields := map[string]map[string]string{}
	for rows.Next() {
		var asset, section, key, value, source string
		if err = rows.Scan(&asset, &section, &key, &value, &source); err != nil {
			rows.Close()
			return nil, false, err
		}
		h := get(asset)
		switch section {
		case "identity":
			if key == "hostname" {
				h.Hostname = value // 1.0 первична
			}
		case "os":
			if osFields[asset] == nil {
				osFields[asset] = map[string]string{}
			}
			osFields[asset][key] = value
		case "network":
			name, field, ok := strings.Cut(key, ".")
			if !ok {
				continue
			}
			if legacy[asset] == nil {
				legacy[asset] = map[string]*NetworkInterface{}
			}
			n := legacy[asset][name]
			if n == nil {
				n = &NetworkInterface{Name: name, Source: source}
				legacy[asset][name] = n
			}
			switch field {
			case "mac":
				n.MAC = value
			case "addresses":
				_ = json.Unmarshal([]byte(value), &n.Addresses)
			}
		}
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, false, err
	}
	for asset, f := range osFields {
		if name := strings.TrimSpace(f["name"] + " " + f["version"]); name != "" {
			hosts[asset].OS = name
		}
	}
	for asset, ifs := range legacy {
		h := hosts[asset]
		names := make([]string, 0, len(ifs))
		for name := range ifs {
			names = append(names, name)
		}
		sort.Strings(names)
	next:
		for _, name := range names {
			for _, existing := range h.Interfaces {
				if existing.Name == name && existing.MAC == ifs[name].MAC {
					continue next // тот же интерфейс уже из 1.2
				}
			}
			h.Interfaces = append(h.Interfaces, *ifs[name])
		}
	}
	sort.Strings(order)
	truncated := len(order) > limit
	if truncated {
		order = order[:limit]
	}
	out := make([]NetworkHost, 0, len(order))
	for _, asset := range order {
		out = append(out, *hosts[asset])
	}
	return out, truncated, nil
}
