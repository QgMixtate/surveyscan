package router

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// Сводка по шардам (C37.04): ограниченный параллелизм, тайм-аут на ячейку, частичный отказ виден явно (сводка не
// выдаёт неполные числа за полные). Отключённые копии организаций после переноса считаются отдельно.

type ShardSummary struct {
	Shard    string `json:"shard_id"`
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	Tenants  int    `json:"active_tenants"`
	Disabled int    `json:"disabled_tenants"`
	Assets   int64  `json:"assets"`
}

type Summary struct {
	Complete   bool           `json:"complete"`
	Shards     []ShardSummary `json:"shards"`
	Assets     int64          `json:"assets_in_available_shards"`
	Duplicates []string       `json:"duplicate_asset_uids"` // UID в активных организациях более чем одного шарда
	Misplaced  []string       `json:"misplaced_tenants"`    // активна в ячейке, но каталог указывает другой шард
}

// Dial открывает подключение к ячейке.
type Dial func(ctx context.Context, shard string) (*pgx.Conn, error)

func Summarize(ctx context.Context, cat Catalog, shards []string, dial Dial, parallel int, timeout time.Duration) Summary {
	if parallel < 1 {
		parallel = 4
	}
	type result struct {
		s    ShardSummary
		uids []string
		act  []string
	}
	results := make([]result, len(shards))
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for i, name := range shards {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			r := result{s: ShardSummary{Shard: name}}
			c, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			e := func() error {
				conn, e := dial(c, name)
				if e != nil {
					return e
				}
				defer conn.Close(context.WithoutCancel(c))
				rows, e := conn.Query(c, `SELECT t.tenant_id::text,t.status,(SELECT count(*) FROM assets.assets a WHERE a.tenant_id=t.tenant_id) FROM access.tenants t`)
				if e != nil {
					return e
				}
				for rows.Next() {
					var tenant, status string
					var n int64
					if e = rows.Scan(&tenant, &status, &n); e != nil {
						return e
					}
					if status == "active" {
						r.s.Tenants++
						r.s.Assets += n
						r.act = append(r.act, tenant)
					} else {
						r.s.Disabled++
					}
				}
				if e = rows.Err(); e != nil {
					return e
				}
				rows, e = conn.Query(c, `SELECT a.asset_uid::text FROM assets.assets a JOIN access.tenants t USING (tenant_id) WHERE t.status='active'`)
				if e != nil {
					return e
				}
				r.uids, e = pgx.CollectRows(rows, pgx.RowTo[string])
				return e
			}()
			if e != nil {
				r = result{s: ShardSummary{Shard: name, Error: "unavailable"}}
			} else {
				r.s.OK = true
			}
			results[i] = r
		}(i, name)
	}
	wg.Wait()
	out := Summary{Complete: true, Duplicates: []string{}, Misplaced: []string{}}
	seen := map[string]string{}
	for _, r := range results {
		out.Shards = append(out.Shards, r.s)
		if !r.s.OK {
			out.Complete = false
			continue
		}
		out.Assets += r.s.Assets
		for _, u := range r.uids {
			if prev, ok := seen[u]; ok && prev != r.s.Shard {
				out.Duplicates = append(out.Duplicates, u)
			}
			seen[u] = r.s.Shard
		}
		for _, t := range r.act {
			if p, e := cat.Placement(ctx, t); e != nil || p.Shard != r.s.Shard {
				out.Misplaced = append(out.Misplaced, t)
			}
		}
	}
	sort.Strings(out.Duplicates)
	sort.Strings(out.Misplaced)
	return out
}
