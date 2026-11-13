// surveyscan-router — маршрутизатор ячеек и каталог организаций (C37, ADR decisions/C37-shards.md).
//
//	surveyscan-router <команда> -config router.json [флаги]
//	  serve | init-catalog | add-shard -id ID -region R | place -tenant T -shard ID -home R [-dr R] [-residency X]
//	  sync-logins | summary | move-tenant | set-writer -shard ID -node N | failover -shard ID -to N [-old-unreachable] | check-writers -tenant T -to ID [-dry-run]
//
// Конфигурация (приватный файл, пароли — только в отдельных файлах):
//
//	{"listen":"127.0.0.1:8090","secure":true,"route_key_file":"/etc/surveyscan/route.key",
//	 "catalog":{"database_url":"postgres://router@db/catalog","password_file":"/etc/surveyscan/catalog.pw"},
//	 "shards":{"cell-a":{"backend":"http://10.0.0.11:8080","database_url":"postgres://admin@db-a/surveyscan","password_file":"…"}}}
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/config"
	"github.com/QgMixtate/surveyscan/v2/internal/router"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type dbConfig struct {
	DatabaseURL  string `json:"database_url"`
	PasswordFile string `json:"password_file"`
}

type shardConfig struct {
	Backend string `json:"backend"`
	dbConfig
	Nodes map[string]dbConfig `json:"nodes,omitempty"` // C38: узлы PostgreSQL ячейки (писатель и реплика)
}

func nodes(s shardConfig) router.Nodes {
	out := router.Nodes{}
	for name, d := range s.Nodes {
		out[name] = func(ctx context.Context) (*pgx.Conn, error) { return conn(ctx, d) }
	}
	return out
}

// watch — сторож писателей (C38.02): раз в 10 с ограждает узлы, принимающие запись не по каталогу.
func watch(ctx context.Context, cat router.Catalog, c fileConfig) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		for name, s := range c.Shards {
			if len(s.Nodes) < 2 {
				continue
			}
			fenced, _, e := router.CheckWriters(ctx, cat, name, nodes(s), "router:watchdog")
			for _, n := range fenced {
				fmt.Fprintf(os.Stderr, "surveyscan-router: shard %s: fenced unexpected writer %s\n", name, n)
			}
			if e != nil {
				fmt.Fprintf(os.Stderr, "surveyscan-router: shard %s: writer check failed\n", name)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

type fileConfig struct {
	Listen       string                 `json:"listen"`
	Secure       bool                   `json:"secure"`
	RouteKeyFile string                 `json:"route_key_file"`
	Catalog      dbConfig               `json:"catalog"`
	Shards       map[string]shardConfig `json:"shards"`
}

func load(path string) (fileConfig, error) {
	var c fileConfig
	b, e := os.ReadFile(path)
	if e != nil {
		return c, errors.New("cannot read router config")
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil {
		return c, fmt.Errorf("invalid router config: %v", e)
	}
	if c.Catalog.DatabaseURL == "" {
		return c, errors.New("catalog.database_url is required")
	}
	return c, nil
}

func private(path string, min int) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, errors.New("cannot read route key file")
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 4096 {
		return nil, errors.New("route key file must be a private regular file <=4096 bytes")
	}
	b, e := io.ReadAll(f)
	b = []byte(strings.TrimRight(string(b), "\r\n"))
	if e != nil || len(b) < min {
		return nil, fmt.Errorf("route key must be at least %d bytes", min)
	}
	return b, nil
}

func pool(ctx context.Context, d dbConfig) (*pgxpool.Pool, error) {
	cc, e := config.DatabaseFrom(d.DatabaseURL, d.PasswordFile)
	if e != nil {
		return nil, e
	}
	pc, e := pgxpool.ParseConfig("")
	if e != nil {
		return nil, e
	}
	pc.ConnConfig = cc
	pc.MaxConns = 8
	return pgxpool.NewWithConfig(ctx, pc)
}

func conn(ctx context.Context, d dbConfig) (*pgx.Conn, error) {
	cc, e := config.DatabaseFrom(d.DatabaseURL, d.PasswordFile)
	if e != nil {
		return nil, e
	}
	return pgx.ConnectConfig(ctx, cc)
}

func actor() string {
	if u := os.Getenv("USER"); u != "" {
		return "cli:" + u
	}
	return "cli"
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: surveyscan-router serve|init-catalog|add-shard|place|sync-logins|summary|move-tenant|set-writer|failover|check-writers -config FILE")
		os.Exit(2)
	}
	if e := run(os.Args[1], os.Args[2:]); e != nil {
		fmt.Fprintln(os.Stderr, "surveyscan-router:", e)
		os.Exit(1)
	}
}

func run(cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	cfgPath := fs.String("config", "", "router config (JSON)")
	id := fs.String("id", "", "shard id")
	region := fs.String("region", "", "shard region")
	tenant := fs.String("tenant", "", "tenant id")
	shard := fs.String("shard", "", "shard id")
	home := fs.String("home", "", "home region")
	dr := fs.String("dr", "", "DR region")
	residency := fs.String("residency", "", "data residency label")
	to := fs.String("to", "", "target shard")
	dry := fs.Bool("dry-run", false, "copy, verify and remove the copy without fencing")
	node := fs.String("node", "", "PostgreSQL node of the shard")
	unreachable := fs.Bool("old-unreachable", false, "operator confirms the old writer is powered off or isolated")
	catchUp := fs.Duration("catch-up", 30*time.Second, "max wait for the replica to replay the old writer's WAL")
	if e := fs.Parse(args); e != nil {
		return e
	}
	c, e := load(*cfgPath)
	if e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	p, e := pool(ctx, c.Catalog)
	if e != nil {
		return e
	}
	defer p.Close()
	cat := router.Catalog{Pool: p}
	out := json.NewEncoder(os.Stdout)
	switch cmd {
	case "init-catalog":
		return cat.Init(ctx)
	case "add-shard":
		if _, ok := c.Shards[*id]; !ok {
			return errors.New("shard is not in router config")
		}
		return cat.AddShard(ctx, *id, *region, actor())
	case "place":
		opt := func(s string) *string {
			if s == "" {
				return nil
			}
			return &s
		}
		return cat.Place(ctx, *tenant, *shard, *home, opt(*dr), opt(*residency), actor())
	case "sync-logins":
		var rows []router.LoginRow
		for name, s := range c.Shards {
			cn, e := conn(ctx, s.dbConfig)
			if e != nil {
				return fmt.Errorf("shard %s: %v", name, e)
			}
			r, e := cn.Query(ctx, "SELECT username,tenant_id::text FROM access.users")
			if e == nil {
				var got []router.LoginRow
				got, e = pgx.CollectRows(r, func(row pgx.CollectableRow) (router.LoginRow, error) {
					var l router.LoginRow
					return l, row.Scan(&l.Username, &l.Tenant)
				})
				rows = append(rows, got...)
			}
			cn.Close(ctx)
			if e != nil {
				return fmt.Errorf("shard %s: %v", name, e)
			}
		}
		n, conflicts, e := cat.SyncLogins(ctx, rows, actor())
		if e != nil {
			return e
		}
		return out.Encode(map[string]int{"logins": n, "conflicts": conflicts})
	case "set-writer":
		if _, ok := c.Shards[*shard].Nodes[*node]; !ok {
			return errors.New("node is not in router config")
		}
		return cat.SetWriter(ctx, *shard, *node, actor())
	case "failover":
		s, ok := c.Shards[*shard]
		if !ok {
			return errors.New("shard is not in router config")
		}
		rep, e := router.Failover(ctx, cat, *shard, nodes(s), *to, *unreachable, *catchUp, actor())
		_ = out.Encode(rep)
		return e
	case "check-writers":
		res := map[string]any{}
		for name, s := range c.Shards {
			if len(s.Nodes) < 2 {
				continue
			}
			fenced, down, e := router.CheckWriters(ctx, cat, name, nodes(s), actor())
			res[name] = map[string]any{"fenced": fenced, "unreachable": down, "ok": e == nil}
		}
		return out.Encode(res)
	case "summary":
		names := make([]string, 0, len(c.Shards))
		for name := range c.Shards {
			names = append(names, name)
		}
		sort.Strings(names)
		sum := router.Summarize(ctx, cat, names, func(ctx context.Context, name string) (*pgx.Conn, error) {
			return conn(ctx, c.Shards[name].dbConfig)
		}, 4, 10*time.Second)
		if e = out.Encode(sum); e == nil && !sum.Complete {
			e = errors.New("summary is partial: some shards are unavailable")
		}
		return e
	case "move-tenant":
		pl, e := cat.Placement(ctx, *tenant)
		if e != nil {
			return e
		}
		from, ok1 := c.Shards[pl.Shard]
		dst, ok2 := c.Shards[*to]
		if !ok1 || !ok2 {
			return errors.New("source or target shard is not in router config")
		}
		a, e := conn(ctx, from.dbConfig)
		if e != nil {
			return e
		}
		defer a.Close(context.WithoutCancel(ctx))
		b, e := conn(ctx, dst.dbConfig)
		if e != nil {
			return e
		}
		defer b.Close(context.WithoutCancel(ctx))
		rep, e := router.Move(ctx, cat, a, b, *tenant, pl.Shard, *to, *dry, actor())
		_ = out.Encode(rep)
		return e
	case "serve":
		key, e := private(c.RouteKeyFile, 32)
		if e != nil {
			return e
		}
		shards := map[string]*url.URL{}
		for name, s := range c.Shards {
			u, e := url.Parse(s.Backend)
			if e != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return fmt.Errorf("shard %s: invalid backend", name)
			}
			shards[name] = u
		}
		srv := &http.Server{Addr: c.Listen, Handler: &router.Router{Catalog: cat, Shards: shards, Key: key, Secure: c.Secure},
			ReadHeaderTimeout: 10 * time.Second}
		go func() {
			<-ctx.Done()
			sh, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = srv.Shutdown(sh)
		}()
		fmt.Fprintln(os.Stderr, "surveyscan-router listening on", c.Listen)
		if e = srv.ListenAndServe(); !errors.Is(e, http.ErrServerClosed) {
			return e
		}
		return nil
	}
	return errors.New("unknown command")
}
