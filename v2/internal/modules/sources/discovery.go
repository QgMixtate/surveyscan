package sources

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// C51 (ADR decisions/D13-discovery-policy.md): обследования сети. Подсеть заводит администратор, запуск — оператор
// или расписание; collector подсети забирает задание и сдаёт результат. Пределы D-13 проверяются здесь, на сервере.

const (
	DiscoveryRate      = 50   // проб в секунду на collector
	DiscoveryTimeoutMS = 1000 // тайм-аут одной пробы
	DiscoveryMaxPrefix = 22   // подсеть не шире /22
	DiscoveryMinPeriod = 60   // расписание не чаще раза в час (минуты)
	discoveryStale     = 2 * time.Hour
)

// DiscoveryPorts — TCP-порты пробы (D-13).
var DiscoveryPorts = []int{22, 80, 135, 161, 443, 445, 3389, 5985, 5986}

type DiscoveryNetwork struct {
	ID        string        `json:"network_id"`
	Site      string        `json:"site_id"`
	Collector string        `json:"collector_id"`
	Name      string        `json:"name"`
	CIDR      string        `json:"cidr"`
	Probes    []string      `json:"probes"`
	Schedule  *int          `json:"schedule_minutes"`
	Active    bool          `json:"active"`
	Revision  string        `json:"revision"`
	LastRun   *DiscoveryRun `json:"last_run"`
	Present   int           `json:"present_hosts"`
	Missing   int           `json:"missing_hosts"`
}

type DiscoveryNetworkInput struct {
	Site      string   `json:"site_id"`
	Collector string   `json:"collector_id"`
	Name      string   `json:"name"`
	CIDR      string   `json:"cidr"`
	Probes    []string `json:"probes"`
	Schedule  *int     `json:"schedule_minutes"`
}

type DiscoveryNetworkPatch struct {
	Revision string    `json:"revision"`
	Name     *string   `json:"name,omitempty"`
	Probes   *[]string `json:"probes,omitempty"`
	Schedule *int      `json:"schedule_minutes,omitempty"` // 0 — снять расписание
	Active   *bool     `json:"active,omitempty"`
}

type DiscoveryRun struct {
	ID          string     `json:"run_id"`
	Network     string     `json:"network_id"`
	Trigger     string     `json:"trigger"`
	RequestedBy string     `json:"requested_by"`
	RequestedAt time.Time  `json:"requested_at"`
	State       string     `json:"state"`
	FinishedAt  *time.Time `json:"finished_at"`
	Addresses   *int       `json:"addresses"`
	Found       *int       `json:"found"`
	New         *int       `json:"new_hosts"`
	Missing     *int       `json:"missing"`
	Errors      []string   `json:"errors"`
}

type DiscoveryHost struct {
	IP        string    `json:"ip"`
	MAC       *string   `json:"mac"`
	Ports     []int     `json:"ports"`
	ICMP      bool      `json:"icmp"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	State     string    `json:"state"`
}

// DiscoveryJob — задание для collector.
type DiscoveryJob struct {
	Run       string   `json:"run_id"`
	Network   string   `json:"network_id"`
	CIDR      string   `json:"cidr"`
	Probes    []string `json:"probes"`
	Ports     []int    `json:"ports"`
	Rate      int      `json:"rate_per_second"`
	TimeoutMS int      `json:"timeout_ms"`
}

// FoundHost — узел из результата collector.
type FoundHost struct {
	IP    string  `json:"ip"`
	MAC   *string `json:"mac,omitempty"`
	Ports []int   `json:"ports"`
	ICMP  bool    `json:"icmp"`
}

func validProbes(p []string) bool {
	if len(p) < 1 || len(p) > 3 {
		return false
	}
	seen := map[string]bool{}
	for _, x := range p {
		if (x != "tcp" && x != "arp" && x != "icmp") || seen[x] {
			return false
		}
		seen[x] = true
	}
	return true
}

func validSchedule(s *int) bool { return s == nil || (*s >= DiscoveryMinPeriod && *s <= 10080) }

// parseNetwork — IPv4-подсеть не шире /22, адрес — адрес сети.
func parseNetwork(cidr string) (netip.Prefix, bool) {
	p, e := netip.ParsePrefix(strings.TrimSpace(cidr))
	if e != nil || !p.Addr().Is4() || p.Bits() < DiscoveryMaxPrefix || p.Masked() != p {
		return p, false
	}
	return p, true
}

func discoveryConflict(e error) error {
	var pg *pgconn.PgError
	if errors.As(e, &pg) && pg.Code == "23505" {
		return domain.Conflict
	}
	if errors.As(e, &pg) && (pg.Code == "23503" || pg.Code == "23514") {
		return domain.Invalid
	}
	return e
}

func (Store) CreateDiscoveryNetwork(ctx context.Context, tx pgx.Tx, tenant string, in DiscoveryNetworkInput) (DiscoveryNetwork, error) {
	p, ok := parseNetwork(in.CIDR)
	name := strings.TrimSpace(in.Name)
	if !ok || !validProbes(in.Probes) || !validSchedule(in.Schedule) || name == "" || len([]rune(name)) > 128 || !identifier.Valid(in.Site) || !identifier.Valid(in.Collector) {
		return DiscoveryNetwork{}, domain.Invalid
	}
	var site string
	e := tx.QueryRow(ctx, "SELECT site_id::text FROM sources.sources WHERE tenant_id=$1 AND source_id=$2 AND source_kind='collector' AND state='active'", tenant, in.Collector).Scan(&site)
	if errors.Is(e, pgx.ErrNoRows) || (e == nil && site != in.Site) {
		return DiscoveryNetwork{}, domain.Invalid // collector должен быть активным и на той же площадке
	}
	if e != nil {
		return DiscoveryNetwork{}, e
	}
	id := identifier.New()
	if _, e = tx.Exec(ctx, "INSERT INTO sources.discovery_networks(tenant_id,network_id,site_id,collector_id,name,cidr,probes,schedule_minutes) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
		tenant, id, in.Site, in.Collector, name, p.String(), in.Probes, in.Schedule); e != nil {
		return DiscoveryNetwork{}, discoveryConflict(e)
	}
	return (Store{}).DiscoveryNetwork(ctx, tx, tenant, id)
}

func (Store) PatchDiscoveryNetwork(ctx context.Context, tx pgx.Tx, tenant, id string, in DiscoveryNetworkPatch) (DiscoveryNetwork, error) {
	if !identifier.Valid(id) {
		return DiscoveryNetwork{}, domain.NotFound
	}
	if in.Probes != nil && !validProbes(*in.Probes) || in.Schedule != nil && *in.Schedule != 0 && !validSchedule(in.Schedule) {
		return DiscoveryNetwork{}, domain.Invalid
	}
	var name *string
	if in.Name != nil {
		n := strings.TrimSpace(*in.Name)
		if n == "" || len([]rune(n)) > 128 {
			return DiscoveryNetwork{}, domain.Invalid
		}
		name = &n
	}
	var probes []string
	if in.Probes != nil {
		probes = *in.Probes
	}
	tag, e := tx.Exec(ctx, `UPDATE sources.discovery_networks SET name=COALESCE($4,name),probes=COALESCE($5,probes),
schedule_minutes=CASE WHEN $6::int IS NULL THEN schedule_minutes WHEN $6=0 THEN NULL ELSE $6 END,active=COALESCE($7,active),revision=revision+1
WHERE tenant_id=$1 AND network_id=$2 AND revision::text=$3`, tenant, id, in.Revision, name, probes, in.Schedule, in.Active)
	if e != nil {
		return DiscoveryNetwork{}, discoveryConflict(e)
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM sources.discovery_networks WHERE tenant_id=$1 AND network_id=$2)", tenant, id).Scan(&exists); e != nil {
			return DiscoveryNetwork{}, e
		}
		if exists {
			return DiscoveryNetwork{}, domain.Revision
		}
		return DiscoveryNetwork{}, domain.NotFound
	}
	return (Store{}).DiscoveryNetwork(ctx, tx, tenant, id)
}

func scanNetwork(row pgx.Row) (DiscoveryNetwork, error) {
	var n DiscoveryNetwork
	e := row.Scan(&n.ID, &n.Site, &n.Collector, &n.Name, &n.CIDR, &n.Probes, &n.Schedule, &n.Active, &n.Revision, &n.Present, &n.Missing)
	return n, e
}

func (s Store) DiscoveryNetwork(ctx context.Context, tx pgx.Tx, tenant, id string) (DiscoveryNetwork, error) {
	if !identifier.Valid(id) {
		return DiscoveryNetwork{}, domain.NotFound
	}
	n, e := scanNetwork(tx.QueryRow(ctx, `SELECT n.network_id::text,n.site_id::text,n.collector_id::text,n.name,n.cidr::text,n.probes,n.schedule_minutes,n.active,n.revision::text,
(SELECT count(*) FROM sources.discovery_hosts h WHERE h.tenant_id=n.tenant_id AND h.network_id=n.network_id AND h.state='present')::int,
(SELECT count(*) FROM sources.discovery_hosts h WHERE h.tenant_id=n.tenant_id AND h.network_id=n.network_id AND h.state='missing')::int
FROM sources.discovery_networks n WHERE n.tenant_id=$1 AND n.network_id=$2`, tenant, id))
	if errors.Is(e, pgx.ErrNoRows) {
		return n, domain.NotFound
	}
	if e != nil {
		return n, e
	}
	runs, e := s.DiscoveryRuns(ctx, tx, tenant, id, 1)
	if e == nil && len(runs) == 1 {
		n.LastRun = &runs[0]
	}
	return n, e
}

func (s Store) DiscoveryNetworks(ctx context.Context, tx pgx.Tx, tenant string) ([]DiscoveryNetwork, error) {
	rows, e := tx.Query(ctx, `SELECT n.network_id::text,n.site_id::text,n.collector_id::text,n.name,n.cidr::text,n.probes,n.schedule_minutes,n.active,n.revision::text,
(SELECT count(*) FROM sources.discovery_hosts h WHERE h.tenant_id=n.tenant_id AND h.network_id=n.network_id AND h.state='present')::int,
(SELECT count(*) FROM sources.discovery_hosts h WHERE h.tenant_id=n.tenant_id AND h.network_id=n.network_id AND h.state='missing')::int
FROM sources.discovery_networks n WHERE n.tenant_id=$1 ORDER BY n.name, n.network_id`, tenant)
	if e != nil {
		return nil, e
	}
	out := []DiscoveryNetwork{}
	for rows.Next() {
		n, e := scanNetwork(rows)
		if e != nil {
			rows.Close()
			return nil, e
		}
		out = append(out, n)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return nil, e
	}
	for i := range out {
		runs, e := s.DiscoveryRuns(ctx, tx, tenant, out[i].ID, 1)
		if e != nil {
			return nil, e
		}
		if len(runs) == 1 {
			out[i].LastRun = &runs[0]
		}
	}
	return out, nil
}

func (Store) DiscoveryRuns(ctx context.Context, tx pgx.Tx, tenant, network string, limit int) ([]DiscoveryRun, error) {
	rows, e := tx.Query(ctx, `SELECT run_id::text,network_id::text,trigger,requested_by,requested_at,state,finished_at,addresses,found,new_hosts,missing,errors
FROM sources.discovery_runs WHERE tenant_id=$1 AND network_id=$2 ORDER BY requested_at DESC, run_id LIMIT $3`, tenant, network, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []DiscoveryRun{}
	for rows.Next() {
		var r DiscoveryRun
		if e = rows.Scan(&r.ID, &r.Network, &r.Trigger, &r.RequestedBy, &r.RequestedAt, &r.State, &r.FinishedAt, &r.Addresses, &r.Found, &r.New, &r.Missing, &r.Errors); e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (Store) DiscoveryHosts(ctx context.Context, tx pgx.Tx, tenant, network string) ([]DiscoveryHost, error) {
	rows, e := tx.Query(ctx, `SELECT host(ip),mac,ports,icmp,first_seen,last_seen,state FROM sources.discovery_hosts WHERE tenant_id=$1 AND network_id=$2 ORDER BY ip`, tenant, network)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []DiscoveryHost{}
	for rows.Next() {
		var h DiscoveryHost
		if e = rows.Scan(&h.IP, &h.MAC, &h.Ports, &h.ICMP, &h.FirstSeen, &h.LastSeen, &h.State); e != nil {
			return nil, e
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// StartDiscovery ставит обследование в очередь; одно незавершённое на подсеть (иначе Conflict).
func (Store) StartDiscovery(ctx context.Context, tx pgx.Tx, tenant, network, trigger, actor string) (string, error) {
	var active bool
	e := tx.QueryRow(ctx, "SELECT active FROM sources.discovery_networks WHERE tenant_id=$1 AND network_id=$2 FOR UPDATE", tenant, network).Scan(&active)
	if errors.Is(e, pgx.ErrNoRows) {
		return "", domain.NotFound
	}
	if e != nil {
		return "", e
	}
	if !active {
		return "", domain.Invalid
	}
	id := identifier.New()
	if _, e = tx.Exec(ctx, "INSERT INTO sources.discovery_runs(tenant_id,run_id,network_id,trigger,requested_by) VALUES($1,$2,$3,$4,$5)", tenant, id, network, trigger, actor); e != nil {
		return "", discoveryConflict(e)
	}
	return id, nil
}

// DiscoveryDue ставит в очередь обследования по расписанию (подсети, у которых последнее обследование старше периода)
// и закрывает зависшие (running дольше 2 ч) как failed. Возвращает число поставленных.
func (Store) DiscoveryDue(ctx context.Context, tx pgx.Tx, tenant string) (int, error) {
	if _, e := tx.Exec(ctx, `UPDATE sources.discovery_runs SET state='failed',finished_at=now(),errors=array_append(errors,'collector:timeout')
WHERE tenant_id=$1 AND state='running' AND claimed_at < now()-$2::interval`, tenant, discoveryStale.String()); e != nil {
		return 0, e
	}
	tag, e := tx.Exec(ctx, `INSERT INTO sources.discovery_runs(tenant_id,run_id,network_id,trigger,requested_by)
SELECT n.tenant_id,gen_random_uuid(),n.network_id,'schedule','schedule' FROM sources.discovery_networks n
WHERE n.tenant_id=$1 AND n.active AND n.schedule_minutes IS NOT NULL
AND NOT EXISTS(SELECT 1 FROM sources.discovery_runs r WHERE r.tenant_id=n.tenant_id AND r.network_id=n.network_id AND (r.state IN ('queued','running') OR r.requested_at > now()-make_interval(mins => n.schedule_minutes)))
ON CONFLICT DO NOTHING`, tenant)
	if e != nil {
		return 0, e
	}
	return int(tag.RowsAffected()), nil
}

// ClaimDiscovery выдаёт collector самое старое ожидающее обследование его подсетей (или ничего).
func (Store) ClaimDiscovery(ctx context.Context, tx pgx.Tx, tenant, collector string) (*DiscoveryJob, error) {
	var j DiscoveryJob
	e := tx.QueryRow(ctx, `UPDATE sources.discovery_runs r SET state='running',claimed_at=now()
FROM sources.discovery_networks n WHERE r.tenant_id=$1 AND n.tenant_id=r.tenant_id AND n.network_id=r.network_id AND n.collector_id=$2 AND n.active
AND r.run_id=(SELECT r2.run_id FROM sources.discovery_runs r2 JOIN sources.discovery_networks n2 USING(tenant_id,network_id)
  WHERE r2.tenant_id=$1 AND n2.collector_id=$2 AND n2.active AND r2.state='queued' ORDER BY r2.requested_at, r2.run_id LIMIT 1 FOR UPDATE OF r2 SKIP LOCKED)
RETURNING r.run_id::text,n.network_id::text,n.cidr::text,n.probes`, tenant, collector).Scan(&j.Run, &j.Network, &j.CIDR, &j.Probes)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	j.Ports, j.Rate, j.TimeoutMS = slices.Clone(DiscoveryPorts), DiscoveryRate, DiscoveryTimeoutMS
	return &j, nil
}

// DiscoveryOutcome — итог приёма результата.
type DiscoveryOutcome struct {
	Run     string `json:"run_id"`
	Found   int    `json:"found"`
	New     int    `json:"new_hosts"`
	Missing int    `json:"missing"`
	Dropped int    `json:"dropped_out_of_scope"`
}

// CompleteDiscovery принимает результат обследования от collector этой подсети. Узлы вне подсети отбрасываются (scope
// не расширяется). Present → missing для узлов, не найденных этим обследованием; найденный снова — present.
// Повтор того же результата для завершённого обследования — без изменений (идемпотентно).
func (Store) CompleteDiscovery(ctx context.Context, tx pgx.Tx, tenant, collector, run string, addresses int, hosts []FoundHost, errs []string) (DiscoveryOutcome, error) {
	out := DiscoveryOutcome{Run: run}
	if !identifier.Valid(run) || addresses < 0 || len(hosts) > 1024 || len(errs) > 32 {
		return out, domain.Invalid
	}
	var network, cidr, state string
	var found, newHosts, missing *int
	e := tx.QueryRow(ctx, `SELECT r.network_id::text,n.cidr::text,r.state,r.found,r.new_hosts,r.missing FROM sources.discovery_runs r JOIN sources.discovery_networks n USING(tenant_id,network_id)
WHERE r.tenant_id=$1 AND r.run_id=$2 AND n.collector_id=$3 FOR UPDATE OF r`, tenant, run, collector).Scan(&network, &cidr, &state, &found, &newHosts, &missing)
	if errors.Is(e, pgx.ErrNoRows) {
		return out, domain.NotFound
	}
	if e != nil {
		return out, e
	}
	if state == "done" || state == "failed" {
		if found != nil {
			out.Found, out.New, out.Missing = *found, *newHosts, *missing
		}
		return out, nil
	}
	if state != "running" {
		return out, domain.Conflict
	}
	prefix, _ := netip.ParsePrefix(cidr)
	clean := map[string]FoundHost{}
	for _, h := range hosts {
		a, e := netip.ParseAddr(h.IP)
		if e != nil || !a.Is4() || !prefix.Contains(a) {
			out.Dropped++
			continue
		}
		if h.MAC != nil {
			m := strings.ToLower(*h.MAC)
			if len(m) != 17 {
				h.MAC = nil
			} else {
				h.MAC = &m
			}
		}
		ports := []int{}
		for _, p := range h.Ports {
			if slices.Contains(DiscoveryPorts, p) && !slices.Contains(ports, p) {
				ports = append(ports, p)
			}
		}
		sort.Ints(ports)
		h.Ports = ports
		clean[a.String()] = h
	}
	cleanErrs := []string{}
	for _, x := range errs {
		if len(x) > 0 && len(x) <= 64 {
			cleanErrs = append(cleanErrs, x)
		}
	}
	var now time.Time
	if e = tx.QueryRow(ctx, "SELECT now()").Scan(&now); e != nil {
		return out, e
	}
	for ip, h := range clean {
		var inserted bool
		if e = tx.QueryRow(ctx, `INSERT INTO sources.discovery_hosts(tenant_id,network_id,ip,mac,ports,icmp,first_seen,last_seen,last_run_id,state) VALUES($1,$2,$3,$4,$5,$6,$7,$7,$8,'present')
ON CONFLICT (tenant_id,network_id,ip) DO UPDATE SET mac=COALESCE(excluded.mac,sources.discovery_hosts.mac),ports=excluded.ports,icmp=excluded.icmp,last_seen=excluded.last_seen,last_run_id=excluded.last_run_id,state='present'
RETURNING (xmax=0)`, tenant, network, ip, h.MAC, h.Ports, h.ICMP, now, run).Scan(&inserted); e != nil {
			return out, discoveryConflict(e)
		}
		if inserted {
			out.New++
		}
	}
	out.Found = len(clean)
	final := "done"
	if len(clean) == 0 && len(cleanErrs) > 0 {
		final = "failed" // ничего не найдено и есть ошибки — не отмечаем все узлы пропавшими молча
	} else {
		tag, e := tx.Exec(ctx, "UPDATE sources.discovery_hosts SET state='missing' WHERE tenant_id=$1 AND network_id=$2 AND state='present' AND last_run_id<>$3", tenant, network, run)
		if e != nil {
			return out, e
		}
		out.Missing = int(tag.RowsAffected())
	}
	_, e = tx.Exec(ctx, `UPDATE sources.discovery_runs SET state=$3,finished_at=now(),addresses=$4,found=$5,new_hosts=$6,missing=$7,errors=$8 WHERE tenant_id=$1 AND run_id=$2`,
		tenant, run, final, addresses, out.Found, out.New, out.Missing, cleanErrs)
	return out, e
}

// DiscoveryTenants — организации с заведёнными подсетями (для фоновой работы расписания).
func (Store) DiscoveryTenants(ctx context.Context, tx pgx.Tx) ([]string, error) {
	rows, e := tx.Query(ctx, "SELECT DISTINCT tenant_id::text FROM sources.discovery_networks")
	if e != nil {
		return nil, e
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}
