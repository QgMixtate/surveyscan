package sources

import (
	"context"
	"errors"
	"net/netip"
	"regexp"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
)

// C51.03: цели удалённого сбора, создаваемые из Web. Для каждой цели центр по запросу collector (mTLS) выдаёт grant
// на отдельный источник-агент; collector регистрирует его обычным путём агента и собирает данные узла от его имени.

var hostKeyRe = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

type RemoteTarget struct {
	ID            string     `json:"target_id"`
	Collector     string     `json:"collector_id"`
	Network       *string    `json:"network_id"`
	Address       string     `json:"address"`
	Kind          string     `json:"kind"`
	Port          int        `json:"port"`
	Credential    string     `json:"credential_id"`
	HostKey       *string    `json:"host_key_sha256"`
	ServerName    *string    `json:"tls_server_name"`
	Interval      int        `json:"interval_seconds"`
	Source        *string    `json:"agent_source_id"`
	State         string     `json:"state"`
	LastCollected *time.Time `json:"last_collected_at"`
	LastError     *string    `json:"last_error"`
	Revision      string     `json:"revision"`
}

type RemoteTargetInput struct {
	Collector  string  `json:"collector_id"`
	Network    *string `json:"network_id,omitempty"`
	Address    string  `json:"address"`
	Kind       string  `json:"kind"`
	Port       int     `json:"port,omitempty"`
	Credential string  `json:"credential_id"`
	HostKey    *string `json:"host_key_sha256,omitempty"`
	CAPEM      *string `json:"tls_ca_pem,omitempty"`
	ServerName *string `json:"tls_server_name,omitempty"`
	Interval   int     `json:"interval_seconds,omitempty"`
}

// MachineTarget — цель глазами collector (без секрета учётки).
type MachineTarget struct {
	ID         string  `json:"target_id"`
	Kind       string  `json:"kind"`
	Address    string  `json:"address"`
	Port       int     `json:"port"`
	Username   string  `json:"username"`
	HostKey    *string `json:"host_key_sha256"`
	CAPEM      *string `json:"tls_ca_pem"`
	ServerName *string `json:"tls_server_name"`
	Interval   int     `json:"interval_seconds"`
	Source     *string `json:"agent_source_id"`
	State      string  `json:"state"`
	Site       string  `json:"site_id"`
	Scope      string  `json:"network_scope_id"`
	Tenant     string  `json:"tenant_id"`
}

func (Store) CreateTarget(ctx context.Context, tx pgx.Tx, tenant string, in RemoteTargetInput) (RemoteTarget, error) {
	addr, e := netip.ParseAddr(in.Address)
	if e != nil || !addr.Is4() || !identifier.Valid(in.Collector) || !identifier.Valid(in.Credential) || (in.Kind != "ssh" && in.Kind != "winrm") {
		return RemoteTarget{}, domain.Invalid // SNMP-цели (сетевые устройства) — отдельным шагом
	}
	if in.Port == 0 {
		in.Port = map[string]int{"ssh": 22, "winrm": 5986}[in.Kind]
	}
	if in.Interval == 0 {
		in.Interval = 3600
	}
	if in.Port < 1 || in.Port > 65535 || in.Interval < 300 || in.Interval > 86400 {
		return RemoteTarget{}, domain.Invalid
	}
	switch in.Kind {
	case "ssh":
		if in.HostKey == nil || !hostKeyRe.MatchString(*in.HostKey) || in.CAPEM != nil || in.ServerName != nil {
			return RemoteTarget{}, domain.Invalid // отпечаток ключа хоста обязателен: без TOFU
		}
	case "winrm":
		if in.HostKey != nil || in.CAPEM == nil || in.ServerName == nil || len(*in.CAPEM) > 16384 || len(*in.ServerName) == 0 || len(*in.ServerName) > 253 {
			return RemoteTarget{}, domain.Invalid
		}
		if _, err := contractsCA(*in.CAPEM); err != nil {
			return RemoteTarget{}, domain.Invalid
		}
	}
	var active bool
	e = tx.QueryRow(ctx, "SELECT active FROM sources.collect_credentials WHERE tenant_id=$1 AND credential_id=$2 AND kind=$3", tenant, in.Credential, in.Kind).Scan(&active)
	if errors.Is(e, pgx.ErrNoRows) || (e == nil && !active) {
		return RemoteTarget{}, domain.Invalid
	}
	if e != nil {
		return RemoteTarget{}, e
	}
	if in.Network != nil {
		var cidr string
		if e = tx.QueryRow(ctx, "SELECT cidr::text FROM sources.discovery_networks WHERE tenant_id=$1 AND network_id=$2 AND collector_id=$3", tenant, *in.Network, in.Collector).Scan(&cidr); e != nil {
			return RemoteTarget{}, domain.Invalid
		}
		if p, err := netip.ParsePrefix(cidr); err != nil || !p.Contains(addr) {
			return RemoteTarget{}, domain.Invalid
		}
	}
	var ok bool
	if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM sources.sources WHERE tenant_id=$1 AND source_id=$2 AND source_kind='collector' AND state='active')", tenant, in.Collector).Scan(&ok); e != nil {
		return RemoteTarget{}, e
	}
	if !ok {
		return RemoteTarget{}, domain.Invalid
	}
	id := identifier.New()
	if _, e = tx.Exec(ctx, `INSERT INTO sources.remote_targets(tenant_id,target_id,collector_id,network_id,address,kind,port,credential_id,host_key_sha256,tls_ca_pem,tls_server_name,interval_seconds)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, tenant, id, in.Collector, in.Network, addr.String(), in.Kind, in.Port, in.Credential, in.HostKey, in.CAPEM, in.ServerName, in.Interval); e != nil {
		return RemoteTarget{}, discoveryConflict(e)
	}
	return (Store{}).Target(ctx, tx, tenant, id)
}

func (Store) Target(ctx context.Context, tx pgx.Tx, tenant, id string) (RemoteTarget, error) {
	var t RemoteTarget
	if !identifier.Valid(id) {
		return t, domain.NotFound
	}
	e := tx.QueryRow(ctx, `SELECT target_id::text,collector_id::text,network_id::text,host(address),kind,port,credential_id::text,host_key_sha256,tls_server_name,interval_seconds,agent_source_id::text,state,last_collected_at,last_error,revision::text
FROM sources.remote_targets WHERE tenant_id=$1 AND target_id=$2`, tenant, id).Scan(&t.ID, &t.Collector, &t.Network, &t.Address, &t.Kind, &t.Port, &t.Credential, &t.HostKey, &t.ServerName, &t.Interval, &t.Source, &t.State, &t.LastCollected, &t.LastError, &t.Revision)
	if errors.Is(e, pgx.ErrNoRows) {
		return t, domain.NotFound
	}
	return t, e
}

func (Store) Targets(ctx context.Context, tx pgx.Tx, tenant string) ([]RemoteTarget, error) {
	rows, e := tx.Query(ctx, `SELECT target_id::text,collector_id::text,network_id::text,host(address),kind,port,credential_id::text,host_key_sha256,tls_server_name,interval_seconds,agent_source_id::text,state,last_collected_at,last_error,revision::text
FROM sources.remote_targets WHERE tenant_id=$1 ORDER BY address, kind`, tenant)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []RemoteTarget{}
	for rows.Next() {
		var t RemoteTarget
		if e = rows.Scan(&t.ID, &t.Collector, &t.Network, &t.Address, &t.Kind, &t.Port, &t.Credential, &t.HostKey, &t.ServerName, &t.Interval, &t.Source, &t.State, &t.LastCollected, &t.LastError, &t.Revision); e != nil {
			return nil, e
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// SetTargetState — включить/отключить цель (администратор).
func (Store) SetTargetState(ctx context.Context, tx pgx.Tx, tenant, id, revision string, disabled bool) (RemoteTarget, error) {
	tag, e := tx.Exec(ctx, `UPDATE sources.remote_targets SET state=CASE WHEN $4 THEN 'disabled' WHEN agent_source_id IS NULL THEN 'pending' ELSE 'active' END,revision=revision+1
WHERE tenant_id=$1 AND target_id=$2 AND revision::text=$3`, tenant, id, revision, disabled)
	if e != nil {
		return RemoteTarget{}, discoveryConflict(e)
	}
	if tag.RowsAffected() == 0 {
		if _, e = (Store{}).Target(ctx, tx, tenant, id); e != nil {
			return RemoteTarget{}, e
		}
		return RemoteTarget{}, domain.Revision
	}
	return (Store{}).Target(ctx, tx, tenant, id)
}

func (Store) collectorTargets(ctx context.Context, tx pgx.Tx, tenant, collector string) ([]MachineTarget, error) {
	rows, e := tx.Query(ctx, `SELECT t.target_id::text,t.kind,host(t.address),t.port,c.username,t.host_key_sha256,t.tls_ca_pem,t.tls_server_name,t.interval_seconds,t.agent_source_id::text,t.state,s.site_id::text,
(SELECT n.scope_id::text FROM scope.network_scopes n WHERE n.tenant_id=s.tenant_id AND n.site_id=s.site_id ORDER BY n.scope_id LIMIT 1),t.tenant_id::text
FROM sources.remote_targets t JOIN sources.collect_credentials c ON c.tenant_id=t.tenant_id AND c.credential_id=t.credential_id JOIN sources.sources s ON s.tenant_id=t.tenant_id AND s.source_id=t.collector_id
WHERE t.tenant_id=$1 AND t.collector_id=$2 AND t.state<>'disabled' AND c.active ORDER BY t.target_id`, tenant, collector)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []MachineTarget{}
	for rows.Next() {
		var t MachineTarget
		if e = rows.Scan(&t.ID, &t.Kind, &t.Address, &t.Port, &t.Username, &t.HostKey, &t.CAPEM, &t.ServerName, &t.Interval, &t.Source, &t.State, &t.Site, &t.Scope, &t.Tenant); e != nil {
			return nil, e
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// CollectTargets — цели этого collector (mTLS).
func (s *MachineService) CollectTargets(ctx context.Context, fp string) ([]MachineTarget, error) {
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx)
	actor, e := s.collectorActor(ctx, tx, fp)
	if e != nil {
		return nil, e
	}
	return Store{}.collectorTargets(ctx, tx, actor.Tenant, actor.Source)
}

// TargetGrantRequest — подготовленная collector личность агента цели (как у `surveyscan-agent prepare`).
type TargetGrantRequest struct {
	Source  string `json:"source_id"`
	CSRHash string `json:"csr_sha256"`
	Public  string `json:"signing_public_key"`
}

// TargetGrant выдаёт collector grant на источник-агент его цели (один раз; повтор — Conflict). Регистрация далее —
// обычным путём агента через этот collector.
func (s *MachineService) TargetGrant(ctx context.Context, fp, target string, req TargetGrantRequest) (contracts.EnrollmentGrant, error) {
	if !identifier.Valid(target) || !identifier.Valid(req.Source) {
		return contracts.EnrollmentGrant{}, domain.Invalid
	}
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return contracts.EnrollmentGrant{}, e
	}
	defer tx.Rollback(ctx)
	actor, e := s.collectorActor(ctx, tx, fp)
	if e != nil {
		return contracts.EnrollmentGrant{}, e
	}
	var kind string
	var bound *string
	e = tx.QueryRow(ctx, "SELECT kind,agent_source_id::text FROM sources.remote_targets WHERE tenant_id=$1 AND target_id=$2 AND collector_id=$3 AND state='pending' FOR UPDATE", actor.Tenant, target, actor.Source).Scan(&kind, &bound)
	if errors.Is(e, pgx.ErrNoRows) {
		return contracts.EnrollmentGrant{}, domain.NotFound
	}
	if e != nil {
		return contracts.EnrollmentGrant{}, e
	}
	if bound != nil && *bound != req.Source {
		return contracts.EnrollmentGrant{}, domain.Conflict
	}
	var collectorID string
	if e = tx.QueryRow(ctx, "SELECT collector_id::text FROM sources.collectors WHERE tenant_id=$1 AND source_id=$2", actor.Tenant, actor.Source).Scan(&collectorID); e != nil {
		return contracts.EnrollmentGrant{}, domain.Unauthorized
	}
	if bound != nil { // прежний grant не завершён (сбой collector) — старый ожидающий источник освобождается
		if _, e = tx.Exec(ctx, "DELETE FROM sources.enrollment_grants WHERE tenant_id=$1 AND source_id=$2", actor.Tenant, *bound); e != nil {
			return contracts.EnrollmentGrant{}, e
		}
		return contracts.EnrollmentGrant{}, domain.Conflict
	}
	platform := map[string]string{"ssh": contracts.InventoryPlatformLinux12, "winrm": contracts.InventoryPlatform12}[kind]
	grant, e := s.grantTx(ctx, tx, contracts.EnrollmentGrantRequest{TenantID: actor.Tenant, SourceID: req.Source, Kind: "agent", SiteID: actor.Site, TTL: 900, CSRHash: req.CSRHash, PublicKey: req.Public, CollectorID: &collectorID, InventoryPlatform: platform, Acquisition: kind}, platform, kind, "collector:"+actor.Source)
	if e != nil {
		return grant, e
	}
	if _, e = tx.Exec(ctx, "UPDATE sources.remote_targets SET agent_source_id=$3,revision=revision+1 WHERE tenant_id=$1 AND target_id=$2", actor.Tenant, target, req.Source); e != nil {
		return grant, e
	}
	return grant, tx.Commit(ctx)
}

// TargetReport — итог сбора цели от collector: активна (зарегистрирована) и время/ошибка последнего сбора.
func (s *MachineService) TargetReport(ctx context.Context, fp, target string, ok bool, problem string) error {
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	actor, e := s.collectorActor(ctx, tx, fp)
	if e != nil {
		return e
	}
	if len(problem) > 128 {
		problem = problem[:128]
	}
	tag, e := tx.Exec(ctx, `UPDATE sources.remote_targets SET state=CASE WHEN state='pending' AND agent_source_id IS NOT NULL AND EXISTS(SELECT 1 FROM sources.sources s WHERE s.tenant_id=$1 AND s.source_id=agent_source_id AND s.state='active') THEN 'active' ELSE state END,
last_collected_at=CASE WHEN $4 THEN now() ELSE last_collected_at END,last_error=NULLIF($5,'') WHERE tenant_id=$1 AND target_id=$2 AND collector_id=$3 AND state<>'disabled'`, actor.Tenant, target, actor.Source, ok, problem)
	if e != nil {
		return e
	}
	if tag.RowsAffected() == 0 {
		return domain.NotFound
	}
	return tx.Commit(ctx)
}

// TargetForSecret — проверка, что цель принадлежит collector и активна; возвращает тип, логин и учётку.
func (s *MachineService) TargetForSecret(ctx context.Context, fp, target string) (tenant, source, kind, username, credential string, err error) {
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return "", "", "", "", "", e
	}
	defer tx.Rollback(ctx)
	actor, e := s.collectorActor(ctx, tx, fp)
	if e != nil {
		return "", "", "", "", "", e
	}
	e = tx.QueryRow(ctx, `SELECT t.kind,c.username,c.credential_id::text FROM sources.remote_targets t JOIN sources.collect_credentials c ON c.tenant_id=t.tenant_id AND c.credential_id=t.credential_id
WHERE t.tenant_id=$1 AND t.target_id=$2 AND t.collector_id=$3 AND t.state<>'disabled' AND c.active`, actor.Tenant, target, actor.Source).Scan(&kind, &username, &credential)
	if errors.Is(e, pgx.ErrNoRows) {
		return "", "", "", "", "", domain.NotFound
	}
	return actor.Tenant, actor.Source, kind, username, credential, e
}

func contractsCA(pemText string) (int, error) {
	n := 0
	rest := []byte(pemText)
	for {
		var b *pemBlock
		b, rest = decodePEM(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return 0, errors.New("not a certificate")
		}
		if _, err := parseCert(b.Bytes); err != nil {
			return 0, err
		}
		n++
	}
	if n == 0 {
		return 0, errors.New("no certificate")
	}
	return n, nil
}
