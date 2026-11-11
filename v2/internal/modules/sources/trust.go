package sources

import (
	"context"
	"errors"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources/port"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/jackc/pgx/v5"
)

type Store struct{}

// Trust проверяет привязку ключа и возвращает приоритет данных источника. R-027 (решение 3А): к настроенному
// приоритету привязки добавляется надбавка по способу сбора — агент на хосте (+2) > удалённый сбор SSH/WinRM (+1) >
// portable/collector (+0); при равных доверенных часах данные более приоритетного источника не перезаписываются.
func (Store) Trust(ctx context.Context, tx pgx.Tx, o contracts.Observation, key string) (port.Trust, error) {
	var t port.Trust
	e := tx.QueryRow(ctx, `SELECT b.public_key,b.priority+CASE WHEN s.source_kind='agent' THEN CASE COALESCE((SELECT g.acquisition FROM sources.agents g WHERE g.tenant_id=s.tenant_id AND g.source_id=s.source_id LIMIT 1),'agent') WHEN 'agent' THEN 2 ELSE 1 END ELSE 0 END FROM sources.ingest_bindings b JOIN sources.sources s ON s.tenant_id=b.tenant_id AND s.source_id=b.source_id JOIN scope.network_scopes n ON n.tenant_id=b.tenant_id AND n.scope_id=b.scope_id JOIN access.tenants a ON a.tenant_id=s.tenant_id WHERE b.tenant_id=$1 AND b.source_id=$2 AND b.generation_id=$3 AND b.key_id=$4 AND b.namespace=$5 AND b.scope_id=$6 AND n.site_id=$7 AND s.site_id=$7 AND s.source_kind=$8 AND s.generation_id=b.generation_id AND s.state='active' AND b.active AND a.status='active' FOR SHARE OF b,s,n,a`, o.TenantID, o.Origin.SourceID, o.Origin.GenerationID, key, o.Record.Namespace, o.Scope.ScopeID, o.Scope.SiteID, o.Origin.SourceKind).Scan(&t.PublicKey, &t.Priority)
	if errors.Is(e, pgx.ErrNoRows) {
		e = domain.Unauthorized
	}
	return t, e
}
