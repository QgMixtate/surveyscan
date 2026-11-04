package messaging

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Diagnostics struct {
	Pending    int64    `json:"pending_events"`
	OldestAge  *float64 `json:"oldest_pending_age_seconds"`
	Retry      int64    `json:"retry_events"`
	DeadLetter int64    `json:"dead_letter_events"`
}

func Statistics(ctx context.Context, pool *pgxpool.Pool, tenant string) (Diagnostics, error) {
	var out Diagnostics
	e := pool.QueryRow(ctx, `SELECT count(*) FILTER(WHERE c.state IS NULL OR c.state IN ('claimed','retry')),extract(epoch FROM clock_timestamp()-min(e.occurred_at) FILTER(WHERE c.state IS NULL OR c.state IN ('claimed','retry')))::float8,count(*) FILTER(WHERE c.state='retry'),count(*) FILTER(WHERE c.state='dead_letter') FROM messaging.outbox_events e LEFT JOIN messaging.consumer_checkpoints c ON c.tenant_id=e.tenant_id AND c.event_id=e.event_id AND c.consumer_name='registry-version' WHERE e.tenant_id=$1`, tenant).Scan(&out.Pending, &out.OldestAge, &out.Retry, &out.DeadLetter)
	return out, e
}
