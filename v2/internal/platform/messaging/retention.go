package messaging

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// C36.03: очистка служебных журналов пачками (без длинных транзакций). События outbox удаляются, только если их
// применили все нужные потребители и на них не ссылается незавершённая доставка уведомления.

type RetentionResult struct {
	Events, Checkpoints, Deliveries, Leases int64
}

// PruneOutbox удаляет до batch событий тенантов старше age, применённых потребителем версий, индексом поиска
// (если search) и раздачей уведомлений (если у тенанта есть подписки).
func PruneOutbox(ctx context.Context, pool *pgxpool.Pool, age time.Duration, search bool, batch int) (RetentionResult, error) {
	var out RetentionResult
	tx, e := pool.Begin(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	rows, e := tx.Query(ctx, `SELECT e.tenant_id,e.event_id FROM messaging.outbox_events e
WHERE e.occurred_at < clock_timestamp() - $1*interval '1 second'
AND EXISTS(SELECT 1 FROM messaging.consumer_checkpoints c WHERE c.tenant_id=e.tenant_id AND c.event_id=e.event_id AND c.consumer_name='registry-version' AND c.state='applied')
AND (NOT $2 OR EXISTS(SELECT 1 FROM messaging.consumer_checkpoints c WHERE c.tenant_id=e.tenant_id AND c.event_id=e.event_id AND c.consumer_name='search-index' AND c.state='applied'))
AND (NOT EXISTS(SELECT 1 FROM messaging.webhook_subscriptions s WHERE s.tenant_id=e.tenant_id)
     OR EXISTS(SELECT 1 FROM messaging.consumer_checkpoints c WHERE c.tenant_id=e.tenant_id AND c.event_id=e.event_id AND c.consumer_name='webhook-fanout' AND c.state='applied'))
AND NOT EXISTS(SELECT 1 FROM messaging.webhook_deliveries d WHERE d.tenant_id=e.tenant_id AND d.event_id=e.event_id AND d.state='pending')
ORDER BY e.occurred_at LIMIT $3 FOR UPDATE OF e SKIP LOCKED`, age.Seconds(), search, batch)
	if e != nil {
		return out, e
	}
	var tenants, events []string
	for rows.Next() {
		var t, id string
		if e = rows.Scan(&t, &id); e != nil {
			rows.Close()
			return out, e
		}
		tenants, events = append(tenants, t), append(events, id)
	}
	rows.Close()
	if e = rows.Err(); e != nil || len(events) == 0 {
		return out, e
	}
	// только эта транзакция может удалять события (триггер неизменяемости, миграция 0046)
	if _, e = tx.Exec(ctx, "SELECT set_config('surveyscan.retention','outbox',true)"); e != nil {
		return out, e
	}
	const pairs = "SELECT * FROM unnest($1::uuid[],$2::uuid[]) AS p(tenant_id,event_id)"
	tag, e := tx.Exec(ctx, "DELETE FROM messaging.webhook_deliveries d USING ("+pairs+") p WHERE d.tenant_id=p.tenant_id AND d.event_id=p.event_id", tenants, events)
	if e != nil {
		return out, e
	}
	out.Deliveries = tag.RowsAffected()
	if tag, e = tx.Exec(ctx, "DELETE FROM messaging.consumer_checkpoints c USING ("+pairs+") p WHERE c.tenant_id=p.tenant_id AND c.event_id=p.event_id", tenants, events); e != nil {
		return out, e
	}
	out.Checkpoints = tag.RowsAffected()
	if tag, e = tx.Exec(ctx, "DELETE FROM messaging.outbox_events o USING ("+pairs+") p WHERE o.tenant_id=p.tenant_id AND o.event_id=p.event_id", tenants, events); e != nil {
		return out, e
	}
	out.Events = tag.RowsAffected()
	return out, tx.Commit(ctx)
}

// PruneDeliveries удаляет до batch завершённых доставок (delivered/dead) старше age.
func PruneDeliveries(ctx context.Context, pool *pgxpool.Pool, age time.Duration, batch int) (int64, error) {
	tag, e := pool.Exec(ctx, `DELETE FROM messaging.webhook_deliveries WHERE ctid IN (SELECT ctid FROM messaging.webhook_deliveries
WHERE state IN ('delivered','dead') AND coalesce(delivered_at,next_attempt_at) < clock_timestamp() - $1*interval '1 second' LIMIT $2)`, age.Seconds(), batch)
	return tag.RowsAffected(), e
}

// PruneLeases удаляет истёкшие аренды.
func PruneLeases(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	tag, e := pool.Exec(ctx, "DELETE FROM messaging.work_leases WHERE lease_until < clock_timestamp() - interval '1 hour'")
	return tag.RowsAffected(), e
}
