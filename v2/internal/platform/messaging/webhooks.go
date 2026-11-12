package messaging

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// C31.03 (ADR decisions/C31-integrations.md): подписки на события outbox и их доставка. Раздача (fan-out) — потребитель
// outbox WebhookConsumer: строка доставки на подписку, если событие возникло после создания подписки (история не
// рассылается). Отправка — по строкам доставки с повторами; после WebhookMaxAttempts неудач — dead.

const (
	WebhookConsumer    = "webhook-fanout"
	WebhookMaxAttempts = 5
)

// WebhookEventTypes — события, на которые можно подписаться (типы outbox C03).
var WebhookEventTypes = map[string]bool{"asset.created.v1": true, "asset.facts_changed.v1": true, "responsibility.assigned.v1": true,
	"observation.recorded.v1": true, "source.contact_updated.v1": true, "source.profile_updated.v1": true}

type WebhookSubscription struct {
	ID         string    `json:"subscription_id"`
	URL        string    `json:"url"`
	EventTypes []string  `json:"event_types"`
	Active     bool      `json:"active"`
	Revision   string    `json:"revision"`
	CreatedAt  time.Time `json:"created_at"`
	Pending    int       `json:"pending"`
	Delivered  int       `json:"delivered"`
	Dead       int       `json:"dead"`
}

type WebhookDelivery struct {
	EventID    string     `json:"event_id"`
	EventType  string     `json:"event_type"`
	OccurredAt time.Time  `json:"occurred_at"`
	State      string     `json:"state"`
	Attempts   int        `json:"attempts"`
	NextAt     *time.Time `json:"next_attempt_at"`
	LastStatus *int       `json:"last_status"`
	LastError  *string    `json:"last_error"`
	Delivered  *time.Time `json:"delivered_at"`
}

// WebhookJob — доставка, взятая отправителем (аренда next_attempt_at на время отправки).
type WebhookJob struct {
	Tenant, Subscription, URL string
	Attempts                  int
	Payload                   WebhookPayload
}

type WebhookPayload struct {
	Schema     string            `json:"schema"`
	EventID    string            `json:"event_id"`
	EventType  string            `json:"event_type"`
	TenantID   string            `json:"tenant_id"`
	OccurredAt time.Time         `json:"occurred_at"`
	Aggregate  WebhookAggregate  `json:"aggregate"`
	Data       map[string]string `json:"data"`
}

type WebhookAggregate struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	Version string `json:"version"`
}

type Webhooks struct{}

const subscriptionColumns = `s.subscription_id::text,s.url,s.event_types,s.active,s.revision::text,s.created_at,
(SELECT count(*) FILTER (WHERE d.state='pending') FROM messaging.webhook_deliveries d WHERE d.tenant_id=s.tenant_id AND d.subscription_id=s.subscription_id)::int,
(SELECT count(*) FILTER (WHERE d.state='delivered') FROM messaging.webhook_deliveries d WHERE d.tenant_id=s.tenant_id AND d.subscription_id=s.subscription_id)::int,
(SELECT count(*) FILTER (WHERE d.state='dead') FROM messaging.webhook_deliveries d WHERE d.tenant_id=s.tenant_id AND d.subscription_id=s.subscription_id)::int`

func scanSubscription(row pgx.Row) (WebhookSubscription, error) {
	var s WebhookSubscription
	e := row.Scan(&s.ID, &s.URL, &s.EventTypes, &s.Active, &s.Revision, &s.CreatedAt, &s.Pending, &s.Delivered, &s.Dead)
	if errors.Is(e, pgx.ErrNoRows) {
		e = domain.NotFound
	}
	return s, e
}

func validTypes(types []string) bool {
	if len(types) == 0 || len(types) > 16 {
		return false
	}
	seen := map[string]bool{}
	for _, t := range types {
		if !WebhookEventTypes[t] || seen[t] {
			return false
		}
		seen[t] = true
	}
	return true
}

func (Webhooks) Create(ctx context.Context, tx pgx.Tx, tenant, url string, types []string, actor string) (WebhookSubscription, error) {
	if !validTypes(types) {
		return WebhookSubscription{}, domain.Invalid
	}
	id := identifier.New()
	if _, e := tx.Exec(ctx, "INSERT INTO messaging.webhook_subscriptions(tenant_id,subscription_id,url,event_types,actor_ref,created_at) VALUES($1,$2,$3,$4,$5,clock_timestamp())", tenant, id, url, types, actor); e != nil {
		return WebhookSubscription{}, e
	}
	return Webhooks{}.Get(ctx, tx, tenant, id)
}

func (Webhooks) Get(ctx context.Context, tx pgx.Tx, tenant, id string) (WebhookSubscription, error) {
	if !identifier.Valid(id) {
		return WebhookSubscription{}, domain.NotFound
	}
	return scanSubscription(tx.QueryRow(ctx, "SELECT "+subscriptionColumns+" FROM messaging.webhook_subscriptions s WHERE s.tenant_id=$1 AND s.subscription_id=$2", tenant, id))
}

func (Webhooks) List(ctx context.Context, tx pgx.Tx, tenant string) ([]WebhookSubscription, error) {
	rows, e := tx.Query(ctx, "SELECT "+subscriptionColumns+" FROM messaging.webhook_subscriptions s WHERE s.tenant_id=$1 ORDER BY s.created_at,s.subscription_id LIMIT 100", tenant)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []WebhookSubscription{}
	for rows.Next() {
		s, e := scanSubscription(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// Update меняет адрес, типы и активность при совпадении ревизии (nil — не менять).
func (w Webhooks) Update(ctx context.Context, tx pgx.Tx, tenant, id, revision string, url *string, types []string, active *bool) (WebhookSubscription, error) {
	if types != nil && !validTypes(types) {
		return WebhookSubscription{}, domain.Invalid
	}
	if _, e := w.Get(ctx, tx, tenant, id); e != nil {
		return WebhookSubscription{}, e
	}
	tag, e := tx.Exec(ctx, `UPDATE messaging.webhook_subscriptions SET url=COALESCE($4,url),event_types=COALESCE($5,event_types),active=COALESCE($6,active),revision=revision+1
WHERE tenant_id=$1 AND subscription_id=$2 AND revision::text=$3`, tenant, id, revision, url, types, active)
	if e != nil {
		return WebhookSubscription{}, e
	}
	if tag.RowsAffected() != 1 {
		return WebhookSubscription{}, domain.Revision
	}
	return w.Get(ctx, tx, tenant, id)
}

func (Webhooks) Deliveries(ctx context.Context, tx pgx.Tx, tenant, id, state string, limit int) ([]WebhookDelivery, error) {
	rows, e := tx.Query(ctx, `SELECT d.event_id::text,e.event_type,e.occurred_at,d.state,d.attempts,CASE WHEN d.state='pending' THEN d.next_attempt_at END,d.last_status,d.last_error,d.delivered_at
FROM messaging.webhook_deliveries d JOIN messaging.outbox_events e ON e.tenant_id=d.tenant_id AND e.event_id=d.event_id
WHERE d.tenant_id=$1 AND d.subscription_id=$2 AND ($3='' OR d.state=$3) ORDER BY e.occurred_at DESC,d.event_id LIMIT $4`, tenant, id, state, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []WebhookDelivery{}
	for rows.Next() {
		var d WebhookDelivery
		if e = rows.Scan(&d.EventID, &d.EventType, &d.OccurredAt, &d.State, &d.Attempts, &d.NextAt, &d.LastStatus, &d.LastError, &d.Delivered); e != nil {
			return nil, e
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Retry — повтор dead-доставки (явное действие администратора). Доставленное повторно не отправляется.
func (Webhooks) Retry(ctx context.Context, tx pgx.Tx, tenant, id, event string) error {
	if !identifier.Valid(event) {
		return domain.NotFound
	}
	var state string
	e := tx.QueryRow(ctx, "SELECT state FROM messaging.webhook_deliveries WHERE tenant_id=$1 AND subscription_id=$2 AND event_id=$3 FOR UPDATE", tenant, id, event).Scan(&state)
	if errors.Is(e, pgx.ErrNoRows) {
		return domain.NotFound
	}
	if e != nil {
		return e
	}
	if state != "dead" {
		return domain.Conflict
	}
	_, e = tx.Exec(ctx, "UPDATE messaging.webhook_deliveries SET state='pending',attempts=0,next_attempt_at=clock_timestamp(),last_error=NULL WHERE tenant_id=$1 AND subscription_id=$2 AND event_id=$3", tenant, id, event)
	return e
}

// FanoutWebhooks раздаёт события тенанта по активным подпискам (только возникшие после создания подписки).
func FanoutWebhooks(ctx context.Context, pool *pgxpool.Pool, tenant string, max int) (int, error) {
	return ConsumeBatch(ctx, pool, tenant, WebhookConsumer, max, func(ctx context.Context, tx pgx.Tx, events []Event) error {
		ids := make([]string, len(events))
		for i, ev := range events {
			ids[i] = ev.ID
		}
		_, e := tx.Exec(ctx, `INSERT INTO messaging.webhook_deliveries(tenant_id,subscription_id,event_id)
SELECT e.tenant_id,s.subscription_id,e.event_id FROM messaging.outbox_events e JOIN messaging.webhook_subscriptions s ON s.tenant_id=e.tenant_id
WHERE e.tenant_id=$1 AND e.event_id=ANY($2::uuid[]) AND s.active AND e.event_type=ANY(s.event_types) AND e.occurred_at>=s.created_at
ON CONFLICT DO NOTHING`, tenant, ids)
		return e
	})
}

// ClaimWebhooks берёт до max созревших доставок активных подписок (всех тенантов) и арендует их на lease.
func ClaimWebhooks(ctx context.Context, pool *pgxpool.Pool, max int, lease time.Duration) ([]WebhookJob, error) {
	tx, e := pool.Begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx)
	rows, e := tx.Query(ctx, `SELECT d.tenant_id::text,d.subscription_id::text,s.url,d.attempts,e.event_id::text,e.event_type,e.occurred_at,e.aggregate_type,e.aggregate_id::text,e.aggregate_version::text,e.payload
FROM messaging.webhook_deliveries d JOIN messaging.webhook_subscriptions s ON s.tenant_id=d.tenant_id AND s.subscription_id=d.subscription_id
JOIN messaging.outbox_events e ON e.tenant_id=d.tenant_id AND e.event_id=d.event_id
WHERE d.state='pending' AND d.next_attempt_at<=clock_timestamp() AND s.active ORDER BY d.next_attempt_at LIMIT $1 FOR UPDATE OF d SKIP LOCKED`, max)
	if e != nil {
		return nil, e
	}
	jobs := []WebhookJob{}
	for rows.Next() {
		var j WebhookJob
		var payload []byte
		p := &j.Payload
		if e = rows.Scan(&j.Tenant, &j.Subscription, &j.URL, &j.Attempts, &p.EventID, &p.EventType, &p.OccurredAt, &p.Aggregate.Type, &p.Aggregate.ID, &p.Aggregate.Version, &payload); e != nil {
			rows.Close()
			return nil, e
		}
		if e = json.Unmarshal(payload, &p.Data); e != nil {
			rows.Close()
			return nil, e
		}
		p.Schema, p.TenantID = "surveyscan-webhook-v1", j.Tenant
		if p.Data == nil {
			p.Data = map[string]string{}
		}
		jobs = append(jobs, j)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return nil, e
	}
	for _, j := range jobs {
		if _, e = tx.Exec(ctx, "UPDATE messaging.webhook_deliveries SET next_attempt_at=clock_timestamp()+$4*interval '1 second' WHERE tenant_id=$1 AND subscription_id=$2 AND event_id=$3", j.Tenant, j.Subscription, j.Payload.EventID, lease.Seconds()); e != nil {
			return nil, e
		}
	}
	return jobs, tx.Commit(ctx)
}

// WebhookBackoff — пауза перед следующей попыткой после attempts неудач: 30 с, 1, 2, 4 мин… не более часа.
func WebhookBackoff(attempts int) time.Duration {
	d := 30 * time.Second
	for i := 1; i < attempts && d < time.Hour; i++ {
		d *= 2
	}
	return min(d, time.Hour)
}

// FinishWebhook записывает итог попытки: 2xx — delivered; иначе повтор с паузой, после WebhookMaxAttempts — dead.
func FinishWebhook(ctx context.Context, pool *pgxpool.Pool, j WebhookJob, status int, failure string) error {
	if len([]rune(failure)) > 512 {
		failure = string([]rune(failure)[:512])
	}
	var code *int
	if status > 0 {
		code = &status
	}
	if failure == "" {
		_, e := pool.Exec(ctx, "UPDATE messaging.webhook_deliveries SET state='delivered',attempts=attempts+1,last_status=$4,last_error=NULL,delivered_at=clock_timestamp() WHERE tenant_id=$1 AND subscription_id=$2 AND event_id=$3 AND state='pending'", j.Tenant, j.Subscription, j.Payload.EventID, code)
		return e
	}
	attempts := j.Attempts + 1
	state := "pending"
	if attempts >= WebhookMaxAttempts {
		state = "dead"
	}
	_, e := pool.Exec(ctx, `UPDATE messaging.webhook_deliveries SET state=$4,attempts=$5,last_status=$6,last_error=$7,next_attempt_at=clock_timestamp()+$8*interval '1 second'
WHERE tenant_id=$1 AND subscription_id=$2 AND event_id=$3 AND state='pending'`, j.Tenant, j.Subscription, j.Payload.EventID, state, attempts, code, failure, WebhookBackoff(attempts).Seconds())
	return e
}
