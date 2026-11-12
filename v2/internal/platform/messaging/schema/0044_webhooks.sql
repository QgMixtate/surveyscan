-- Owner: messaging; C31.03 (ADR decisions/C31-integrations.md) — исходящие уведомления (webhook) по событиям outbox.
-- Секрет подписи в БД не хранится: ключ выводится из приватного файла центра и ID подписки.
CREATE TABLE messaging.webhook_subscriptions (
 tenant_id uuid NOT NULL,
 subscription_id uuid NOT NULL,
 url text NOT NULL CHECK (length(url) BETWEEN 10 AND 2048),
 event_types text[] NOT NULL CHECK (cardinality(event_types) BETWEEN 1 AND 16),
 active boolean NOT NULL DEFAULT true,
 revision platform.uint64 NOT NULL DEFAULT 1,
 created_at timestamptz NOT NULL DEFAULT now(),
 actor_ref text NOT NULL,
 PRIMARY KEY (tenant_id,subscription_id),
 FOREIGN KEY (tenant_id) REFERENCES access.tenants(tenant_id) ON DELETE RESTRICT
);

-- Доставка «как минимум один раз»: строка на (подписка, событие); получатель отбрасывает повторы по event_id.
CREATE TABLE messaging.webhook_deliveries (
 tenant_id uuid NOT NULL,
 subscription_id uuid NOT NULL,
 event_id uuid NOT NULL,
 state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','delivered','dead')),
 attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
 next_attempt_at timestamptz NOT NULL DEFAULT now(),
 last_status integer,
 last_error text CHECK (length(last_error) <= 512),
 delivered_at timestamptz,
 PRIMARY KEY (tenant_id,subscription_id,event_id),
 FOREIGN KEY (tenant_id,subscription_id) REFERENCES messaging.webhook_subscriptions(tenant_id,subscription_id) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id,event_id) REFERENCES messaging.outbox_events(tenant_id,event_id) ON DELETE RESTRICT
);
CREATE INDEX webhook_due ON messaging.webhook_deliveries(next_attempt_at) WHERE state='pending';
CREATE INDEX webhook_by_state ON messaging.webhook_deliveries(tenant_id,subscription_id,state,next_attempt_at);
