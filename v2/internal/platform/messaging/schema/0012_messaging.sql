-- Owner: messaging; C02 logical baseline refined by C03 signed payload.
CREATE SCHEMA IF NOT EXISTS messaging;

CREATE TABLE messaging.outbox_events (
    tenant_id uuid NOT NULL,
    event_id uuid NOT NULL,
    producer_module text NOT NULL,
    aggregate_type text NOT NULL,
    aggregate_id uuid NOT NULL,
    aggregate_version platform.uint64 NOT NULL DEFAULT 1,
    event_type text NOT NULL,
    schema_version jsonb NOT NULL DEFAULT '{"major":1,"minor":0}'::jsonb,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    correlation_id uuid NOT NULL,
    causation_id uuid,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (tenant_id,event_id),
    UNIQUE (tenant_id,aggregate_type,aggregate_id,aggregate_version),
    FOREIGN KEY (tenant_id) REFERENCES access.tenants (tenant_id) ON DELETE RESTRICT
);

CREATE TABLE messaging.consumer_checkpoints (
    tenant_id uuid NOT NULL,
    consumer_name text NOT NULL,
    event_id uuid NOT NULL,
    state text NOT NULL CHECK (state IN ('claimed','applied','retry','dead_letter')),
    attempts integer NOT NULL DEFAULT 1 CHECK (attempts >= 0),
    lease_until timestamptz,
    applied_at timestamptz,
    PRIMARY KEY (tenant_id,consumer_name,event_id),
    FOREIGN KEY (tenant_id,event_id) REFERENCES messaging.outbox_events (tenant_id,event_id) ON DELETE RESTRICT
);
