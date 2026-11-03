-- Owner: audit; C02 logical baseline refined by C03 signed payload.
CREATE SCHEMA IF NOT EXISTS audit;

CREATE TABLE audit.audit_events (
    tenant_id uuid NOT NULL,
    audit_id uuid NOT NULL,
    actor_ref text NOT NULL,
    action text NOT NULL,
    object_type text NOT NULL,
    object_id text NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    safe_metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (tenant_id,audit_id),
    FOREIGN KEY (tenant_id) REFERENCES access.tenants (tenant_id) ON DELETE RESTRICT
);
