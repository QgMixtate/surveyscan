-- Owner: imports; C02 logical baseline refined by C03 signed payload.
CREATE SCHEMA IF NOT EXISTS imports;

CREATE TABLE imports.deliveries (
    tenant_id uuid NOT NULL,
    delivery_id uuid NOT NULL,
    collector_id uuid,
    digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    state text NOT NULL CHECK (state IN ('receiving','validating','processing','completed','completed_with_errors','rejected','failed')),
    received_at timestamptz NOT NULL DEFAULT now(),
    revision platform.uint64 NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id,delivery_id),
    FOREIGN KEY (tenant_id,collector_id) REFERENCES sources.collectors (tenant_id,collector_id) ON DELETE RESTRICT
);

CREATE TABLE imports.import_checkpoints (
    tenant_id uuid NOT NULL,
    delivery_id uuid NOT NULL,
    record_key text NOT NULL CHECK (length(record_key) BETWEEN 1 AND 256),
    state text NOT NULL CHECK (state IN ('pending','applied','recorded_pending_resolution','rejected')),
    observation_id uuid,
    reason_code text NOT NULL,
    revision platform.uint64 NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id,delivery_id,record_key),
    FOREIGN KEY (tenant_id,delivery_id) REFERENCES imports.deliveries (tenant_id,delivery_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id,observation_id) REFERENCES inventory.observations (tenant_id,observation_id) ON DELETE RESTRICT
);
