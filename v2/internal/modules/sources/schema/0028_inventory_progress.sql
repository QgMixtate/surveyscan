-- Owner: sources; успешный сбор и heartbeat — независимые сигналы.
CREATE TABLE sources.inventory_progress (
 tenant_id uuid NOT NULL,
 source_id uuid NOT NULL,
 generation_id uuid NOT NULL,
 last_successful_inventory_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,source_id,generation_id),
 FOREIGN KEY(tenant_id,source_id) REFERENCES sources.sources(tenant_id,source_id) ON DELETE RESTRICT
);
