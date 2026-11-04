-- Source-owned, origin-reported diagnostics; separate from heartbeat and inventory freshness.
CREATE TABLE sources.runtime_diagnostics (
 tenant_id uuid NOT NULL,
 source_id uuid NOT NULL,
 generation_id uuid NOT NULL,
 collected_at timestamptz NOT NULL,
 received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 pending_files integer NOT NULL CHECK(pending_files BETWEEN 0 AND 4096),
 pending_bytes bigint NOT NULL CHECK(pending_bytes BETWEEN 0 AND 1099511627776),
 oldest_pending_at timestamptz,
 disk_available_bytes bigint CHECK(disk_available_bytes BETWEEN 0 AND 9007199254740991),
 certificate_expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,source_id,generation_id),
 FOREIGN KEY(tenant_id,source_id) REFERENCES sources.sources(tenant_id,source_id) ON DELETE RESTRICT
);
