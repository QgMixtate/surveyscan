-- Sources owns published profiles and origin-reported application progress. No inventory freshness mutation.
CREATE TABLE sources.profiles (
 tenant_id uuid NOT NULL,
 source_id uuid NOT NULL,
 revision platform.uint64 NOT NULL DEFAULT 2 CHECK(revision>=2),
 heartbeat_seconds integer NOT NULL CHECK(heartbeat_seconds BETWEEN 30 AND 3600),
 inventory_seconds integer NOT NULL CHECK(inventory_seconds BETWEEN 60 AND 86400),
 jitter_percent integer NOT NULL CHECK(jitter_percent BETWEEN 0 AND 25),
 spool_limit_bytes bigint NOT NULL CHECK(spool_limit_bytes BETWEEN 524288 AND 1073741824),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,source_id),
 FOREIGN KEY(tenant_id,source_id) REFERENCES sources.sources(tenant_id,source_id) ON DELETE RESTRICT
);
CREATE TABLE sources.profile_progress (
 tenant_id uuid NOT NULL,
 source_id uuid NOT NULL,
 generation_id uuid NOT NULL,
 applied_revision platform.uint64,
 last_config_contact_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,source_id,generation_id),
 FOREIGN KEY(tenant_id,source_id) REFERENCES sources.sources(tenant_id,source_id) ON DELETE RESTRICT
);
