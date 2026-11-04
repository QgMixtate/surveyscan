-- Owner: sources. Контакт источника не изменяет freshness наблюдаемых секций.
CREATE TABLE sources.heartbeat_state (
 tenant_id uuid NOT NULL,
 source_id uuid NOT NULL,
 generation_id uuid NOT NULL,
 challenge_id uuid NOT NULL,
 nonce text NOT NULL,
 issued_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 consumed boolean NOT NULL DEFAULT false,
 last_sequence platform.uint64,
 last_contact_at timestamptz,
 PRIMARY KEY(tenant_id,source_id,generation_id),
 FOREIGN KEY(tenant_id,source_id) REFERENCES sources.sources(tenant_id,source_id) ON DELETE RESTRICT,
 CHECK(expires_at>issued_at)
);
CREATE TABLE sources.heartbeat_receipts (
 tenant_id uuid NOT NULL,
 heartbeat_id uuid NOT NULL,
 source_id uuid NOT NULL,
 generation_id uuid NOT NULL,
 digest text NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$'),
 sequence platform.uint64 NOT NULL,
 result jsonb NOT NULL,
 PRIMARY KEY(tenant_id,heartbeat_id),
 UNIQUE(tenant_id,source_id,generation_id,sequence),
 FOREIGN KEY(tenant_id,source_id) REFERENCES sources.sources(tenant_id,source_id) ON DELETE RESTRICT
);
