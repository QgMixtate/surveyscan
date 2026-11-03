-- Owner: assets; C02 logical baseline refined by C03 signed payload.
CREATE SCHEMA IF NOT EXISTS assets;

CREATE TABLE assets.assets (
    tenant_id uuid NOT NULL,
    asset_uid uuid NOT NULL,
    site_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    asset_type text NOT NULL DEFAULT 'unknown' CHECK (length(asset_type) BETWEEN 1 AND 64),
    aggregate_version platform.uint64 NOT NULL DEFAULT 1,
    lifecycle_state text NOT NULL DEFAULT 'unknown' CHECK (length(lifecycle_state) BETWEEN 1 AND 64),
    created_at timestamptz NOT NULL DEFAULT now(),
    retired_at timestamptz,
    PRIMARY KEY (tenant_id,asset_uid),
    UNIQUE (asset_uid),
    FOREIGN KEY (tenant_id,site_id) REFERENCES scope.sites (tenant_id,site_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id,scope_id,site_id) REFERENCES scope.network_scopes (tenant_id,scope_id,site_id) ON DELETE RESTRICT
);

CREATE TABLE assets.asset_business_fields (
    tenant_id uuid NOT NULL,
    asset_uid uuid NOT NULL,
    display_name text,
    purpose text,
    criticality text NOT NULL DEFAULT 'unknown' CHECK (criticality IN ('unknown','low','medium','high','critical')),
    tags text[] NOT NULL DEFAULT '{}'::text[],
    revision platform.uint64 NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id,asset_uid),
    FOREIGN KEY (tenant_id,asset_uid) REFERENCES assets.assets (tenant_id,asset_uid) ON DELETE RESTRICT,
    CHECK (cardinality(tags)<=32)
);

CREATE TABLE assets.source_records (
    tenant_id uuid NOT NULL,
    source_record_key uuid NOT NULL,
    source_id uuid NOT NULL,
    namespace text NOT NULL,
    source_local_id text NOT NULL CHECK (length(source_local_id) BETWEEN 1 AND 256),
    resolution_state text NOT NULL CHECK (resolution_state IN ('unresolved','resolved','conflict')),
    asset_uid uuid,
    revision platform.uint64 NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id,source_record_key),
    UNIQUE (tenant_id,source_id,namespace,source_local_id),
    UNIQUE (tenant_id,source_record_key,source_id),
    FOREIGN KEY (tenant_id,source_id) REFERENCES sources.sources (tenant_id,source_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id,asset_uid) REFERENCES assets.assets (tenant_id,asset_uid) ON DELETE RESTRICT,
    CHECK ((resolution_state='resolved') = (asset_uid IS NOT NULL))
);

CREATE TABLE assets.asset_identifiers (
    tenant_id uuid NOT NULL,
    identifier_id uuid NOT NULL,
    asset_uid uuid NOT NULL,
    kind text NOT NULL,
    namespace text NOT NULL,
    normalized_value text NOT NULL,
    strength text NOT NULL CHECK (strength IN ('weak','strong','unknown')),
    source_record_key uuid NOT NULL,
    valid_from timestamptz NOT NULL DEFAULT now(),
    valid_to timestamptz,
    PRIMARY KEY (tenant_id,identifier_id),
    FOREIGN KEY (tenant_id,asset_uid) REFERENCES assets.assets (tenant_id,asset_uid) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id,source_record_key) REFERENCES assets.source_records (tenant_id,source_record_key) ON DELETE RESTRICT,
    CHECK (valid_to IS NULL OR valid_to >= valid_from)
);

CREATE TABLE assets.reconciliation_conflicts (
    tenant_id uuid NOT NULL,
    conflict_id uuid NOT NULL,
    source_record_key uuid NOT NULL,
    candidate_asset_uids uuid[] NOT NULL DEFAULT '{}'::uuid[],
    reason_code text NOT NULL,
    state text NOT NULL CHECK (state IN ('open','resolved','dismissed')),
    revision platform.uint64 NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id,conflict_id),
    FOREIGN KEY (tenant_id,source_record_key) REFERENCES assets.source_records (tenant_id,source_record_key) ON DELETE RESTRICT,
    CHECK (cardinality(candidate_asset_uids)<=16)
);

CREATE TABLE assets.asset_changes (
    tenant_id uuid NOT NULL,
    change_id uuid NOT NULL,
    asset_uid uuid NOT NULL,
    aggregate_version platform.uint64 NOT NULL DEFAULT 1,
    reason_code text NOT NULL,
    provenance jsonb NOT NULL DEFAULT '{}'::jsonb,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    actor_ref text NOT NULL,
    PRIMARY KEY (tenant_id,change_id),
    FOREIGN KEY (tenant_id,asset_uid) REFERENCES assets.assets (tenant_id,asset_uid) ON DELETE RESTRICT
);

CREATE INDEX asset_identifier_lookup ON assets.asset_identifiers(tenant_id,kind,namespace,normalized_value);
