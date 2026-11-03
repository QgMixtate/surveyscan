-- Owner: sources; C02 logical baseline refined by C03 signed payload.
CREATE SCHEMA IF NOT EXISTS sources;

CREATE TABLE sources.sources (
    tenant_id uuid NOT NULL,
    source_id uuid NOT NULL,
    source_kind text NOT NULL CHECK (source_kind IN ('agent','collector','portable')),
    site_id uuid NOT NULL,
    state text NOT NULL CHECK (state IN ('pending','active','revoked','disabled')),
    generation_id uuid NOT NULL,
    last_contact_at timestamptz,
    last_successful_inventory_at timestamptz,
    revision platform.uint64 NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id,source_id),
    UNIQUE (tenant_id,source_id,source_kind),
    FOREIGN KEY (tenant_id,site_id) REFERENCES scope.sites (tenant_id,site_id) ON DELETE RESTRICT
);

CREATE TABLE sources.collectors (
    tenant_id uuid NOT NULL,
    collector_id uuid NOT NULL,
    source_id uuid NOT NULL,
    source_kind text NOT NULL DEFAULT 'collector' CHECK (source_kind='collector'),
    revision platform.uint64 NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id,collector_id),
    UNIQUE (tenant_id,source_id),
    FOREIGN KEY (tenant_id,source_id,source_kind) REFERENCES sources.sources (tenant_id,source_id,source_kind) ON DELETE RESTRICT
);

CREATE TABLE sources.agents (
    tenant_id uuid NOT NULL,
    agent_id uuid NOT NULL,
    source_id uuid NOT NULL,
    source_kind text NOT NULL DEFAULT 'agent' CHECK (source_kind='agent'),
    collector_id uuid NOT NULL,
    enrollment_revision platform.uint64 NOT NULL DEFAULT 1,
    revision platform.uint64 NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id,agent_id),
    UNIQUE (tenant_id,source_id),
    FOREIGN KEY (tenant_id,source_id,source_kind) REFERENCES sources.sources (tenant_id,source_id,source_kind) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id,collector_id) REFERENCES sources.collectors (tenant_id,collector_id) ON DELETE RESTRICT
);
