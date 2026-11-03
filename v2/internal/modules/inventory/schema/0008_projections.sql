-- Owner: inventory; C02 logical baseline refined by C03 signed payload.
CREATE SCHEMA IF NOT EXISTS inventory;

CREATE TABLE inventory.current_facts (
    tenant_id uuid NOT NULL,
    asset_uid uuid NOT NULL,
    section_name text NOT NULL,
    fact_key text NOT NULL,
    value text NOT NULL,
    observation_id uuid NOT NULL,
    link_id uuid NOT NULL,
    projection_revision platform.uint64 NOT NULL DEFAULT 1,
    policy_revision platform.uint64 NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id,asset_uid,section_name,fact_key),
    FOREIGN KEY (tenant_id,link_id,asset_uid,observation_id) REFERENCES assets.observation_links (tenant_id,link_id,asset_uid,observation_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id,observation_id,section_name) REFERENCES inventory.observation_sections (tenant_id,observation_id,section_name) ON DELETE RESTRICT
);

CREATE TABLE inventory.section_state (
    tenant_id uuid NOT NULL,
    asset_uid uuid NOT NULL,
    section_name text NOT NULL,
    last_attempt_id uuid,
    last_success_id uuid,
    last_status text NOT NULL CHECK (last_status IN ('ok','partial','unavailable','unsupported','not_requested','unknown')),
    projection_revision platform.uint64 NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id,asset_uid,section_name),
    FOREIGN KEY (tenant_id,asset_uid) REFERENCES assets.assets (tenant_id,asset_uid) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id,last_attempt_id,section_name) REFERENCES inventory.observation_sections (tenant_id,observation_id,section_name) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id,last_success_id,section_name) REFERENCES inventory.observation_sections (tenant_id,observation_id,section_name) ON DELETE RESTRICT
);
