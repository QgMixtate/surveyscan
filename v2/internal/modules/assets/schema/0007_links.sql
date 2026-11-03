-- Owner: assets; C02 logical baseline refined by C03 signed payload.
CREATE SCHEMA IF NOT EXISTS assets;

CREATE TABLE assets.observation_links (
    tenant_id uuid NOT NULL,
    link_id uuid NOT NULL,
    observation_id uuid NOT NULL,
    asset_uid uuid NOT NULL,
    assignment_revision platform.uint64 NOT NULL DEFAULT 1,
    valid_from timestamptz NOT NULL DEFAULT now(),
    valid_to timestamptz,
    reason_code text NOT NULL,
    PRIMARY KEY (tenant_id,link_id),
    UNIQUE (tenant_id,observation_id,assignment_revision),
    UNIQUE (tenant_id,link_id,asset_uid,observation_id),
    FOREIGN KEY (tenant_id,observation_id) REFERENCES inventory.observations (tenant_id,observation_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id,asset_uid) REFERENCES assets.assets (tenant_id,asset_uid) ON DELETE RESTRICT,
    CHECK (valid_to IS NULL OR valid_to >= valid_from)
);

CREATE UNIQUE INDEX observation_one_active_link ON assets.observation_links(tenant_id,observation_id) WHERE valid_to IS NULL;
