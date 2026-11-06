-- C15: independent projection for observation 1.2; C09/1.0 remains unchanged.
-- Provider record keys identify rows within an asset/section, never global assets.
CREATE TABLE inventory.record_facts12 (
 tenant_id uuid NOT NULL,
 asset_uid uuid NOT NULL,
 section_name text NOT NULL,
 record_key text NOT NULL CHECK (record_key ~ '^[0-9a-f]{64}$'),
 field_name text NOT NULL,
 value jsonb NOT NULL,
 observation_id uuid NOT NULL,
 link_id uuid NOT NULL,
 projection_revision platform.uint64 NOT NULL DEFAULT 1,
 PRIMARY KEY (tenant_id,asset_uid,section_name,record_key,field_name),
 FOREIGN KEY (tenant_id,link_id,asset_uid,observation_id)
  REFERENCES assets.observation_links(tenant_id,link_id,asset_uid,observation_id),
 FOREIGN KEY (tenant_id,observation_id,section_name)
  REFERENCES inventory.observation_sections(tenant_id,observation_id,section_name)
);

CREATE TABLE inventory.record_section_state12 (
 tenant_id uuid NOT NULL,
 asset_uid uuid NOT NULL,
 section_name text NOT NULL,
 last_attempt_id uuid NOT NULL,
 last_status text NOT NULL CHECK (last_status IN ('partial','unavailable','unsupported','not_requested')),
 clock_uncertain boolean NOT NULL,
 projection_revision platform.uint64 NOT NULL DEFAULT 1,
 PRIMARY KEY (tenant_id,asset_uid,section_name),
 FOREIGN KEY (tenant_id,asset_uid) REFERENCES assets.assets(tenant_id,asset_uid),
 FOREIGN KEY (tenant_id,last_attempt_id,section_name)
  REFERENCES inventory.observation_sections(tenant_id,observation_id,section_name)
);
