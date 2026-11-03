-- Owner: inventory; C02 logical baseline refined by C03 signed payload.
CREATE SCHEMA IF NOT EXISTS inventory;

CREATE TABLE inventory.observations (
    tenant_id uuid NOT NULL,
    observation_id uuid NOT NULL,
    source_record_key uuid NOT NULL,
    source_id uuid NOT NULL,
    generation_id uuid NOT NULL,
    source_sequence platform.uint64 NOT NULL,
    collected_at timestamptz NOT NULL DEFAULT now(),
    received_at timestamptz NOT NULL DEFAULT now(),
    clock_quality text NOT NULL CHECK (clock_quality IN ('trusted','estimated','unknown','skewed')),
    digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    asserted_asset_uid uuid,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    origin_key_id uuid NOT NULL,
    origin_signature bytea NOT NULL CHECK (octet_length(origin_signature)=64),
    canonical_payload bytea NOT NULL,
    CHECK (encode(sha256(canonical_payload),'hex')=digest),
    CHECK (convert_from(canonical_payload,'UTF8')::jsonb=payload),
    PRIMARY KEY (tenant_id,observation_id),
    UNIQUE (tenant_id,source_id,generation_id,source_record_key,source_sequence),
    FOREIGN KEY (tenant_id,source_record_key,source_id) REFERENCES assets.source_records (tenant_id,source_record_key,source_id) ON DELETE RESTRICT
);

CREATE TABLE inventory.observation_sections (
    tenant_id uuid NOT NULL,
    observation_id uuid NOT NULL,
    section_name text NOT NULL,
    status text NOT NULL CHECK (status IN ('ok','partial','unavailable','unsupported','not_requested','unknown')),
    collection_complete boolean NOT NULL DEFAULT false,
    reason_code text NOT NULL,
    record_count integer NOT NULL DEFAULT 0 CHECK (record_count >= 0),
    facts jsonb NOT NULL DEFAULT '[]'::jsonb,
    PRIMARY KEY (tenant_id,observation_id,section_name),
    FOREIGN KEY (tenant_id,observation_id) REFERENCES inventory.observations (tenant_id,observation_id) ON DELETE RESTRICT,
    CHECK (jsonb_typeof(facts)='array'),
    CHECK (record_count=jsonb_array_length(facts)),
    CHECK (status NOT IN ('unavailable','unsupported','not_requested') OR (record_count=0 AND NOT collection_complete)),
    CHECK (status<>'partial' OR NOT collection_complete)
);
