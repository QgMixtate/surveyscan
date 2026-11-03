-- Owner: responsibility; C02 logical baseline refined by C03 signed payload.
CREATE SCHEMA IF NOT EXISTS responsibility;

CREATE TABLE responsibility.responsibility_assignments (
    tenant_id uuid NOT NULL,
    assignment_id uuid NOT NULL,
    asset_uid uuid NOT NULL,
    subject_id uuid NOT NULL,
    role text NOT NULL,
    valid_from timestamptz NOT NULL DEFAULT now(),
    valid_to timestamptz,
    reason_code text NOT NULL,
    actor_ref text NOT NULL,
    PRIMARY KEY (tenant_id,assignment_id),
    FOREIGN KEY (tenant_id,asset_uid) REFERENCES assets.assets (tenant_id,asset_uid) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id,subject_id) REFERENCES responsibility.subjects (tenant_id,subject_id) ON DELETE RESTRICT,
    CHECK (valid_to IS NULL OR valid_to >= valid_from)
);

CREATE UNIQUE INDEX responsibility_one_active_role ON responsibility.responsibility_assignments(tenant_id,asset_uid,role) WHERE valid_to IS NULL;
