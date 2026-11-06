-- Sources owns Windows inventory profile offers/application reports separately from C12.
-- Common cadence remains in sources.profiles; profile contact is neither heartbeat nor inventory success.
CREATE TABLE sources.inventory_profile_progress12 (
 tenant_id uuid NOT NULL,
 source_id uuid NOT NULL,
 generation_id uuid NOT NULL,
 policy_id text NOT NULL CHECK(policy_id='windows-amd64-partial-baseline-v1'),
 offered_revision platform.uint64 NOT NULL CHECK(offered_revision>=1),
 applied_revision platform.uint64,
 last_profile_contact_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,source_id,generation_id),
 FOREIGN KEY(tenant_id,source_id) REFERENCES sources.sources(tenant_id,source_id) ON DELETE RESTRICT,
 CHECK(applied_revision IS NULL OR (applied_revision>=1 AND applied_revision<=offered_revision))
);
