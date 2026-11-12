-- Owner: responsibility; C31.02 (ADR decisions/C31-integrations.md) — оргструктура из Active Directory (только чтение).
-- Субъект из каталога: origin='ldap', external_id = objectGUID (неизменяемый), synced_at — последняя синхронизация.
-- Мастер таких субъектов — AD: вручную их не переименовывают, не отключают и не меняют состав их команд.
ALTER TABLE responsibility.subjects DROP CONSTRAINT subjects_origin_check;
ALTER TABLE responsibility.subjects ADD CONSTRAINT subjects_origin_check CHECK (origin IN ('local','ldap'));
ALTER TABLE responsibility.subjects ADD COLUMN external_id text CHECK (length(external_id) BETWEEN 1 AND 128),
 ADD COLUMN synced_at timestamptz;
ALTER TABLE responsibility.subjects ADD CONSTRAINT subject_external CHECK ((origin='local') = (external_id IS NULL));
CREATE UNIQUE INDEX subject_external_id ON responsibility.subjects(tenant_id,origin,external_id) WHERE external_id IS NOT NULL;

CREATE TABLE responsibility.directory_sync_runs (
 tenant_id uuid NOT NULL,
 run_id uuid NOT NULL,
 mode text NOT NULL CHECK (mode IN ('full','incremental')),
 started_at timestamptz NOT NULL,
 finished_at timestamptz NOT NULL,
 status text NOT NULL CHECK (status IN ('succeeded','failed')),
 counters jsonb NOT NULL DEFAULT '{}'::jsonb,
 error text CHECK (length(error) <= 1024),
 PRIMARY KEY (tenant_id,run_id),
 FOREIGN KEY (tenant_id) REFERENCES access.tenants(tenant_id) ON DELETE RESTRICT
);
CREATE INDEX directory_sync_recent ON responsibility.directory_sync_runs(tenant_id,started_at DESC);
