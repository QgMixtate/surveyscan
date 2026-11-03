-- Owner: responsibility; C02 logical baseline refined by C03 signed payload.
CREATE SCHEMA IF NOT EXISTS responsibility;

CREATE TABLE responsibility.subjects (
    tenant_id uuid NOT NULL,
    subject_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('team','person')),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 512),
    contact text NOT NULL CHECK (length(contact) BETWEEN 1 AND 512),
    active boolean NOT NULL DEFAULT true,
    revision platform.uint64 NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id,subject_id),
    FOREIGN KEY (tenant_id) REFERENCES access.tenants (tenant_id) ON DELETE RESTRICT,
    CHECK (kind <> 'team' OR length(contact)>0)
);
