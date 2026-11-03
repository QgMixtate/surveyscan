-- Owner: access; C02 logical baseline refined by C03 signed payload.
CREATE SCHEMA IF NOT EXISTS access;

CREATE TABLE access.tenants (
    tenant_id uuid NOT NULL,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 512),
    status text NOT NULL CHECK (status IN ('active','disabled')),
    revision platform.uint64 NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id)
);
