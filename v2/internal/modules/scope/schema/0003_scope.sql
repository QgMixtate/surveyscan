-- Owner: scope; C02 logical baseline refined by C03 signed payload.
CREATE SCHEMA IF NOT EXISTS scope;

CREATE TABLE scope.sites (
    tenant_id uuid NOT NULL,
    site_id uuid NOT NULL,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 512),
    fallback_subject_id uuid NOT NULL,
    revision platform.uint64 NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id,site_id),
    FOREIGN KEY (tenant_id) REFERENCES access.tenants (tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id,fallback_subject_id) REFERENCES responsibility.subjects (tenant_id,subject_id) ON DELETE RESTRICT
);

CREATE TABLE scope.network_scopes (
    tenant_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    namespace text NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    revision platform.uint64 NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id,scope_id),
    UNIQUE (tenant_id,site_id,namespace),
    UNIQUE (tenant_id,scope_id,site_id),
    FOREIGN KEY (tenant_id,site_id) REFERENCES scope.sites (tenant_id,site_id) ON DELETE RESTRICT
);
