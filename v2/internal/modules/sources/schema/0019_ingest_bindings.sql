-- C06: явная привязка ключа/namespace/scope; не публичная процедура enrollment.
CREATE TABLE sources.ingest_bindings (
 tenant_id uuid NOT NULL, source_id uuid NOT NULL, generation_id uuid NOT NULL, key_id uuid NOT NULL,
 namespace text NOT NULL, scope_id uuid NOT NULL, public_key bytea NOT NULL CHECK(octet_length(public_key)=32),
 priority integer NOT NULL DEFAULT 1 CHECK(priority BETWEEN 1 AND 100), active boolean NOT NULL DEFAULT true,
 PRIMARY KEY(tenant_id,source_id,generation_id,key_id,namespace,scope_id),
 FOREIGN KEY(tenant_id,source_id) REFERENCES sources.sources(tenant_id,source_id),
 FOREIGN KEY(tenant_id,scope_id) REFERENCES scope.network_scopes(tenant_id,scope_id)
);
