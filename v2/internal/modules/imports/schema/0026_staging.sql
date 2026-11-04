-- C07: bounded staging, immutable digest/owner и durable signed result.
ALTER TABLE imports.import_checkpoints ADD COLUMN result jsonb;
CREATE TABLE imports.delivery_payloads (
 tenant_id uuid NOT NULL, delivery_id uuid NOT NULL, principal_source uuid NOT NULL, principal_generation uuid NOT NULL,
 payload bytea NOT NULL CHECK(octet_length(payload)<=1048576),
 digest text NOT NULL CHECK(encode(sha256(payload),'hex')=digest), receipt jsonb,
 PRIMARY KEY(tenant_id,delivery_id), FOREIGN KEY(tenant_id,delivery_id) REFERENCES imports.deliveries(tenant_id,delivery_id),
 FOREIGN KEY(tenant_id,principal_source) REFERENCES sources.sources(tenant_id,source_id)
);
