-- C07: scoped одноразовые grants, metadata mTLS и shared enrollment rate limit.
CREATE TABLE sources.enrollment_grants (
 grant_id uuid PRIMARY KEY, tenant_id uuid NOT NULL, source_id uuid NOT NULL,
 token_hash text NOT NULL UNIQUE CHECK(token_hash ~ '^[0-9a-f]{64}$'),
 csr_sha256 text NOT NULL CHECK(csr_sha256 ~ '^[0-9a-f]{64}$'),
 public_key bytea NOT NULL CHECK(octet_length(public_key)=32),
 scope_id uuid NOT NULL, signing_key_id uuid NOT NULL,
 collector_id uuid, expires_at timestamptz NOT NULL, result jsonb,
 FOREIGN KEY(tenant_id,source_id) REFERENCES sources.sources(tenant_id,source_id),
 FOREIGN KEY(tenant_id,scope_id) REFERENCES scope.network_scopes(tenant_id,scope_id),
 FOREIGN KEY(tenant_id,collector_id) REFERENCES sources.collectors(tenant_id,collector_id)
);
CREATE TABLE sources.machine_identities (
 fingerprint text PRIMARY KEY CHECK(fingerprint ~ '^[0-9a-f]{64}$'),
 tenant_id uuid NOT NULL, source_id uuid NOT NULL, generation_id uuid NOT NULL,
 expires_at timestamptz NOT NULL, revoked boolean NOT NULL DEFAULT false,
 FOREIGN KEY(tenant_id,source_id) REFERENCES sources.sources(tenant_id,source_id)
);
CREATE TABLE sources.enrollment_buckets(bucket text PRIMARY KEY,window_id bigint NOT NULL,attempts integer NOT NULL);
