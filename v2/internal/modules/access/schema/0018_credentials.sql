-- C05: access owns user credentials, not target/device secrets.
CREATE TABLE access.users (
 user_id uuid PRIMARY KEY,
 tenant_id uuid NOT NULL REFERENCES access.tenants(tenant_id),
 username text NOT NULL UNIQUE CHECK(username ~ '^[a-z0-9_.@-]{1,128}$'),
 password_salt bytea NOT NULL CHECK(octet_length(password_salt)=16),
 password_hash bytea NOT NULL CHECK(octet_length(password_hash)=32),
 password_algorithm text NOT NULL DEFAULT 'argon2id-m65536-t3-p1-v19' CHECK(password_algorithm='argon2id-m65536-t3-p1-v19'),
 role text NOT NULL CHECK(role IN ('admin','operator','viewer')),
 enabled boolean NOT NULL DEFAULT true,
 revision platform.uint64 NOT NULL DEFAULT 1,
 UNIQUE(tenant_id,user_id)
);
CREATE TABLE access.bootstrap_state (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 tenant_id uuid NOT NULL,
 user_id uuid NOT NULL,
 FOREIGN KEY(tenant_id,user_id) REFERENCES access.users(tenant_id,user_id)
);
CREATE TABLE access.credentials (
 credential_id uuid PRIMARY KEY,
 tenant_id uuid NOT NULL,
 user_id uuid NOT NULL,
 user_revision platform.uint64 NOT NULL,
 kind text NOT NULL CHECK(kind IN ('session','cli')),
 secret_hash text NOT NULL UNIQUE CHECK(secret_hash ~ '^[0-9a-f]{64}$'),
 csrf_hash text CHECK(csrf_hash ~ '^[0-9a-f]{64}$'),
 name text NOT NULL CHECK(length(name) BETWEEN 1 AND 128),
 scopes text[] NOT NULL DEFAULT '{}',
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL,
 revoked_at timestamptz,
 FOREIGN KEY(tenant_id,user_id) REFERENCES access.users(tenant_id,user_id),
 CHECK(expires_at>created_at),
 CHECK((kind='session' AND csrf_hash IS NOT NULL AND cardinality(scopes)=0) OR (kind='cli' AND csrf_hash IS NULL AND cardinality(scopes) BETWEEN 1 AND 2 AND scopes <@ ARRAY['assets:read','sources:read']::text[]))
);
CREATE INDEX credentials_user ON access.credentials(tenant_id,user_id);
CREATE TABLE access.login_buckets(bucket text PRIMARY KEY,window_id bigint NOT NULL,attempts integer NOT NULL);
CREATE TABLE access.security_events (
 event_id uuid PRIMARY KEY,
 tenant_id uuid NOT NULL REFERENCES access.tenants(tenant_id),
 user_id uuid NOT NULL,
 action text NOT NULL,
 object_id uuid NOT NULL,
 occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,user_id) REFERENCES access.users(tenant_id,user_id)
);
