-- Owner: sources. Cert renewal имеет отдельный challenge и неизменяемый result ledger.
CREATE TABLE sources.renewal_challenges (
 tenant_id uuid NOT NULL,
 source_id uuid NOT NULL,
 generation_id uuid NOT NULL,
 challenge_id uuid NOT NULL,
 nonce text NOT NULL,
 issued_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 consumed boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,source_id,generation_id),
 FOREIGN KEY(tenant_id,source_id) REFERENCES sources.sources(tenant_id,source_id) ON DELETE RESTRICT,
 CHECK(expires_at>issued_at)
);
CREATE TABLE sources.renewal_receipts (
 tenant_id uuid NOT NULL,
 renewal_id uuid NOT NULL,
 source_id uuid NOT NULL,
 generation_id uuid NOT NULL,
 digest text NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$'),
 key_id uuid NOT NULL,
 result jsonb NOT NULL,
 PRIMARY KEY(tenant_id,renewal_id),
 FOREIGN KEY(tenant_id,source_id) REFERENCES sources.sources(tenant_id,source_id) ON DELETE RESTRICT
);
