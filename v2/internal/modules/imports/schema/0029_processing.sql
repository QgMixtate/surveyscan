-- Owner: imports. Token-fenced processing lease; data GC only with durable signed receipt.
ALTER TABLE imports.delivery_payloads ALTER COLUMN payload DROP NOT NULL;
ALTER TABLE imports.delivery_payloads ADD CONSTRAINT payload_gc_requires_receipt CHECK(payload IS NOT NULL OR receipt IS NOT NULL);
CREATE TABLE imports.processing_claims (
 tenant_id uuid NOT NULL,
 delivery_id uuid NOT NULL,
 owner uuid,
 lease_until timestamptz,
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts>=0),
 failures integer NOT NULL DEFAULT 0 CHECK(failures>=0),
 retry_at timestamptz,
 state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','processing','retry','dead_letter','completed')),
 failure_code text,
 PRIMARY KEY(tenant_id,delivery_id),
 FOREIGN KEY(tenant_id,delivery_id) REFERENCES imports.deliveries(tenant_id,delivery_id),
 CHECK((owner IS NULL)=(lease_until IS NULL))
);
ALTER TABLE imports.processing_claims ADD CONSTRAINT active_claim_has_owner CHECK((state='processing')=(owner IS NOT NULL));
CREATE INDEX pending_delivery_quota ON imports.delivery_payloads(tenant_id,principal_source) WHERE payload IS NOT NULL;
-- Старые завершённые C07 доставки также не должны бессрочно занимать staging budget.
-- Полные допустимые observations/conflicts и result ledger уже committed перед receipt.
UPDATE imports.delivery_payloads SET payload=NULL WHERE receipt IS NOT NULL;
