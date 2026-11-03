-- C06: сохранённый результат, приоритет policy и время отдельной секции.
ALTER TABLE inventory.section_state ADD COLUMN clock_uncertain boolean NOT NULL DEFAULT false;
ALTER TABLE inventory.observations ADD COLUMN source_priority integer NOT NULL DEFAULT 1;
ALTER TABLE inventory.observation_sections ADD COLUMN collected_at timestamptz NOT NULL DEFAULT now();
CREATE TABLE inventory.observation_results (
 tenant_id uuid NOT NULL, observation_id uuid NOT NULL, asset_uid uuid,
 disposition text NOT NULL CHECK(disposition IN ('applied','recorded_pending_resolution')), reason_code text NOT NULL,
 PRIMARY KEY(tenant_id,observation_id),
 FOREIGN KEY(tenant_id,observation_id) REFERENCES inventory.observations(tenant_id,observation_id),
 FOREIGN KEY(tenant_id,asset_uid) REFERENCES assets.assets(tenant_id,asset_uid)
);
CREATE TRIGGER observation_result_immutable BEFORE UPDATE OR DELETE ON inventory.observation_results FOR EACH ROW EXECUTE FUNCTION inventory.immutable_evidence();

ALTER TABLE inventory.observations ADD COLUMN transaction_id xid8 NOT NULL DEFAULT pg_current_xact_id();
CREATE FUNCTION inventory.check_observation_commit() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM inventory.observation_results WHERE tenant_id=NEW.tenant_id AND observation_id=NEW.observation_id)
 OR NOT EXISTS(SELECT 1 FROM messaging.outbox_events WHERE tenant_id=NEW.tenant_id AND aggregate_type='observation' AND aggregate_id=NEW.observation_id AND transaction_id=pg_current_xact_id())
 OR NOT EXISTS(SELECT 1 FROM audit.audit_events WHERE tenant_id=NEW.tenant_id AND object_type='observation' AND object_id=NEW.observation_id::text AND transaction_id=pg_current_xact_id())
 THEN RAISE EXCEPTION 'observation requires result, outbox and audit' USING ERRCODE='23514';END IF;RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER observation_commit_guard AFTER INSERT ON inventory.observations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION inventory.check_observation_commit();
CREATE FUNCTION inventory.section_insert_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM inventory.observations WHERE tenant_id=NEW.tenant_id AND observation_id=NEW.observation_id AND transaction_id=pg_current_xact_id()) THEN RAISE EXCEPTION 'section must be inserted with immutable observation' USING ERRCODE='23514';END IF;RETURN NEW;
END $$;
CREATE TRIGGER section_parent_transaction BEFORE INSERT ON inventory.observation_sections FOR EACH ROW EXECUTE FUNCTION inventory.section_insert_guard();
