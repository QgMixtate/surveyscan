-- C06: доменная запись без history/outbox/audit не может завершить commit.
ALTER TABLE assets.asset_changes ADD COLUMN transaction_id xid8 NOT NULL DEFAULT pg_current_xact_id();
CREATE FUNCTION assets.check_commit() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE tid uuid; aid uuid; ver numeric;
BEGIN
 IF TG_OP='DELETE' THEN tid:=OLD.tenant_id;aid:=OLD.asset_uid;ELSE tid:=NEW.tenant_id;aid:=NEW.asset_uid;END IF;
 IF TG_TABLE_NAME='assets' THEN ver:=NEW.aggregate_version;ELSE SELECT aggregate_version INTO ver FROM assets.assets WHERE tenant_id=tid AND asset_uid=aid;END IF;
 IF NOT EXISTS(SELECT 1 FROM assets.asset_changes WHERE tenant_id=tid AND asset_uid=aid AND aggregate_version=ver AND transaction_id=pg_current_xact_id())
 OR NOT EXISTS(SELECT 1 FROM messaging.outbox_events WHERE tenant_id=tid AND aggregate_type='asset' AND aggregate_id=aid AND aggregate_version=ver AND transaction_id=pg_current_xact_id())
 OR NOT EXISTS(SELECT 1 FROM audit.audit_events WHERE tenant_id=tid AND object_type='asset' AND object_id=aid::text AND transaction_id=pg_current_xact_id())
 THEN RAISE EXCEPTION 'asset mutation requires history, outbox and audit in the same transaction' USING ERRCODE='23514';END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER asset_commit_guard AFTER INSERT OR UPDATE ON assets.assets DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION assets.check_commit();
CREATE CONSTRAINT TRIGGER business_commit_guard AFTER INSERT OR UPDATE ON assets.asset_business_fields DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION assets.check_commit();
CREATE CONSTRAINT TRIGGER facts_commit_guard AFTER INSERT OR UPDATE OR DELETE ON inventory.current_facts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION assets.check_commit();
