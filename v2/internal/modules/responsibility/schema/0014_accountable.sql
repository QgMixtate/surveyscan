-- Intentional cross-owner integrity reads; see C02 transaction boundaries.
CREATE FUNCTION responsibility.check_accountable() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE tid uuid; aid uuid; total integer;
BEGIN
 IF TG_OP='DELETE' THEN tid:=OLD.tenant_id; aid:=OLD.asset_uid; ELSE tid:=NEW.tenant_id; aid:=NEW.asset_uid; END IF;
 PERFORM 1 FROM assets.assets WHERE tenant_id=tid AND asset_uid=aid FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT count(*) INTO total FROM responsibility.responsibility_assignments ra JOIN responsibility.subjects s ON s.tenant_id=ra.tenant_id AND s.subject_id=ra.subject_id
 WHERE ra.tenant_id=tid AND ra.asset_uid=aid AND ra.role='accountable' AND ra.valid_to IS NULL AND s.active;
 IF total<>1 THEN RAISE EXCEPTION 'asset requires one active accountable assignment' USING ERRCODE='23514'; END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER asset_requires_accountable AFTER INSERT OR UPDATE ON assets.assets DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION responsibility.check_accountable();
CREATE CONSTRAINT TRIGGER accountable_assignment_guard AFTER INSERT OR UPDATE OR DELETE ON responsibility.responsibility_assignments DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION responsibility.check_accountable();
CREATE FUNCTION responsibility.assignment_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.asset_uid IS DISTINCT FROM OLD.asset_uid THEN RAISE EXCEPTION 'assignment asset binding is immutable' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER assignment_identity_guard BEFORE UPDATE ON responsibility.responsibility_assignments FOR EACH ROW EXECUTE FUNCTION responsibility.assignment_identity();
CREATE FUNCTION responsibility.check_subject_active() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT NEW.active AND (EXISTS(SELECT 1 FROM scope.sites s WHERE s.tenant_id=NEW.tenant_id AND s.fallback_subject_id=NEW.subject_id)
 OR EXISTS(SELECT 1 FROM responsibility.responsibility_assignments a WHERE a.tenant_id=NEW.tenant_id AND a.subject_id=NEW.subject_id AND a.valid_to IS NULL)) THEN RAISE EXCEPTION 'active assignments or fallback require active subject' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER subject_active_guard BEFORE UPDATE ON responsibility.subjects FOR EACH ROW EXECUTE FUNCTION responsibility.check_subject_active();
