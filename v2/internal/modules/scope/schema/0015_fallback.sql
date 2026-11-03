CREATE FUNCTION scope.check_fallback_active() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE eligible boolean;
BEGIN
 SELECT active AND kind='team' INTO eligible FROM responsibility.subjects WHERE tenant_id=NEW.tenant_id AND subject_id=NEW.fallback_subject_id FOR SHARE;
 IF eligible IS DISTINCT FROM true THEN RAISE EXCEPTION 'site requires active fallback team' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER site_fallback_guard BEFORE INSERT OR UPDATE ON scope.sites FOR EACH ROW EXECUTE FUNCTION scope.check_fallback_active();
