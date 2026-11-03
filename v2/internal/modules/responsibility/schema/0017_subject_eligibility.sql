-- Serialize assignment creation against subject deactivation; preserve fallback team eligibility.
CREATE FUNCTION responsibility.assignment_subject_active() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE eligible boolean;
BEGIN
 IF NEW.valid_to IS NULL THEN
  SELECT active INTO eligible FROM responsibility.subjects WHERE tenant_id=NEW.tenant_id AND subject_id=NEW.subject_id FOR SHARE;
  IF eligible IS DISTINCT FROM true THEN RAISE EXCEPTION 'active assignment requires active subject' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER assignment_subject_guard BEFORE INSERT OR UPDATE ON responsibility.responsibility_assignments FOR EACH ROW EXECUTE FUNCTION responsibility.assignment_subject_active();
CREATE FUNCTION responsibility.fallback_team_kind() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.kind<>'team' AND EXISTS(SELECT 1 FROM scope.sites WHERE tenant_id=NEW.tenant_id AND fallback_subject_id=NEW.subject_id) THEN RAISE EXCEPTION 'fallback subject must remain a team' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER fallback_subject_kind_guard BEFORE UPDATE ON responsibility.subjects FOR EACH ROW EXECUTE FUNCTION responsibility.fallback_team_kind();
