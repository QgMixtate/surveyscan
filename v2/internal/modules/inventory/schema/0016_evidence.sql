CREATE FUNCTION inventory.immutable_evidence() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'observation evidence is immutable' USING ERRCODE='23514'; END $$;
CREATE TRIGGER observation_immutable BEFORE UPDATE OR DELETE ON inventory.observations FOR EACH ROW EXECUTE FUNCTION inventory.immutable_evidence();
CREATE TRIGGER observation_section_immutable BEFORE UPDATE OR DELETE ON inventory.observation_sections FOR EACH ROW EXECUTE FUNCTION inventory.immutable_evidence();
CREATE FUNCTION inventory.check_active_fact_link() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM inventory.current_facts f JOIN assets.observation_links l ON l.tenant_id=f.tenant_id AND l.link_id=f.link_id WHERE f.tenant_id=NEW.tenant_id AND f.link_id=NEW.link_id AND l.valid_to IS NOT NULL) THEN RAISE EXCEPTION 'current fact requires active observation assignment' USING ERRCODE='23514'; END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER current_fact_link_guard AFTER INSERT OR UPDATE ON inventory.current_facts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION inventory.check_active_fact_link();
CREATE CONSTRAINT TRIGGER observation_link_projection_guard AFTER UPDATE ON assets.observation_links DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION inventory.check_active_fact_link();
