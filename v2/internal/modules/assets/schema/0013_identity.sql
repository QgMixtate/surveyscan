CREATE FUNCTION assets.immutable_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'asset identity cannot be deleted' USING ERRCODE='23514'; END IF;
 IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.asset_uid IS DISTINCT FROM OLD.asset_uid THEN RAISE EXCEPTION 'asset identity is immutable' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER asset_identity_guard BEFORE UPDATE OR DELETE ON assets.assets FOR EACH ROW EXECUTE FUNCTION assets.immutable_identity();
CREATE FUNCTION assets.conflict_candidates_scoped() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM unnest(NEW.candidate_asset_uids) AS candidate(id) WHERE NOT EXISTS(SELECT 1 FROM assets.assets a WHERE a.tenant_id=NEW.tenant_id AND a.asset_uid=candidate.id)) THEN RAISE EXCEPTION 'candidate asset outside tenant' USING ERRCODE='23503'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER conflict_candidate_guard BEFORE INSERT OR UPDATE ON assets.reconciliation_conflicts FOR EACH ROW EXECUTE FUNCTION assets.conflict_candidates_scoped();
