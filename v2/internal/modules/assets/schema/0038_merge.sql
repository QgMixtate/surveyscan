-- Owner: assets; C25.03 — слияние и разделение активов. asset_uid неизменен и не переиспользуется:
-- поглощённый актив остаётся строкой с merged_into (канонический UID), старые UID разрешаются переходом.
ALTER TABLE assets.assets ADD COLUMN merged_into uuid, ADD COLUMN merged_at timestamptz;
ALTER TABLE assets.assets ADD CONSTRAINT asset_merged_into FOREIGN KEY (tenant_id,merged_into) REFERENCES assets.assets(tenant_id,asset_uid) ON DELETE RESTRICT;
ALTER TABLE assets.assets ADD CONSTRAINT asset_merge_shape CHECK ((merged_into IS NULL)=(merged_at IS NULL) AND merged_into IS DISTINCT FROM asset_uid);

CREATE TABLE assets.asset_operations (
 tenant_id uuid NOT NULL,
 operation_id uuid NOT NULL,
 kind text NOT NULL CHECK (kind IN ('merge','split')),
 from_asset_uid uuid NOT NULL,
 to_asset_uid uuid NOT NULL,
 source_record_keys uuid[] NOT NULL,
 actor_ref text NOT NULL,
 occurred_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (tenant_id,operation_id),
 FOREIGN KEY (tenant_id,from_asset_uid) REFERENCES assets.assets(tenant_id,asset_uid) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id,to_asset_uid) REFERENCES assets.assets(tenant_id,asset_uid) ON DELETE RESTRICT,
 CHECK (from_asset_uid<>to_asset_uid AND cardinality(source_record_keys) <= 10000)
);
CREATE INDEX asset_operations_by_asset ON assets.asset_operations(tenant_id,from_asset_uid);
CREATE INDEX asset_operations_to_asset ON assets.asset_operations(tenant_id,to_asset_uid);

-- Слияние необратимо для UID: снять merged_into нельзя, а к поглощённому активу нельзя привязать запись или наблюдение.
CREATE FUNCTION assets.merge_final() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.merged_into IS NOT NULL AND (NEW.merged_into IS DISTINCT FROM OLD.merged_into OR NEW.merged_at IS DISTINCT FROM OLD.merged_at) THEN
  RAISE EXCEPTION 'merged asset is final' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER asset_merge_final BEFORE UPDATE ON assets.assets FOR EACH ROW EXECUTE FUNCTION assets.merge_final();
CREATE FUNCTION assets.not_merged_target() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.asset_uid IS NOT NULL AND EXISTS(SELECT 1 FROM assets.assets WHERE tenant_id=NEW.tenant_id AND asset_uid=NEW.asset_uid AND merged_into IS NOT NULL) THEN
  RAISE EXCEPTION 'asset is merged' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER source_record_not_merged BEFORE INSERT OR UPDATE OF asset_uid ON assets.source_records FOR EACH ROW EXECUTE FUNCTION assets.not_merged_target();
CREATE TRIGGER link_not_merged BEFORE INSERT ON assets.observation_links FOR EACH ROW EXECUTE FUNCTION assets.not_merged_target();
