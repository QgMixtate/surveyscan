-- C06: независимый durable consumer; не индекс полнотекстового поиска.
CREATE TABLE assets.consumer_versions (
 tenant_id uuid NOT NULL, asset_uid uuid NOT NULL, aggregate_version platform.uint64 NOT NULL,
 PRIMARY KEY(tenant_id,asset_uid), FOREIGN KEY(tenant_id,asset_uid) REFERENCES assets.assets(tenant_id,asset_uid)
);
