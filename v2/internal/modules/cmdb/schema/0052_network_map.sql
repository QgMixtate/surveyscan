-- Owner: cmdb; C22.04 — редактируемая схема сети: ручная раскладка, устройства, связи, группы, подписи и
-- переопределения типов поверх наблюдаемой схемы L3. Один общий документ на тенант; правки — с ревизией и аудитом.
CREATE TABLE cmdb.network_maps (
 tenant_id uuid NOT NULL,
 map_name text NOT NULL DEFAULT 'main' CHECK (map_name = 'main'),
 document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object' AND octet_length(document::text) <= 1048576),
 revision platform.uint64 NOT NULL DEFAULT 1,
 updated_at timestamptz NOT NULL DEFAULT now(),
 updated_by uuid NOT NULL,
 PRIMARY KEY (tenant_id, map_name),
 FOREIGN KEY (tenant_id) REFERENCES access.tenants(tenant_id) ON DELETE RESTRICT
);
