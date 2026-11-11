-- Owner: cmdb; C26.02 — бизнес-сервисы (CI без актива, ручной ввод) и типизированные связи между CI (CM-01…CM-04).
CREATE SCHEMA IF NOT EXISTS cmdb;

CREATE TABLE cmdb.services (
 tenant_id uuid NOT NULL,
 service_uid uuid NOT NULL,
 name text NOT NULL CHECK (length(name) BETWEEN 1 AND 256),
 description text CHECK (length(description) <= 4096),
 criticality text NOT NULL DEFAULT 'unknown' CHECK (criticality IN ('unknown','low','medium','high','critical')),
 revision platform.uint64 NOT NULL DEFAULT 1,
 created_at timestamptz NOT NULL DEFAULT now(),
 retired_at timestamptz,
 PRIMARY KEY (tenant_id, service_uid),
 UNIQUE (service_uid),
 FOREIGN KEY (tenant_id) REFERENCES access.tenants(tenant_id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX service_active_name ON cmdb.services (tenant_id, lower(name)) WHERE retired_at IS NULL;

-- Конец связи — ровно один из (актив, сервис), оба в том же тенанте (FK по tenant_id): межтенантная связь невозможна.
CREATE TABLE cmdb.relations (
 tenant_id uuid NOT NULL,
 relation_id uuid NOT NULL,
 relation_type text NOT NULL CHECK (relation_type IN ('runs_on','uses','depends_on','hosts','connected_to')),
 from_asset_uid uuid, from_service_uid uuid,
 to_asset_uid uuid, to_service_uid uuid,
 origin text NOT NULL CHECK (origin IN ('manual','observed')),
 confidence text NOT NULL CHECK (confidence IN ('confirmed','probable','weak')),
 note text CHECK (length(note) <= 1024),
 valid_from timestamptz NOT NULL DEFAULT now(),
 valid_to timestamptz,
 actor_ref text NOT NULL,
 PRIMARY KEY (tenant_id, relation_id),
 FOREIGN KEY (tenant_id, from_asset_uid) REFERENCES assets.assets(tenant_id, asset_uid) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id, to_asset_uid) REFERENCES assets.assets(tenant_id, asset_uid) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id, from_service_uid) REFERENCES cmdb.services(tenant_id, service_uid) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id, to_service_uid) REFERENCES cmdb.services(tenant_id, service_uid) ON DELETE RESTRICT,
 CHECK ((from_asset_uid IS NULL) <> (from_service_uid IS NULL) AND (to_asset_uid IS NULL) <> (to_service_uid IS NULL)),
 CHECK (from_asset_uid IS DISTINCT FROM to_asset_uid OR from_asset_uid IS NULL),
 CHECK (from_service_uid IS DISTINCT FROM to_service_uid OR from_service_uid IS NULL),
 CHECK (valid_to IS NULL OR valid_to >= valid_from)
);
CREATE UNIQUE INDEX relation_active_edge ON cmdb.relations (tenant_id, relation_type,
 COALESCE(from_asset_uid, from_service_uid), COALESCE(to_asset_uid, to_service_uid)) WHERE valid_to IS NULL;
CREATE INDEX relation_from_asset ON cmdb.relations (tenant_id, from_asset_uid) WHERE from_asset_uid IS NOT NULL;
CREATE INDEX relation_to_asset ON cmdb.relations (tenant_id, to_asset_uid) WHERE to_asset_uid IS NOT NULL;
CREATE INDEX relation_from_service ON cmdb.relations (tenant_id, from_service_uid) WHERE from_service_uid IS NOT NULL;
CREATE INDEX relation_to_service ON cmdb.relations (tenant_id, to_service_uid) WHERE to_service_uid IS NOT NULL;

-- История сервисов и связей (C03 заморожен: собственный журнал модуля, плюс аудит в той же транзакции).
CREATE TABLE cmdb.changes (
 tenant_id uuid NOT NULL,
 change_id uuid NOT NULL,
 object_type text NOT NULL CHECK (object_type IN ('service','relation')),
 object_id uuid NOT NULL,
 action text NOT NULL CHECK (action IN ('created','updated','retired','retargeted')),
 detail jsonb NOT NULL DEFAULT '{}'::jsonb,
 actor_ref text NOT NULL,
 occurred_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (tenant_id, change_id)
);
CREATE INDEX cmdb_changes_object ON cmdb.changes (tenant_id, object_id, occurred_at);
