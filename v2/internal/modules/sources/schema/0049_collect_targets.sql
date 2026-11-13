-- Owner: sources; C51.03 (D-13, решение 2026-11-13 «через центр»): учётки сбора и цели удалённого сбора из Web.
-- Секреты учёток (пароль, ключ, ключи SNMPv3) — только в хранилище секретов (OpenBao KV), здесь — описание без секрета.
CREATE TABLE sources.collect_credentials (
 tenant_id uuid NOT NULL,
 credential_id uuid NOT NULL,
 name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
 kind text NOT NULL CHECK (kind IN ('ssh','winrm','snmp')),
 username text NOT NULL CHECK (length(username) BETWEEN 1 AND 256),
 active boolean NOT NULL DEFAULT true,
 revision platform.uint64 NOT NULL DEFAULT 1,
 secret_changed_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (tenant_id, credential_id),
 UNIQUE (tenant_id, credential_id, kind),
 FOREIGN KEY (tenant_id) REFERENCES access.tenants (tenant_id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX collect_credential_name ON sources.collect_credentials (tenant_id, lower(name)) WHERE active;

-- Цель сбора: узел, способ, учётка и collector. Для каждой цели центр сам регистрирует отдельный источник-агент
-- (agent_source_id), от имени которого collector подписывает данные узла: сведение активов и защита от клонов — как
-- у обычного агента.
CREATE TABLE sources.remote_targets (
 tenant_id uuid NOT NULL,
 target_id uuid NOT NULL,
 collector_id uuid NOT NULL,
 collector_kind text NOT NULL DEFAULT 'collector' CHECK (collector_kind = 'collector'),
 network_id uuid,
 address inet NOT NULL CHECK (family(address) = 4),
 kind text NOT NULL CHECK (kind IN ('ssh','winrm','snmp')),
 port int NOT NULL CHECK (port BETWEEN 1 AND 65535),
 credential_id uuid NOT NULL,
 host_key_sha256 text CHECK (host_key_sha256 ~ '^SHA256:[A-Za-z0-9+/]{43}$'),
 tls_ca_pem text CHECK (length(tls_ca_pem) <= 16384),
 tls_server_name text CHECK (length(tls_server_name) BETWEEN 1 AND 253),
 interval_seconds int NOT NULL DEFAULT 3600 CHECK (interval_seconds BETWEEN 300 AND 86400),
 agent_source_id uuid,
 state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','active','disabled')),
 last_collected_at timestamptz,
 last_error text CHECK (length(last_error) <= 128),
 revision platform.uint64 NOT NULL DEFAULT 1,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (tenant_id, target_id),
 CHECK (kind <> 'ssh' OR host_key_sha256 IS NOT NULL),
 CHECK (kind <> 'winrm' OR (tls_ca_pem IS NOT NULL AND tls_server_name IS NOT NULL)),
 FOREIGN KEY (tenant_id, collector_id, collector_kind) REFERENCES sources.sources (tenant_id, source_id, source_kind) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id, credential_id, kind) REFERENCES sources.collect_credentials (tenant_id, credential_id, kind) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id, network_id) REFERENCES sources.discovery_networks (tenant_id, network_id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX remote_target_once ON sources.remote_targets (tenant_id, address, kind) WHERE state <> 'disabled';
