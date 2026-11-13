-- Owner: sources; C51 (ADR decisions/D13-discovery-policy.md): обследования сети, заводимые в Web.
-- Подсеть заводит администратор (CIDR IPv4 не шире /22, площадка, collector, пробы); запускает оператор вручную или
-- по расписанию (не чаще раза в час); collector забирает задание по машинному каналу C51 и сдаёт подписанный результат.
CREATE TABLE sources.discovery_networks (
 tenant_id uuid NOT NULL,
 network_id uuid NOT NULL,
 site_id uuid NOT NULL,
 collector_id uuid NOT NULL,
 collector_kind text NOT NULL DEFAULT 'collector' CHECK (collector_kind = 'collector'),
 name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
 cidr cidr NOT NULL CHECK (family(cidr) = 4 AND masklen(cidr) BETWEEN 22 AND 32),
 probes text[] NOT NULL CHECK (cardinality(probes) BETWEEN 1 AND 3 AND probes <@ ARRAY['tcp','arp','icmp']),
 schedule_minutes int CHECK (schedule_minutes IS NULL OR schedule_minutes BETWEEN 60 AND 10080),
 active boolean NOT NULL DEFAULT true,
 revision platform.uint64 NOT NULL DEFAULT 1,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (tenant_id, network_id),
 FOREIGN KEY (tenant_id, collector_id, collector_kind) REFERENCES sources.sources (tenant_id, source_id, source_kind) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id, site_id) REFERENCES scope.sites (tenant_id, site_id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX discovery_network_cidr ON sources.discovery_networks (tenant_id, cidr) WHERE active;

CREATE TABLE sources.discovery_runs (
 tenant_id uuid NOT NULL,
 run_id uuid NOT NULL,
 network_id uuid NOT NULL,
 trigger text NOT NULL CHECK (trigger IN ('manual','schedule')),
 requested_by text NOT NULL,
 requested_at timestamptz NOT NULL DEFAULT now(),
 state text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','running','done','failed')),
 claimed_at timestamptz,
 finished_at timestamptz,
 addresses int CHECK (addresses >= 0),
 found int CHECK (found >= 0),
 new_hosts int CHECK (new_hosts >= 0),
 missing int CHECK (missing >= 0),
 errors text[] NOT NULL DEFAULT '{}',
 PRIMARY KEY (tenant_id, run_id),
 FOREIGN KEY (tenant_id, network_id) REFERENCES sources.discovery_networks (tenant_id, network_id) ON DELETE RESTRICT
);
-- одно незавершённое обследование на подсеть
CREATE UNIQUE INDEX discovery_run_open ON sources.discovery_runs (tenant_id, network_id) WHERE state IN ('queued','running');
CREATE INDEX discovery_run_recent ON sources.discovery_runs (tenant_id, network_id, requested_at DESC);

-- Найденные узлы подсети (presence: present → missing после пропуска в обследовании; вернулся — снова present).
CREATE TABLE sources.discovery_hosts (
 tenant_id uuid NOT NULL,
 network_id uuid NOT NULL,
 ip inet NOT NULL,
 mac text CHECK (mac ~ '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$'),
 ports int[] NOT NULL DEFAULT '{}',
 icmp boolean NOT NULL DEFAULT false,
 first_seen timestamptz NOT NULL,
 last_seen timestamptz NOT NULL,
 last_run_id uuid NOT NULL,
 state text NOT NULL CHECK (state IN ('present','missing')),
 PRIMARY KEY (tenant_id, network_id, ip),
 FOREIGN KEY (tenant_id, network_id) REFERENCES sources.discovery_networks (tenant_id, network_id) ON DELETE RESTRICT
);
