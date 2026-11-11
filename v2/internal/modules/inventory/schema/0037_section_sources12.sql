-- R-027 (решение пользователя 1А): последняя попытка раздела профиля 1.2 по КАЖДОМУ источнику актива.
-- Статус раздела в карточке — лучший среди источников, прочие показываются подсказкой.
-- record_section_state12 (последняя попытка любого источника) не меняется. Применённые миграции 0000–0036 не менялись.
CREATE TABLE inventory.record_section_source_state12 (
 tenant_id uuid NOT NULL,
 asset_uid uuid NOT NULL,
 section_name text NOT NULL,
 source_id uuid NOT NULL,
 last_attempt_id uuid NOT NULL,
 last_status text NOT NULL CHECK (last_status IN ('partial','unavailable','unsupported','not_requested')),
 collected_at timestamptz NOT NULL,
 PRIMARY KEY (tenant_id,asset_uid,section_name,source_id),
 FOREIGN KEY (tenant_id,asset_uid) REFERENCES assets.assets(tenant_id,asset_uid),
 FOREIGN KEY (tenant_id,last_attempt_id,section_name)
  REFERENCES inventory.observation_sections(tenant_id,observation_id,section_name)
);

-- Перенос уже известных попыток (по одной на раздел); остальные источники появятся со следующим наблюдением.
INSERT INTO inventory.record_section_source_state12(tenant_id,asset_uid,section_name,source_id,last_attempt_id,last_status,collected_at)
SELECT r.tenant_id,r.asset_uid,r.section_name,o.source_id,r.last_attempt_id,r.last_status,s.collected_at
FROM inventory.record_section_state12 r
JOIN inventory.observations o ON o.tenant_id=r.tenant_id AND o.observation_id=r.last_attempt_id
JOIN inventory.observation_sections s ON s.tenant_id=r.tenant_id AND s.observation_id=r.last_attempt_id AND s.section_name=r.section_name;
