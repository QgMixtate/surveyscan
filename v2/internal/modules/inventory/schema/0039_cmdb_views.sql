-- Owner: inventory; C26.02 — нормализованные представления над проекцией 1.2 (record_facts12): установки ПО и
-- компоненты. Представления, а не копии: всегда согласованы с проекцией (приём, пересборка C25.03), фильтруемые
-- поля вынесены в столбцы, остальное — в record_facts12 (JSONB). Поиск ПО по имени — индекс по выражению.
CREATE INDEX record_facts12_software_name ON inventory.record_facts12 (tenant_id, lower(value #>> '{}'))
 WHERE section_name='software' AND field_name IN ('name','display_name');

CREATE VIEW inventory.software_installations12 AS
SELECT tenant_id, asset_uid, record_key,
 COALESCE(max(value #>> '{}') FILTER (WHERE field_name='display_name'), max(value #>> '{}') FILTER (WHERE field_name='name')) AS name,
 max(value #>> '{}') FILTER (WHERE field_name='version') AS version,
 COALESCE(max(value #>> '{}') FILTER (WHERE field_name='publisher'), max(value #>> '{}') FILTER (WHERE field_name='vendor')) AS publisher,
 max(value #>> '{}') FILTER (WHERE field_name='architecture') AS architecture,
 max(value #>> '{}') FILTER (WHERE field_name='source') AS package_source,
 (array_agg(observation_id ORDER BY field_name='name' DESC, field_name='display_name' DESC))[1] AS observation_id
FROM inventory.record_facts12 WHERE section_name='software'
GROUP BY tenant_id, asset_uid, record_key;

CREATE VIEW inventory.components12 AS
SELECT tenant_id, asset_uid, section_name, record_key,
 max(value #>> '{}') FILTER (WHERE field_name='kind') AS kind,
 max(value #>> '{}') FILTER (WHERE field_name='name') AS name,
 max(value #>> '{}') FILTER (WHERE field_name='vendor') AS vendor,
 max(value #>> '{}') FILTER (WHERE field_name='model') AS model,
 max(value #>> '{}') FILTER (WHERE field_name='serial') AS serial,
 COALESCE(max(value #>> '{}') FILTER (WHERE field_name='bytes'), max(value #>> '{}') FILTER (WHERE field_name='size_bytes')) AS size_bytes,
 (array_agg(observation_id ORDER BY field_name='name' DESC))[1] AS observation_id
FROM inventory.record_facts12 WHERE section_name IN ('hardware','resources')
GROUP BY tenant_id, asset_uid, section_name, record_key;
