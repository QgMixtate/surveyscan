-- Owner: sources; C51.03: цели SNMPv3 (сетевые устройства), которые собирает collector из Web. Отдельная платформа
-- инвентаризации network/snmp и способ сбора snmp; прежние значения не меняются.
ALTER TABLE sources.agents DROP CONSTRAINT agents_inventory_platform_check;
ALTER TABLE sources.agents ADD CONSTRAINT agents_inventory_platform_check
 CHECK(inventory_platform IN ('windows/amd64','linux/amd64','network/snmp'));
ALTER TABLE sources.inventory_profile_progress12 DROP CONSTRAINT inventory_profile_progress12_policy_id_check;
ALTER TABLE sources.inventory_profile_progress12 ADD CONSTRAINT inventory_profile_progress12_policy_id_check
 CHECK(policy_id IN ('windows-amd64-partial-baseline-v1','linux-amd64-partial-baseline-v1','network-snmp-partial-baseline-v1'));
ALTER TABLE sources.agents DROP CONSTRAINT agents_acquisition_check;
ALTER TABLE sources.agents ADD CONSTRAINT agents_acquisition_check CHECK(acquisition IN ('agent','ssh','winrm','snmp'));
