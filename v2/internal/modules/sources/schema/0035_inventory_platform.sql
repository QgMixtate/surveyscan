-- Платформа инвентаризации агента фиксируется при регистрации (grant) и сверяется при запросе профиля 1.2.
-- Старые агенты — Windows (прежнее поведение); применённые миграции 0000–0034 не менялись.
ALTER TABLE sources.agents ADD COLUMN inventory_platform text NOT NULL DEFAULT 'windows/amd64'
 CHECK(inventory_platform IN ('windows/amd64','linux/amd64'));
-- Политика прогресса профиля теперь допускает обе платформы (имя ограничения создано автоматически в 0034).
ALTER TABLE sources.inventory_profile_progress12 DROP CONSTRAINT inventory_profile_progress12_policy_id_check;
ALTER TABLE sources.inventory_profile_progress12 ADD CONSTRAINT inventory_profile_progress12_policy_id_check
 CHECK(policy_id IN ('windows-amd64-partial-baseline-v1','linux-amd64-partial-baseline-v1'));
