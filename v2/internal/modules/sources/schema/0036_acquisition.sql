-- Способ получения данных источника-агента: сам агент на хосте ('agent') или удалённый сбор коллектором (ssh/winrm).
-- Фиксируется при регистрации (grant); старые источники — 'agent'. Применённые миграции 0000–0035 не менялись.
ALTER TABLE sources.agents ADD COLUMN acquisition text NOT NULL DEFAULT 'agent'
 CHECK(acquisition IN ('agent','ssh','winrm'));
