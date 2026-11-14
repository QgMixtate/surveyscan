-- Owner: sources; C51.03, замечание пользователя 2026-11-14: отпечаток ключа хоста SSH-цели необязателен при создании.
-- Пусто — collector запоминает ключ при первом подключении (как known_hosts); дальше смена ключа — ошибка сбора до
-- сброса администратором. Происхождение отпечатка: admin — введён в Web, first_use — запомнен при первом подключении.
DO $$
DECLARE c text;
BEGIN
 SELECT conname INTO c FROM pg_constraint
 WHERE conrelid = 'sources.remote_targets'::regclass AND contype = 'c' AND pg_get_constraintdef(oid) LIKE '%host_key_sha256 IS NOT NULL%';
 IF c IS NULL THEN RAISE EXCEPTION 'remote_targets host key constraint not found'; END IF;
 EXECUTE format('ALTER TABLE sources.remote_targets DROP CONSTRAINT %I', c);
END $$;
ALTER TABLE sources.remote_targets ADD COLUMN host_key_origin text CHECK (host_key_origin IN ('admin','first_use'));
UPDATE sources.remote_targets SET host_key_origin = 'admin' WHERE host_key_sha256 IS NOT NULL;
ALTER TABLE sources.remote_targets ADD CONSTRAINT remote_target_host_key_origin CHECK ((host_key_sha256 IS NULL) = (host_key_origin IS NULL));
