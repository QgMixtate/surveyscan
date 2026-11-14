-- Owner: sources; C51.03, запрос пользователя 2026-11-14: сертификат WinRM-цели (PEM) и имя ПК необязательны.
-- Без PEM collector при первом подключении читает сертификат сервера и закрепляет его отпечаток SHA-256 в центре
-- (first_use, как ключ хоста SSH в 0051); дальше другой сертификат — отказ сбора cert_changed до сброса в Web.
-- admin — доверие по CA из PEM, заданного администратором (с проверкой имени).
DO $$
DECLARE c text;
BEGIN
 SELECT conname INTO c FROM pg_constraint
 WHERE conrelid = 'sources.remote_targets'::regclass AND contype = 'c' AND pg_get_constraintdef(oid) LIKE '%tls_ca_pem IS NOT NULL%';
 IF c IS NULL THEN RAISE EXCEPTION 'remote_targets winrm certificate constraint not found'; END IF;
 EXECUTE format('ALTER TABLE sources.remote_targets DROP CONSTRAINT %I', c);
END $$;
ALTER TABLE sources.remote_targets ADD COLUMN tls_cert_sha256 text CHECK (tls_cert_sha256 ~ '^[0-9a-f]{64}$');
ALTER TABLE sources.remote_targets ADD COLUMN tls_cert_origin text CHECK (tls_cert_origin IN ('admin','first_use'));
UPDATE sources.remote_targets SET tls_cert_origin = 'admin' WHERE tls_ca_pem IS NOT NULL;
ALTER TABLE sources.remote_targets ADD CONSTRAINT remote_target_tls_trust CHECK (
 kind <> 'winrm' AND tls_ca_pem IS NULL AND tls_cert_sha256 IS NULL AND tls_cert_origin IS NULL
 OR kind = 'winrm' AND tls_ca_pem IS NOT NULL AND tls_server_name IS NOT NULL AND tls_cert_origin = 'admin' AND tls_cert_sha256 IS NULL
 OR kind = 'winrm' AND tls_ca_pem IS NULL AND (tls_cert_sha256 IS NULL) = (tls_cert_origin IS NULL) AND tls_cert_origin IS DISTINCT FROM 'admin');
