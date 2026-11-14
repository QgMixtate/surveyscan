-- Owner: sources; C51.03 шаг 3, запрос пользователя 2026-11-14: WinRM по HTTP 5985 с Kerberos — только по полному
-- имени ПК (SPN HTTP/<имя>) и доменной учётке; сообщения шифруются Kerberos; NTLM по HTTP не используется.
-- https — прежний способ (5986, проверка сертификата). Для http_kerberos сертификаты не применяются.
ALTER TABLE sources.remote_targets ADD COLUMN winrm_transport text CHECK (winrm_transport IN ('https','http_kerberos'));
UPDATE sources.remote_targets SET winrm_transport = 'https' WHERE kind = 'winrm';
ALTER TABLE sources.remote_targets ADD CONSTRAINT remote_target_winrm_transport CHECK (
 (kind = 'winrm') = (winrm_transport IS NOT NULL)
 AND (winrm_transport IS DISTINCT FROM 'http_kerberos'
  OR tls_server_name IS NOT NULL AND tls_ca_pem IS NULL AND tls_cert_sha256 IS NULL AND tls_cert_origin IS NULL));
