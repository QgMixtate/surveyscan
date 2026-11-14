-- Owner: sources; C51.03 шаг 2, запрос пользователя 2026-11-14: «доверять CA домена» — корневой сертификат AD CS
-- загружается один раз для организации; WinRM-цели с проверкой «CA домена» проверяют сертификат ПК по нему и по имени
-- ПК (без PEM и без запоминания на каждом ПК). Пока такие цели есть, сертификат CA удалить нельзя.
CREATE TABLE sources.winrm_trust (
 tenant_id uuid NOT NULL PRIMARY KEY,
 ca_pem text NOT NULL CHECK (length(ca_pem) BETWEEN 1 AND 65536),
 revision platform.uint64 NOT NULL DEFAULT 1,
 updated_at timestamptz NOT NULL DEFAULT now(),
 updated_by uuid NOT NULL,
 FOREIGN KEY (tenant_id) REFERENCES access.tenants(tenant_id) ON DELETE RESTRICT
);
DO $$
DECLARE c text;
BEGIN
 SELECT conname INTO c FROM pg_constraint
 WHERE conrelid = 'sources.remote_targets'::regclass AND contype = 'c' AND conname <> 'remote_target_tls_trust'
  AND pg_get_constraintdef(oid) LIKE '%tls_cert_origin%first_use%';
 IF c IS NULL THEN RAISE EXCEPTION 'remote_targets tls_cert_origin constraint not found'; END IF;
 EXECUTE format('ALTER TABLE sources.remote_targets DROP CONSTRAINT %I', c);
END $$;
ALTER TABLE sources.remote_targets DROP CONSTRAINT remote_target_tls_trust;
ALTER TABLE sources.remote_targets ADD CONSTRAINT remote_target_tls_cert_origin CHECK (tls_cert_origin IN ('admin','first_use','domain_ca'));
ALTER TABLE sources.remote_targets ADD CONSTRAINT remote_target_tls_trust CHECK (
 kind <> 'winrm' AND tls_ca_pem IS NULL AND tls_cert_sha256 IS NULL AND tls_cert_origin IS NULL
 OR kind = 'winrm' AND tls_ca_pem IS NOT NULL AND tls_server_name IS NOT NULL AND tls_cert_origin = 'admin' AND tls_cert_sha256 IS NULL
 OR kind = 'winrm' AND tls_ca_pem IS NULL AND tls_server_name IS NOT NULL AND tls_cert_origin = 'domain_ca' AND tls_cert_sha256 IS NULL
 OR kind = 'winrm' AND tls_ca_pem IS NULL AND (tls_cert_sha256 IS NULL) = (tls_cert_origin IS NULL) AND tls_cert_origin IS DISTINCT FROM 'admin' AND tls_cert_origin IS DISTINCT FROM 'domain_ca');
