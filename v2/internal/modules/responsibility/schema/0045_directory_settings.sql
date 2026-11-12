-- Owner: responsibility; C31.05 (решение пользователя 2026-11-12): настройки синхронизации с каталогом задаются в Web.
-- Здесь — только несекретные параметры; пароль служебной учётки — в хранилище секретов центра (OpenBao KV).
CREATE TABLE responsibility.directory_settings (
 tenant_id uuid PRIMARY KEY,
 settings jsonb NOT NULL CHECK (jsonb_typeof(settings)='object' AND octet_length(settings::text) <= 65536),
 revision platform.uint64 NOT NULL DEFAULT 1,
 updated_at timestamptz NOT NULL DEFAULT now(),
 actor_ref text NOT NULL,
 FOREIGN KEY (tenant_id) REFERENCES access.tenants(tenant_id) ON DELETE RESTRICT
);
