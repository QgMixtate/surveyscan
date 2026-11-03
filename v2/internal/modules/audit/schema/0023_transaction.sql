-- C06: обязательный аудит той же транзакции.
ALTER TABLE audit.audit_events ADD COLUMN transaction_id xid8 NOT NULL DEFAULT pg_current_xact_id();
