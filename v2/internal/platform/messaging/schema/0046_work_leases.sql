-- Owner: messaging; C35.02/C36.01 — взаимоисключение работ между процессами центра без состояния сессии БД
-- (совместимо с пулом соединений в режиме транзакций). Аренда продлевается держателем; упавший процесс теряет её
-- по истечении lease_until.
CREATE TABLE messaging.work_leases (
 lease_key text PRIMARY KEY CHECK (length(lease_key) BETWEEN 1 AND 200),
 holder uuid NOT NULL,
 acquired_at timestamptz NOT NULL,
 lease_until timestamptz NOT NULL CHECK (lease_until > acquired_at)
);

-- C36.03: событие по-прежнему нельзя изменить; удалить можно только в транзакции очистки, которая явно отметила себя
-- (set_config('surveyscan.retention','outbox',true) — действует до конца транзакции). Так делает только очистка
-- журналов (события, применённые всеми нужными потребителями и старше срока хранения).
CREATE OR REPLACE FUNCTION messaging.immutable_event() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' AND current_setting('surveyscan.retention', true)='outbox' THEN RETURN OLD; END IF;
 RAISE EXCEPTION 'outbox event is immutable' USING ERRCODE='23514';
END $$;
