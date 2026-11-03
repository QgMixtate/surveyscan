-- C06: привязка outbox к транзакции и неизменяемость уже записанного события.
ALTER TABLE messaging.outbox_events ADD COLUMN transaction_id xid8 NOT NULL DEFAULT pg_current_xact_id();
CREATE FUNCTION messaging.immutable_event() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'outbox event is immutable' USING ERRCODE='23514'; END $$;
CREATE TRIGGER outbox_immutable BEFORE UPDATE OR DELETE ON messaging.outbox_events FOR EACH ROW EXECUTE FUNCTION messaging.immutable_event();
