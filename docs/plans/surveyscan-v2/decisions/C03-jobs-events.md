# C03.03 — задания, попытки и outbox

Дата: 2026-11-03. [Машины состояний и примеры](../contracts/C03/state-machines.json),
[JSON Schema](../contracts/C03/schemas/wire.schema.json), [OpenAPI](../contracts/C03/openapi.json).
Это контракт, не действующая очередь или доказательство конкурентной корректности.

## 1. Job и fencing

E1 тип задания — inventory с profile_revision и разрешёнными target_source_ids на назначенном
collector. Нет произвольного shell payload. Локальный периодический цикл агента может работать
по versioned config без создания нового ручного job на каждый heartbeat.

Create job требует Idempotency-Key: повтор tenant/key/same request digest возвращает прежний job;
тот же ключ с другим содержимым — 409. Operator rights и target scope проверяются на create и execute.
Claim collector содержит стабильный claim_id: потерянный ответ не должен выдать два разных задания
на один retry. Повтор возвращает прежнюю ещё действующую lease; expired claim не оживляет старую attempt.
Если задания нет, 204 и bounded backoff; это не успешная lease с пустым job.

Lease возвращает job_id, новый attempt_id, монотонный lease_version, lease_until,
opaque lease_token, owner_source_id, targets и профиль. Default lease 120s, renewal до expiry;
параметры регулируются сервером. Попытка идентифицируется тройкой job/attempt/version,
token дополнительно проверяется. Worker не выбирает owner/tenant/version сам.

Любой start/heartbeat/completion проверяет owner, scope, текущую attempt/version/token и срок.
Старый worker после истечения lease получает 409 LEASE_STALE; прежний token не разрешает
apply после новой attempt. Проверка fencing перед commit обязательна, проверки только при claim мало.
Payload observation может иметь job reference; stale job result не меняет проекцию по старым полномочиям.
Сохранение rejected raw evidence — отдельная объявленная quarantine policy, не скрытый успешный apply.

## 2. Состояния

queued → leased → running → completed / completed_partial / failed.
queued/leased/running могут перейти в cancel_requested → cancelled.
Lease expiry leased/running без cancel intent и при оставшихся retries → queued с fencing старой attempt.
При cancel intent expiry завершает cancelled и **не** переочередит задание.
После terminal state retry создаёт новое job ID, сохраняя causation/history.

Cancel использует If-Match/revision и аудит; terminal cancel → 409. Если completion и cancel
гоняются, выигрывает одна commit/revision. Если cancel intent уже committed, completion не обходит его:
worker прекращает новые операции, завершает/ограничивает активные и подтверждает cancelled.
Offline collector узнаёт intent после связи; это не обещание мгновенно остановить недоступный узел.

completed означает корректное завершение обработки job; completeness секций оценивается отдельно.
completed_partial означает явно частичный согласованный результат. Точные количества и причины сохраняются;
exit code процесса не доказывает полный сбор. Повтор attempt action идемпотентен, новый heartbeat старой
attempt не продлевает lease следующего владельца.

## 3. События

Event envelope: version 1.0, event_id, tenant_id, producer_module, event_type, aggregate_type/id/version,
occurred_at UTC, correlation_id, nullable causation_id и типизированный безопасный data.
Aggregate/version передаётся без потери uint64 как строка. Один primary event на aggregate version.

| Тип v1 | Producer | Aggregate | Обязательная связка data |
|---|---|---|---|
| asset.created.v1 | Assets | asset | asset_uid = aggregate_id |
| asset.facts_changed.v1 | Assets через owner port | asset | asset_uid = aggregate_id |
| observation.recorded.v1 | Inventory | observation | observation_id = aggregate_id |
| responsibility.assigned.v1 | Responsibility, version через Assets port | asset | asset_uid = aggregate_id |
| source.contact_updated.v1 | Sources | source | source_id = aggregate_id |

Назначение общей версии asset координируется Assets port в том же UnitOfWork; модуль
Responsibility не делает прямой SQL в assets. Audit/consumer state не присваивают новые asset versions.
Если одной команде нужны несколько primary events одного aggregate, выделяются разные версии
в той же транзакции; без скрытых событий одной версии и без глобального порядка всех shard.

Доменные данные, event и требуемая history/audit фиксируются одной PG-транзакцией C02.
Dispatcher читает committed outbox и доставляет at-least-once. Event не является подписью
истинности host facts. В events нет credentials, произвольных конфигов и private keys.

## 4. Consumers и replay

Checkpoint/inbox key — tenant/consumer_name/event_id; есть attempts, state, lease_until, applied_at.
Effect и checkpoint атомарны в целевой PG, где это возможно. Для файлового FTS и внешних систем —
идемпотентность по event/version и отдельные подтверждения; транзакция PG не делает внешний эффект атомарным.
Ошибки → bounded retry/backoff, затем dead_letter; это видимый статус и ручной runbook, не исчезнувший event.

Порядок одного aggregate — по version. Gap/out-of-order требует чтения authoritative projection или
ожидания/rebuild по consumer policy; поздняя версия не откатывает индекс. Нельзя удалять outbox,
пока необходимые consumers/checkpoints/rebuild-retention его требуют.
Replay создаёт явный разрешённый run и не рассылает повторно внешние уведомления без отдельной policy.
Брокер не требуется. Durable outbox одинаков для combined и будущих API/worker.

12 примеров рёбер графа проверяются статически. Реальные lock/lease races, crash после commit,
отказ dispatcher и replay эффекта — проверки C06/C10/C35, не выполненные этим документом.
