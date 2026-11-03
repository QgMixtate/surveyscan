# C06 — постоянный реестр, проекция и атомарные события

Дата: 2026-11-04 (Москва). Реализация локальная в v2/, C03 wire 1.0 сохранён.

## Identity и ingest

Registry.Ingest — внутренний adapter boundary, не публичный machine HTTP endpoint.
Caller передаёт проверенные tenant/source; registry повторно проверяет active tenant/source,
текущую generation, точные key_id/namespace/scope/site bindings через Sources port.
Public key берётся из зарегистрированного binding, не payload. Binding provision пока доверенная
локальная setup-операция; enrollment/collector transport реализует C07, production OpenBao PKI — C11.
Проверяются embedded JSON Schema 2020-12, RFC8785 JCS/SHA256, Ed25519 domain-separated подпись C03.
Go проверен на настоящем подписанном Unicode fixture C03-F01 без fixture private key.
Canonical payload ≤64KiB, uint64 counter без float, unique sections, record counts, section time,
IPv4/IPv6 prefix, completeness и отсутствие неизвестного legacy status. Payload/sections неизменяемы.

Mapping = tenant/origin source/namespace/source_local_id. Relay не меняет origin.
Verified known mapping используется повторно; hostname/IP/MAC и сильные признаки нового record
не запускают автоматический cross-source merge. Совпадение либо противоречие → сохранённый
reconciliation_conflict и immutable observation result recorded_pending_resolution, без нового asset.
Существующий mapping и старые observation_links при конфликте не переписываются.
Asserted UID допускается только для уже известного mapping; другое значение не даёт разрешения.
UUIDv4 нового asset не зависит от адреса/agent/collector; fallback team назначается атомарно.
Идентификаторы нормализуются по типу; в E1 они консервативно сохраняются как evidence. Автоматическое
retention/закрытие старых identifier values и ручной merge/reassignment — последующие пакеты.

Одинаковые observation ID или source-record/generation/sequence проверяются по immutable digest.
Точный повтор возвращает прежний result, не добавляет событий/версий. Другой payload — conflict.
Неопределённость generation continuity не позволяет новым sequence=1 откатить прежние facts.

## Проекция

В одной origin/generation/record порядок определяет точный uint64 sequence, включая >int64.
Для разных источников: доверенное время, затем зарегистрированный приоритет и collected_at;
при равном/неопределённом ранге сохраняется выбранное значение. Delivery time не выбирает победителя.
Приоритет копируется в immutable observation, policy_revision=1 хранится в проекции.
Clock skew/future timestamp не проецируется; регресс часов при более высоком sequence сохраняет
sequence order, но section state отмечает clock uncertainty и freshness становится unknown.

Partial обновляет только явно присутствующие значения; unavailable/unsupported/not_requested
не очищают прежние пригодные facts. Полный успешный пустой authoritative snapshot удаляет только
отсутствующие значения того же origin/generation/record. Старые observations остаются в истории.
Раздельно хранятся last_attempt, last_success, section status и per-fact provenance/link.
Hostname, OS, network IP/MAC хранятся в current_facts. Ручные display_name/purpose/criticality/tags
при ingest не меняются, business_revision не зависит от доставки observations.

GET/list/PATCH assets реализуют C03. ETag привязан к UID/business revision; конкурирующий PATCH
получает 412, чужой UID — generic404. Cursor привязан к tenant, limit1–200; keyset pagination по UUID.
Новые записи между страницами не являются snapshot pagination всей сессии: существующие записи
не дублируются, но одна page session не замораживает реестр. HTTP snapshot одной страницы согласован.
C03 Asset отдаёт hostname/OS/statuses; network facts уже сохраняются, их публичный UI/API shape
надо расширять явной новой версией контракта в C09. Не добавлять скрытые поля поверх C03.

## Транзакция и события

Composition root координирует owner Stores: Assets, Inventory, Responsibility, Audit, Sources port,
Messaging. Модули не импортируют реализации друг друга. Узкие shared integrity reads в SQL
проверяют binding/fallback/commit; они не дают права писать чужие domain tables.
Для SMB writer serialization — advisory lock на tenant. Это не throughput SLA для 100 пользователей;
более тонкая конкуренция/разделение процессов требует следующих пакетов и замеров.

Asset creation v1, fallback assignment v2, projection changes v3+, observation event v1 имеют
разные aggregate/version. Один primary event на версию. Business PATCH использует разрешённый
C03 asset.facts_changed.v1 с reason BUSINESS_FIELDS_CHANGED; это явно включает ручные domain facts,
а не переписывание observed inventory. В events только IDs/reason, без credentials/raw payload.

History, audit, projection, result и outbox сохраняются в общей PG transaction. Deferred SQL guards
отвергают asset/business/current-fact mutation без history + outbox + audit текущей transaction xid.
Observation требует result/event/audit; sections нельзя дописывать в другой transaction.
Это не миграция ручных исторических SQL данных в новую историю; C06 guards применяются к новым записям.
Старые C04/C05 migrations не изменены. Прежние DB fixtures дополнены честными event/audit/history
записями вместо отключения guards. Trusted DB administrator остаётся вне API security boundary.

## Consumer

В combined server работает PG consumer registry-version. Effect — monotonic assets.consumer_versions;
checkpoint и effect атомарны. Outbox immutable; delivery at least once, повтор/restart не повторяет
применённый effect. Порядок одного aggregate — version; между aggregates общего порядка не требуется.
Effect failure откатывает savepoint, checkpoint получает retry/backoff; после 5 attempts — dead_letter.
Более поздние версии того же aggregate не обходят gap. Внешних side effects, брокера и FTS здесь нет.
C10/C35 дополняют эксплуатацию/replay/несколько процессов; это не приёмка всех future consumers.
