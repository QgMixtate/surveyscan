# C02.03 — владение данными, инварианты и транзакции

Дата: 2026-11-03. Инженерный проект E1, без SQL-реализации.
[Каталог 24 сущностей](C02-model.json), [идентичность](C02-identity-model.md),
[наблюдения](C02-observations.md), [контрпримеры](C02-counterexamples.md).

## 1. Единственный владелец записи

| Модуль | Сущности | Публичная операция / чтение |
|---|---|---|
| Access | tenants | AuthorizeTenant; auth/session/machine credential tables — C05/C11 |
| Scope | sites, network_scopes | ResolveSiteScope, ConfigureSite; fallback subject через Responsibility |
| Sources | sources, agents, collectors | EnrollSource, ResolveOrigin, RebindCollector, RecordContact |
| Assets / Reconciliation | assets, asset_business_fields, asset_identifiers, source_records, reconciliation_conflicts, observation_links, asset_changes | ResolveRecord, CreateAsset, AssignObservation, UpdateBusinessFields, TouchAggregate |
| Inventory | observations, observation_sections, current_facts, section_state | RecordObservation, SelectFacts, RebuildProjection, ReadInventory |
| Responsibility | subjects, responsibility_assignments | GetFallback, AssignInitial, Transfer, ReadAssignments |
| Imports | deliveries, import_checkpoints | ReserveDelivery, CommitRecordResult, ReadDeliveryStatus |
| Audit | audit_events | AppendAudit в caller transaction; scoped reading |
| Messaging | outbox_events, consumer_checkpoints | AppendProducedEvent, Claim/Confirm/Retry consumer |

Владелец реализует repository/guards и миграции своей сущности. Другие модули используют
его порт; общий PG connection не разрешает писать чужой SQL. Read-проекция карточки явная,
права применяются до выдачи. API/worker вызывают те же domain ports, без обхода guards.

Outbox/checkpoints — совместная инфраструктура, а не право доменных модулей на произвольный SQL.
Producer добавляет своё событие через MessagingPort с той же транзакцией и согласованной версией;
AuditPort аналогично дописывает безопасную историю действий. Не записывать секреты в metadata/payload.

## 2. Проверяемые инварианты

| ID | Правило | Механизм при реализации |
|---|---|---|
| INV-01 | Все предметные связи в одной tenant; scope соответствует site | Composite PK/FK/UNIQUE плюс authorization на каждом command/query/job; UUID сам по себе не даёт доступ |
| INV-02 | asset_uid неизменяем, не равен адресам/регистрациям и не переиспользуется | UUID issuance + UPDATE guard, history/tombstone; no delete-on-scan |
| INV-03 | Mapping использует origin; смена relay не создаёт asset | UNIQUE(tenant,source,namespace,source_local_id); collector route отдельно |
| INV-04 | Слабые/конфликтующие признаки не дают молчаливый merge | ResolveRecord guard, conflict state, ручное разрешение; E1 reuse только проверенного mapping |
| INV-05 | Payload observation неизменяем, повтор digest не повторяет эффект | Unique IDs/sequence tuple + digest comparison, immutable write API; retention защищает provenance |
| INV-06 | Статус секции и полнота определяют допустимость обновления/удаления | Typed CHECKs для enum/count, policy guard; partial absence не delete |
| INV-07 | Late/sequence/time uncertainty не откатывают проекцию по received_at | Versioned deterministic policy и source generation; при неясности конфликт/история |
| INV-08 | Сбор не меняет ручные business fields | Ownership разных таблиц, отдельный business revision/ETag |
| INV-09 | У каждого созданного asset ровно одно текущее назначение обязательной роли и активный fallback | Partial UNIQUE ограничивает максимум; minimum-one требует domain transaction, asset lock и deferred constraint/commit guard |
| INV-10 | Данные, history/audit и outbox не расходятся по commit | Один локальный PG UnitOfWork, вызовы owner ports, rollback всей операции |
| INV-11 | Checkpoint/ACK не подтверждает неприменённые эффекты как applied | Durable record ledger в той же транзакции; финальный ответ после успешного commit |
| INV-12 | Конкуренция и повторный worker не теряют update | Revision comparison, unique keys, lock/lease; retry ограничен и идемпотентен |
| INV-13 | Только владелец меняет таблицы; source subtype и binding валидны | Архитектурные checks, owner repositories, discriminator CHECK/FK, scoped Source/Access ports |
| INV-14 | Source health/freshness/presence/lifecycle независимы | Разные поля/проекции; heartbeat relay не обновляет contact всех агентов; outage не делает missing/списание |

SQL CHECK не читает чужие строки. Minimum-one assignment, активность subject и допустимость
ссылки current_fact на активное назначение observation — межстрочные guards/constraints,
а не выдуманный CHECK с SELECT. Конкретный SQL и concurrent tests — C04/C06/C10.

## 3. Транзакции, которые сознательно пересекают модули

| TX | Координатор | Участники и commit boundary | При сбое |
|---|---|---|---|
| TX-01 CreateAsset | Application service через Assets | Resolve scope → lock mapping → Assets.create → Responsibility.assign fallback → Assets.history → Audit.append → Messaging.append | Нет asset без assignment, history или обязательного события |
| TX-02 ApplyObservation | Import application service | Reserve/check checkpoint → Inventory.record immutable observation → Assets.resolve/link → Inventory.project eligible facts → Assets.version/history по изменению → audit/outbox → Imports.record result | Повтор выдаёт сохранённый результат; нет checkpoint applied до effects |
| TX-03 TransferResponsibility | Responsibility application service | Lock asset/role → проверить active subject → закрыть старый interval → создать новый → Assets.version/history → Audit/Messaging | Откат сохраняет старое назначение; при commit ровно одна обязательная роль |
| TX-04 ConsumerEffect | Владелец consumer | Claim/lease с короткой транзакцией; затем effect + inbox/checkpoint атомарно в целевой PG | At-least-once delivery, effect идемпотентен; внешние effects требуют отдельного delivery ledger |

В TX-02 новый resolved asset использует TX-01 как часть той же локальной транзакции,
а не отдельный ранний commit. Неразрешённая запись может быть **сохранена с конфликтом**:
observation + conflict + record result durable, но проекция карточки ещё не applied.
Результаты `applied`, `recorded_pending_resolution`, `rejected` различаются; одинаковый digest
повторно возвращает прежний результат. Окончательную ACK/spool policy задаст C03,
она не должна назвать stored conflict успешно применённой карточкой или держать retry без причины.

Network/Bao/file I/O и ожидание клиента не выполняются внутри долгой SQL-транзакции.
Подпись/схема/доступ и staging проверяются до применения; авторизация/lease/version проверяются
ещё раз на commit boundary. Неизменяемость origin не означает доверия всем данным хоста.

Возможная SQL-уникальность outbox: tenant/aggregate_type/aggregate_id/aggregate_version;
один primary event на версию. Событие наблюдения может иметь свой aggregate_id и version=1,
а не притворяться изменением asset business fields. Multiple events per version требуют
явного ordinal контракта C03; скрытый общий порядок всех событий не предполагается.

## 4. Блокеры будущего выделения сервисов

TX-01/02/03 — намеренные межмодульные локальные транзакции E1; это исключения, а не
разрешение модулям напрямую писать чужие таблицы. Общий UnitOfWork передаёт только owner ports.
Перед выделением сервиса C40 потребуется пересмотр aggregate boundaries или saga/compensation,
ownership, backfill/catch-up и cutover. HTTP-вызов не заменяет общую транзакцию автоматически.
Shared composite FK тоже является связностью схемы, которую нужно устранить/заменить при extraction.

## 5. Ответственность и перенос

Site не активируется для auto-create без активной fallback-команды с владельцем/контактом.
Нельзя отключить последний доступный fallback или subject с действующими обязательствами
без контролируемого переназначения. Future person-deactivation переводит назначения на fallback,
а не очищает поле. В E1 достаточны team и accountable role; другие роли — расширение C27.

При site move UID не меняется; scope/ответственность пересматриваются авторизованной командой
с историей. Перепривязка агента к collector — транспортное действие и сама не меняет business site.

## 6. Следующие задачи

C03 фиксирует envelope, namespaces, generation/sequence, canonical digest, коды conflict/ACK и OpenAPI.
C04 создаёт миграции и проверяет реальные PK/FK/индексы. C05/C06/C07/C10 реализуют ports/guards/транзакции.
C25/C26 расширяют reconciliation/CMDB, C27 ответственность, C37–C40 распределение и DR.
Ни один runtime-invariant не считается испытанным чтением данного документа.
