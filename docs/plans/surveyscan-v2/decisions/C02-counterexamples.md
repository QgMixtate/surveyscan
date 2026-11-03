# C02.04 — контрпримеры модели

Дата: 2026-11-03. 22 сценария разобраны **на уровне проекта**; ни PostgreSQL,
ни Go projector не запускались. `reviewed_in_design` не означает passed runtime test.
Численные интервалы/целевые версии здесь не испытываются.
Машиночитаемые входы и ожидаемые решения: [JSON](C02-counterexamples.json).
Инварианты: [ownership](C02-ownership.md), сущности: [model](C02-model.json).

| ID | Сценарий | Начальное состояние / действие | Ожидаемое решение | Инварианты |
|---|---|---|---|---|
| C02-X01 | Повтор того же observation | Есть resolved source record S→A и observation O/digest H/seq10. Повторить O,H,seq10 | Вернуть прежний result; один history/effect, тот же asset A | INV-03, INV-05, INV-11, INV-12 |
| C02-X02 | Тот же ID, другой payload | Есть O/digest H. Отправить O/digest H2 | Conflict; исходный payload и result не перезаписаны | INV-05, INV-11 |
| C02-X03 | Смена IP у известного источника | S→A, seq10, IP=10.0.0.1. Отправить seq11 с IP=10.0.0.2 и непротиворечивой identity | A сохранён; новая техническая проекция/история; IP не создаёт новый UID | INV-02, INV-03, INV-07 |
| C02-X04 | Клон VM с копией agent state | Агент S привязан к A. Второй хост использует тот же agent state, но противоречащий hardware evidence | Не перезаписать A молча; conflict/quarantine и re-enrollment policy; не объявлять физическую идентичность по agent_id | INV-02, INV-04, INV-12 |
| C02-X05 | Одинаковый IP в разных tenant | Tenant T1 и T2, свои источники и scope. Оба сообщают IP=10.0.0.1 | Отдельные assets и правообласти; нет cross-tenant mapping | INV-01, INV-04 |
| C02-X06 | Поздняя offline-запись | Доверенная generation G источника S уже seq20. Приходит запоздавший seq15 того же record | Сохранить историю без rollback current facts и без обновления freshness по received_at | INV-05, INV-07, INV-14 |
| C02-X07 | Partial empty | Есть успешный факт/коллекция seq10. seq11 partial, facts=[], collection_complete=false | Диагностика попытки видна; прежние успешные values/provenance не удалены | INV-06, INV-07 |
| C02-X08 | Подтверждённая пустая коллекция | Есть элементы только в scope коллекции K. Новый ok, complete=true, authoritative K, facts=[] | Удаление допустимо только в K; ручные поля и другие scopes не затронуты | INV-06, INV-08 |
| C02-X09 | Claim чужого asset_uid | Источник разрешён только для T1. Передать asserted UID принадлежащий T2 | Авторизация отклоняет; чужой asset/данные не раскрываются и не меняются | INV-01, INV-13 |
| C02-X10 | Смена collector у того же агента | Origin S→A доставлял через C1. Авторизованно переназначить collector C2 в той же tenant | Origin/mapping/asset A сохраняются; маршрут и аудит обновлены | INV-02, INV-03, INV-13 |
| C02-X11 | Новый источник с конфликтующим serial | A уже имеет identifier X, новый source U сообщает X с другим evidence. Resolve нового record U | Не auto-merge; conflict candidate и pending record, ручное разрешение позже | INV-04, INV-05 |
| C02-X12 | Площадка или collector недоступны | Есть asset A и успешный inventory. Пропустить heartbeat/scan из-за outage | Source health/freshness degraded; asset не списан, ответственность не очищена | INV-09, INV-14 |
| C02-X13 | Сбой создания asset | Создание A ещё не committed. Ошибка после записи A до fallback/outbox | Rollback всех участников TX-01; нет бесхозного или наполовину созданного asset | INV-09, INV-10 |
| C02-X14 | Конкурентная передача ответственности | A имеет одну active accountable role. Два оператора меняют subject по одному revision | Один успех, второй conflict/retry; ровно одна active роль и полная история | INV-09, INV-12 |
| C02-X15 | Reset sequence новой generation | S/G1 уже seq100. Авторизованный re-enroll выпускает G2/seq1 | Не сравнивать 1<100 вне generation; continuity policy C03, при неясности сохранить history/conflict без rollback | INV-03, INV-07, INV-12 |
| C02-X16 | Разрешение отложенного наблюдения | O хранится без asset link в pending conflict. Оператор авторизованно связывает O с A | Payload O не изменён; новая temporal link и controlled projection rebuild с audit | INV-04, INV-05, INV-10 |
| C02-X17 | Два workers применяют один record | Один delivery/record/digest зарезервирован. Оба доходят до commit | Unique/lock/revision обеспечивает один effect и согласованный checkpoint/result | INV-05, INV-10, INV-11, INV-12 |
| C02-X18 | Scope не соответствует site | Asset указал site A и scope site B одной tenant. Создать или изменить asset | Composite FK/guard отвергает mismatch, существующий asset не изменён | INV-01, INV-13 |
| C02-X19 | Неверный source subtype | source_kind=collector. Создать AGENT со ссылкой на этот source | Discriminator CHECK/FK отвергает subtype mismatch | INV-13 |
| C02-X20 | Collector online, агент offline | Collector жив, агент давно не контактировал. Получить новый collector heartbeat и старый buffered heartbeat агента | Контакт collector обновлён; agent contact не становится свежим от relay/replay | INV-07, INV-14 |
| C02-X21 | Retention исходного evidence | Current fact ссылается на O/link. Запустить очистку старых observations | Запретить dangling provenance; сначала согласованная компактизация/архив, без CASCADE удаления asset/facts | INV-02, INV-05 |
| C02-X22 | Ручное имя против нового inventory | У A ручной display_name и старый observed hostname. Новый сбор сообщает другой hostname | Observed hostname обновлён по policy; ручное имя/назначение сохранены | INV-07, INV-08 |

## Вопросы, передаваемые дальше

- C03: canonical digest/envelope, namespace normalization, generation issuance/continuity,
  authenticated origin time и точные ACK/disposition codes. Unresolved observation не считается
  успешно применённой карточкой; central durable result и source spool policy должны быть согласованы.
- C04/C06: SQL-enforcement min-one responsibility, tenant/site/scope FK, source discriminator,
  immutable writes, lock/retry и реальная конкурентная приёмка TX-01/02/03.
- C25: полноценное strong/weak matching, merge/split/reassignment и исправление ошибочных связей.
- C37: глобальные UID и routing за пределами одного PG без фиктивного distributed UNIQUE.

Ни один вопрос не блокирует проектирование контрактов C03. Он становится blocker только
для конкретного claim реализации, если соответствующий guard/contract не определён или не испытан.
