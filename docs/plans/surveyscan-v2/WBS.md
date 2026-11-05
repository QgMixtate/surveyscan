# Полный WBS surveyscan v2

Версия плана 1.0 по архитектуре 0.5. C01–C10:40 done,160 planned. Оценка в часах не выполнялась; база оценки указана по каждой подзадаче.


# C01 — Границы первого релиза и карта решений (E0)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 1–4, 14, 17, 32, 35, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C01.01 — Зафиксировать baseline и источники

Работа: Подготовка и проектирование. Роль: Архитектор.

- Вход/зависимость: Baseline 0.5 и запрос пользователя; контракты и материалы пакета.
- Результат: Манифест версии 0.5, статуса веток и незавершённых документов.
- Проверка: Различены локальное, опубликованное и реализованное.
- База оценки: 1 репозиторий; 4 исходных документа и матрица U-01–19.
- Статус: done; document-reviewed; product tests unrun.

## C01.02 — Описать capabilities SMB-релиза

Работа: Реализация. Роль: Владелец продукта / руководитель проекта.

- Вход/зависимость: C01.01; контракты и материалы пакета.
- Результат: Список полей E1, целевых ОС и явных исключений.
- Проверка: Есть постоянный цикл agent→collector→card и нет enterprise prerequisite.
- База оценки: 1 профиль E1; платформенный выбор Windows либо Linux.
- Статус: done; document-reviewed; product tests unrun.

## C01.03 — Выбрать блокирующие решения E1

Работа: Реализация. Роль: Архитектор.

- Вход/зависимость: C01.02; контракты и материалы пакета.
- Результат: ADR scope: auth/enrollment, frontend, версии Go/PG, локальное хранилище очередей, trust.
- Проверка: У каждого решения статус user-confirmed/proposed/blocked и аргументы.
- База оценки: Только D-01/03/06/07/09/11/14/16/17 в части E1; прочие отложены по эпохам.
- Статус: done; document-reviewed; product tests unrun.

## C01.04 — Определить приёмку и пилотный стенд

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C01.03; контракты и материалы пакета.
- Результат: Сценарии раннего среза и 24-часового E1 прогона.
- Проверка: Не выданы плановые показатели за выполненные тесты.
- База оценки: 1 VM/хост выбранной ОС, 1 collector, 1 центральный стенд.
- Статус: done; document-reviewed; product tests unrun.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C02 — Минимальная ER-модель и владение данными (E0)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 2, 5, 9, 19, 21, 28, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C02.01 — Развести сущности идентичности

Работа: Подготовка и проектирование. Роль: Архитектор.

- Вход/зависимость: C01; контракты и материалы пакета.
- Результат: ER: tenant/site/asset/identifier/source/agent/collector и scope.
- Проверка: agent_id и IP не используются как canonical asset_uid.
- База оценки: 8 базовых сущностей; 3 способа источника.
- Статус: done; design reviewed and structural documentation checks; runtime/mock tests unrun.

## C02.02 — Спроектировать наблюдения и проекции

Работа: Реализация. Роль: Разработчик БД / DBA.

- Вход/зависимость: C02.01; контракты и материалы пакета.
- Результат: ER observation/section/current_fact, collected/received/sequence, statuses.
- Проверка: Старое и partial наблюдение не стирает достоверные факты.
- База оценки: 5 статусов секции и unknown legacy; 2 временные оси.
- Статус: done; design reviewed and structural documentation checks; runtime/mock tests unrun.

## C02.03 — Описать ownership и инварианты

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C02.02; контракты и материалы пакета.
- Результат: Матрица таблица→модуль, source mapping, fallback team, outbox.
- Проверка: Tenant constraints и запрет чужих записей проверяемы.
- База оценки: Реестр, inventory, sources, responsibility, jobs/import.
- Статус: done; design reviewed and structural documentation checks; runtime/mock tests unrun.

## C02.04 — Проверить модель на контрпримерах

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C02.03; контракты и материалы пакета.
- Результат: Набор примеров повтор, смена IP, клон VM, offline и конфликт.
- Проверка: Есть ожидаемое решение каждого примера и открытые вопросы.
- База оценки: Не менее 6 сценариев идентичности и поздних данных.
- Статус: done; design reviewed and structural documentation checks; runtime/mock tests unrun.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C03 — Контракты обмена и состояния доставки (E0)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 6–8, 11, 22–23, 33–34, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C03.01 — Описать envelope наблюдения

Работа: Подготовка и проектирование. Роль: Backend Go-разработчик.

- Вход/зависимость: C02; контракты и материалы пакета.
- Результат: Версионированная схема source/identity/section/provenance/sequence.
- Проверка: Валидные и ошибочные образцы проходят schema checks.
- База оценки: 1 major schema, 3 source_kind, ограниченные payloads.
- Статус: done; schemas/reference fixtures executed; runtime HTTP/mTLS/PG unrun.

## C03.02 — Задать agent→collector→center протокол

Работа: Реализация. Роль: Архитектор.

- Вход/зависимость: C03.01; контракты и материалы пакета.
- Результат: API enrollment/heartbeat/upload/status и state machine receipt/applied.
- Проверка: Промежуточный ACK не выдаётся за commit центра.
- База оценки: 3 компонента; 2 этапа подтверждения; retry/dedup.
- Статус: done; schemas/reference fixtures executed; runtime HTTP/mTLS/PG unrun.

## C03.03 — Описать задания и события

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C03.02; контракты и материалы пакета.
- Результат: Lease/attempt/cancellation, envelope outbox и consumer checkpoint.
- Проверка: Падение после commit допускает повтор без повторного эффекта.
- База оценки: 1 очередь заданий, 1 outbox, version/idempotency keys.
- Статус: done; schemas/reference fixtures executed; runtime HTTP/mTLS/PG unrun.

## C03.04 — Подготовить контрактные fixtures

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C03.03; контракты и материалы пакета.
- Результат: Набор JSON/HTTP fixtures и матрица совместимости.
- Проверка: Unknown major, подмена tenant, conflicting digest отклоняются.
- База оценки: Минимум 8 позитивных/негативных контрактных сценариев.
- Статус: done; schemas/reference fixtures executed; runtime HTTP/mTLS/PG unrun.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C04 — Go-каркас и воспроизводимый dev-стенд (E1)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 4, 9, 12, 28, 31, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C04.01 — Создать структуру модульного backend

Работа: Подготовка и проектирование. Роль: Backend Go-разработчик.

- Вход/зависимость: C03; контракты и материалы пакета.
- Результат: cmd/internal/contracts с границами импортов и combined entrypoint.
- Проверка: Сборка и архитектурная проверка импортов проходят.
- База оценки: Server, collector и agent entrypoints без бизнес-заглушек в приёмке.
- Статус: done; passed local live/unit; hosted GitHub Actions unrun.

## C04.02 — Поднять постоянный PostgreSQL и миграции

Работа: Реализация. Роль: Разработчик БД / DBA.

- Вход/зависимость: C04.01; контракты и материалы пакета.
- Результат: Версионированные миграции минимальной модели и конфиг.
- Проверка: Повторное применение безопасно; данные не зависят от scan DB.
- База оценки: 1 PG кластер; схема из C02.
- Статус: done; passed local live/unit; hosted GitHub Actions unrun.

## C04.03 — Собрать локальный инфраструктурный стенд

Работа: Реализация. Роль: Инженер эксплуатации / сборки.

- Вход/зависимость: C04.02; контракты и материалы пакета.
- Результат: Документированный запуск PG/backend/OpenBao/proxy с локальными томами.
- Проверка: Чистый стенд стартует и диагностирует недостающие настройки.
- База оценки: 1 поддержанный binary/container путь; без Kubernetes.
- Статус: done; passed local live/unit; hosted GitHub Actions unrun.

## C04.04 — Настроить CI и базовые проверки

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C04.03; контракты и материалы пакета.
- Результат: Go build/test, PG integration и schema validation в CI.
- Проверка: Проверки реально выполняются и сохраняют exit status.
- База оценки: 1 CI pipeline и воспроизводимый тестовый PG.
- Статус: done; passed local live/unit; hosted GitHub Actions unrun.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C05 — Пользователи, tenant scope и базовая авторизация (E1)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 3, 11, 18, 27, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C05.01 — Реализовать bootstrap администратора

Работа: Подготовка и проектирование. Роль: Backend Go-разработчик.

- Вход/зависимость: C04; контракты и материалы пакета.
- Результат: Безопасная процедура первого пользователя и хранилище credential metadata.
- Проверка: Нет общих заводских паролей и секретов в логах.
- База оценки: 1 bootstrap flow; reset/expiry policy по ADR.
- Статус: done; passed local real PG/TLS/CLI/HTTP; hosted CI unconfirmed (network blocker).

## C05.02 — Добавить auth и минимальные роли

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C05.01; контракты и материалы пакета.
- Результат: Login/session/token, operator/viewer/admin и tenant context.
- Проверка: Revocation/expiry и отказ неверной роли проверены.
- База оценки: 1 выбранный auth-method; 3 минимальные роли.
- Статус: done; passed local real PG/TLS/CLI/HTTP; hosted CI unconfirmed (network blocker).

## C05.03 — Защитить API и фоновые операции

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C05.02; контракты и материалы пакета.
- Результат: Общий authorization contract для handlers/jobs/artifacts.
- Проверка: Подмена UUID или tenant не даёт чужие данные.
- База оценки: Все минимальные E1 endpoints и job context.
- Статус: done; passed local real PG/TLS/CLI/HTTP; hosted CI unconfirmed (network blocker).

## C05.04 — Проверить auth threat cases

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C05.03; контракты и материалы пакета.
- Результат: Негативные интеграционные проверки и краткий threat record.
- Проверка: Session/cookie/CSRF либо token policy соответствует ADR.
- База оценки: 2 tenant, expired/revoked credential, concurrent session.
- Статус: done; passed local real PG/TLS/CLI/HTTP; hosted CI unconfirmed (network blocker).

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C06 — Постоянный реестр, история и outbox (E1)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 5, 9, 19, 21, 23, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C06.01 — Реализовать asset и identity mapping

Работа: Подготовка и проектирование. Роль: Backend Go-разработчик.

- Вход/зависимость: C05; контракты и материалы пакета.
- Результат: Create/get/list с canonical UID и минимальной reconciliation policy.
- Проверка: Повтор источника не создаёт дубли; конфликт виден.
- База оценки: Минимальные поля E1 и source-local mapping.
- Статус: done; passed local real PG/crypto/HTTPS/binary tests; hosted C06 unrun.

## C06.02 — Сохранить observations/current facts

Работа: Реализация. Роль: Разработчик БД / DBA.

- Вход/зависимость: C06.01; контракты и материалы пакета.
- Результат: Транзакционный ingest с provenance и приоритетом свежести.
- Проверка: Partial/late не затирают бизнес-поля и новые факты.
- База оценки: Поле имя/ОС/IP/MAC, times/statuses из C01.
- Статус: done; passed local real PG/crypto/HTTPS/binary tests; hosted C06 unrun.

## C06.03 — Добавить ответственность, историю и outbox

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C06.02; контракты и материалы пакета.
- Результат: Fallback team при создании, аудит и событие в той же транзакции.
- Проверка: Нет бесхозной карточки или commit данных без события.
- База оценки: 1 accountable role, asset history и минимальный consumer.
- Статус: done; passed local real PG/crypto/HTTPS/binary tests; hosted C06 unrun.

## C06.04 — Проверить реестр на PostgreSQL

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C06.03; контракты и материалы пакета.
- Результат: Integration tests и fixtures повторов/конкуренции.
- Проверка: Tenant isolation, rollback и idempotency подтверждены.
- База оценки: 2 tenant; duplicate/late/conflict/rollback.
- Статус: done; passed local real PG/crypto/HTTPS/binary tests; hosted C06 unrun.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C07 — Площадочный collector и приём результатов (E1)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 7–8, 33–34, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C07.01 — Реализовать регистрацию collector

Работа: Подготовка и проектирование. Роль: Backend Go-разработчик.

- Вход/зависимость: C06; контракты и материалы пакета.
- Результат: Machine identity и привязка site/tenant с ограниченными правами.
- Проверка: Незарегистрированный/отозванный collector отклоняется.
- База оценки: 1 enrollment flow и identity lifecycle базового ADR.
- Статус: done; passed local real PG/x509/mTLS and compiled server/collector; synthetic source; hosted C07 unrun.

## C07.02 — Реализовать центральный upload/status pipeline

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C07.01; контракты и материалы пакета.
- Результат: Staging/validation/checkpoints и передача в реестр.
- Проверка: Размер, схема, digest и tenant проверяются до применения.
- База оценки: E1 JSON/stream envelope; крупный portable archive позже C23.
- Статус: done; passed local real PG/x509/mTLS and compiled server/collector; synthetic source; hosted C07 unrun.

## C07.03 — Реализовать collector ingress для агента

Работа: Реализация. Роль: Разработчик агента/коллектора.

- Вход/зависимость: C07.02; контракты и материалы пакета.
- Результат: HTTPS endpoint приёма наблюдений и outbound доставка в центр.
- Проверка: Источник и provenance не подменяются collector metadata.
- База оценки: 1 collector; agent ingress и center egress.
- Статус: done; passed local real PG/x509/mTLS and compiled server/collector; synthetic source; hosted C07 unrun.

## C07.04 — Проверить минимальный сквозной путь

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C07.03; контракты и материалы пакета.
- Результат: Прогон контрактного источника через collector в PG.
- Проверка: Результат виден в API со статусом applied и mapping UID.
- База оценки: Синтетические fixtures C03; это ещё не проверка реального host agent.
- Статус: done; passed local real PG/x509/mTLS and compiled server/collector; synthetic source; hosted C07 unrun.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C08 — Минимальный host agent и первый живой цикл (E1)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 6, 33–34, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C08.01 — Реализовать read-only адаптер первой ОС

Работа: Подготовка и проектирование. Роль: Разработчик агента/коллектора.

- Вход/зависимость: C07; контракты и материалы пакета.
- Результат: Сбор identity/hostname/ОС/IP/MAC с section statuses.
- Проверка: На реальном тестовом хосте получены ожидаемые сведения.
- База оценки: 1 ОС/архитектура из C01; ограниченный набор полей E1.
- Статус: done; passed local real Linux/amd64 host; three scheduled cycles + restart; real TLS/mTLS/PG; hosted C08 unrun.

## C08.02 — Реализовать agent enrollment и HTTPS client

Работа: Реализация. Роль: Разработчик агента/коллектора.

- Вход/зависимость: C08.01; контракты и материалы пакета.
- Результат: Уникальная machine identity, binding к collector и TLS trust.
- Проверка: Неверный endpoint/cert и revoked identity отклонены.
- База оценки: 1 agent→collector connection; без PG и remote target secrets.
- Статус: done; passed local real Linux/amd64 host; three scheduled cycles + restart; real TLS/mTLS/PG; hosted C08 unrun.

## C08.03 — Добавить регулярный цикл и heartbeat

Работа: Реализация. Роль: Разработчик агента/коллектора.

- Вход/зависимость: C08.02; контракты и материалы пакета.
- Результат: Расписание, раздельный heartbeat, jitter, timeout и graceful stop.
- Проверка: Несколько циклов обновляют один asset без ручного запуска.
- База оценки: Одна configurable schedule; heartbeat и inventory интервалы.
- Статус: done; passed local real Linux/amd64 host; three scheduled cycles + restart; real TLS/mTLS/PG; hosted C08 unrun.

## C08.04 — Показать ранний работающий вертикальный срез

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C08.03; контракты и материалы пакета.
- Результат: Реальный agent→collector→server→PG→API/CLI-dev просмотр.
- Проверка: Свежие данные обновились минимум 3 цикла, UID тот же.
- База оценки: 1 живой хост; без заявления production-ready.
- Статус: done; passed local real Linux/amd64 host; three scheduled cycles + restart; real TLS/mTLS/PG; hosted C08 unrun.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C09 — Отдельный Web UI и базовая карточка (E1)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 11, 27, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C09.01 — Создать независимую frontend-сборку

Работа: Подготовка и проектирование. Роль: Frontend-разработчик.

- Вход/зависимость: C06; контракты и материалы пакета.
- Результат: Локальные assets, API client и version manifest.
- Проверка: Production runtime не требует Node/CDN.
- База оценки: 1 выбранный framework из C01; отдельный pipeline.
- Статус: done; passed local real static UI + Chromium/TLS/PG; generated contracts/build; hosted unrun.

## C09.02 — Сделать login и реестр активов

Работа: Реализация. Роль: Frontend-разработчик.

- Вход/зависимость: C09.01; контракты и материалы пакета.
- Результат: Авторизация, список/фильтры/пагинация, обработка API errors.
- Проверка: UI не получает лишние данные и не полагается на скрытие кнопок.
- База оценки: Минимальные E1 endpoints C05/C06.
- Статус: done; passed local real static UI + Chromium/TLS/PG; generated contracts/build; hosted unrun.

## C09.03 — Сделать карточку и состояния источников

Работа: Реализация. Роль: Frontend-разработчик.

- Вход/зависимость: C09.02; контракты и материалы пакета.
- Результат: Имя/ОС/IP/ответственная команда, section status и времена.
- Проверка: Unknown/partial/stale/source health различаются.
- База оценки: 1 карточка; 3 fixtures: полный, partial, нет контакта.
- Статус: done; passed local real static UI + Chromium/TLS/PG; generated contracts/build; hosted unrun.

## C09.04 — Проверить совместимость и браузер

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C09.03; контракты и материалы пакета.
- Результат: Contract/E2E на реальном API и static hosting.
- Проверка: UI и backend обновляются независимо в согласованной паре.
- База оценки: 2 ширины 800/1440, keyboard path, version mismatch.
- Статус: done; passed local real static UI + Chromium/TLS/PG; generated contracts/build; hosted unrun.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C10 — Долговечная доставка и восстановление (E1)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 7–8, 23, 33–34, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C10.01 — Сохранить agent spool и sequence state

Работа: Подготовка и проектирование. Роль: Разработчик агента/коллектора.

- Вход/зависимость: C08; контракты и материалы пакета.
- Результат: Ограниченная локальная очередь и восстановление после reboot.
- Проверка: Неутверждённые записи переживают crash/restart.
- База оценки: Локальное хранилище по ADR; disk quota и retention.
- Статус: done; passed local real PG/TLS/crash/ENOSPC/bounded24-call burst; hosted unrun; jobs runtime C12.

## C10.02 — Сохранить collector spool и двухэтапные ACK

Работа: Реализация. Роль: Разработчик агента/коллектора.

- Вход/зависимость: C10.01; контракты и материалы пакета.
- Результат: Receipt/applied state и end-to-end confirmation routing.
- Проверка: Потеря связи с центром не очищает agent/collector результаты.
- База оценки: 2 очереди; 2 ACK уровня; duplicate/reorder.
- Статус: done; passed local real PG/TLS/crash/ENOSPC/bounded24-call burst; hosted unrun; jobs runtime C12.

## C10.03 — Укрепить jobs/import/outbox recovery

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C10.02; контракты и материалы пакета.
- Результат: Lease/claim/checkpoint/inbox, retry/backoff и dead-letter state.
- Проверка: Crash между commit и ACK не дублирует эффекты.
- База оценки: По одной точке сбоя до/после commit и delivery.
- Статус: done; passed local real PG/TLS/crash/ENOSPC/bounded24-call burst; hosted unrun; jobs runtime C12.

## C10.04 — Проверить outage и перегрузку

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C10.03; контракты и материалы пакета.
- Результат: Fault tests network cut, disk full, reconnect storm.
- Проверка: Сохранность, квоты и явные ошибки подтверждены.
- База оценки: Agent+collector+center restart по отдельности и ограниченный reconnect burst.
- Статус: done; passed local real PG/TLS/crash/ENOSPC/bounded24-call burst; hosted unrun; jobs runtime C12.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C11 — OpenBao и жизненный цикл машинных доступов (E1)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 18, 33, 34, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C11.01 — Настроить минимальный контур OpenBao

Работа: Подготовка и проектирование. Роль: Инженер эксплуатации / сборки.

- Вход/зависимость: C10; контракты и материалы пакета.
- Результат: Bootstrap/unseal/runbook, scoped policies и backup key procedure.
- Проверка: Приложение не использует root token и открытые пароли в PG.
- База оценки: 1 выбранная версия Bao; KV/Transit только по назначению.
- Статус: done; passed local bounded E1; real Bao/PG/compiled daemons and race-checked TLS reload; limits documented.

## C11.02 — Подключить server secret references

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C11.01; контракты и материалы пакета.
- Результат: Получение ограниченных secrets/ключевых операций по ADR.
- Проверка: Недоступность Bao даёт объявленную деградацию.
- База оценки: Server identity и разрешённые E1 операции без remote target secrets.
- Статус: done; passed local bounded E1; real Bao/PG/compiled daemons and race-checked TLS reload; limits documented.

## C11.03 — Завершить enrollment/renew/revoke

Работа: Реализация. Роль: Разработчик агента/коллектора.

- Вход/зависимость: C11.02; контракты и материалы пакета.
- Результат: Ротация agent/collector identities и защищённое хранение на ОС.
- Проверка: Revoked identity не принимает новые задания/данные по политике.
- База оценки: Agent, collector, server; expiry/renewal и clone case.
- Статус: done; passed local bounded E1; real Bao/PG/compiled daemons and race-checked TLS reload; limits documented.

## C11.04 — Проверить секреты и доверие

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C11.03; контракты и материалы пакета.
- Результат: Проверки logs/artifacts/errors и отказов Bao/cert.
- Проверка: Тестовые секреты отсутствуют в выдаче и отчётах.
- База оценки: Позитивные и негативные auth/TLS/Bao сценарии.
- Статус: done; passed local bounded E1; real Bao/PG/compiled daemons and race-checked TLS reload; limits documented.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C12 — CLI, управление циклом и наблюдаемость (E1)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 7, 12, 22, 34, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C12.01 — Реализовать минимальный CLI

Работа: Подготовка и проектирование. Роль: Backend Go-разработчик.

- Вход/зависимость: C09, C11; контракты и материалы пакета.
- Результат: Login/context, assets list/get, sources/status с JSON и exit codes.
- Проверка: CLI использует тот же API и tenant policy.
- База оценки: Команды E1, pagination/timeout, без секретов в argv.
- Статус: done; passed local bounded E1:39unit/50PG/58fixtures,13operator/17CLI/16browser,8recovery+10agent+10collector race.

## C12.02 — Добавить конфигурацию и диагностику источников

Работа: Реализация. Роль: Разработчик агента/коллектора.

- Вход/зависимость: C12.01; контракты и материалы пакета.
- Результат: Versioned profile, intervals и source health API.
- Проверка: Heartbeat/freshness/completeness не смешиваются.
- База оценки: Agent+collector profiles и last-success/last-contact.
- Статус: done; passed local bounded E1:39unit/50PG/58fixtures,13operator/17CLI/16browser,8recovery+10agent+10collector race.

## C12.03 — Добавить метрики и аудит

Работа: Реализация. Роль: Инженер эксплуатации / сборки.

- Вход/зависимость: C12.02; контракты и материалы пакета.
- Результат: Queue age, import/outbox lag, spool/disk, cert/backup age.
- Проверка: Недоступность/перегрузка обнаруживается по метрикам.
- База оценки: 1 минимальный набор exporters/alerts и structured logs.
- Статус: done; passed local bounded E1:39unit/50PG/58fixtures,13operator/17CLI/16browser,8recovery+10agent+10collector race.

## C12.04 — Проверить операторский сценарий

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C12.03; контракты и материалы пакета.
- Результат: Оператор меняет интервал и видит регулярный результат в UI/CLI.
- Проверка: Изменения аудируются; отключённый источник не делает массовый missing.
- База оценки: 1 человек, 1 агент, 1 collector, 2 tenant негативный тест.
- Статус: done; passed local bounded E1:39unit/50PG/58fixtures,13operator/17CLI/16browser,8recovery+10agent+10collector race.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C13 — Установка, сервисы, обновление и backup (E1)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 4, 12, 31, 33–35, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C13.01 — Оформить постоянные службы и установку

Работа: Подготовка и проектирование. Роль: Инженер эксплуатации / сборки.

- Вход/зависимость: C12; контракты и материалы пакета.
- Результат: Systemd/Windows service по выбранной ОС, конфиги и data dirs.
- Проверка: После перезагрузки весь поддержанный контур стартует сам.
- База оценки: 1 E1 платформа и 1 способ серверной установки.
- Статус: done; actual nonroot units/LoadCredential/PG notify readiness and real kernel reboot/autostart passed.

## C13.02 — Подготовить подписываемые артефакты и версии

Работа: Реализация. Роль: Инженер эксплуатации / сборки.

- Вход/зависимость: C13.01; контракты и материалы пакета.
- Результат: Release manifest/checksums/SBOM и ручное проверяемое обновление.
- Проверка: Артефакты проверяются до применения; версия видна оператору.
- База оценки: Server/agent/collector/UI/CLI; совместимость по C03.
- Статус: done; release14/update19 with schema-safe rollback/SIGKILL/checkpoint, actual systemd server+collector+agent updater and separate CLI/Web passed.

## C13.03 — Реализовать backup/restore и миграции

Работа: Реализация. Роль: Разработчик БД / DBA.

- Вход/зависимость: C13.02; контракты и материалы пакета.
- Результат: Backup PG/artifacts/Bao state, restore runbook и upgrade procedure.
- Проверка: На чистом стенде восстановлены UID, доступы, очередь и история.
- База оценки: 1 round-trip restore и 1 последовательное обновление схемы.
- Статус: done; PG18/Bao9/common checkpoint10/C11 schema31→33 upgrade13; private compiled migration34 fixture through updater19 passed.

## C13.04 — Проверить повторяемость поставки

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C13.03; контракты и материалы пакета.
- Результат: Чистая установка, restart и upgrade/restore отчёт.
- Проверка: Нет зависимости от build machine и потерянных локальных ключей.
- База оценки: 2 чистых среды или восстановленные VM snapshots.
- Статус: done; two independently fresh VM factory runs, each9 checks; no guest Go/Node; restart/update and earlier clean-state restore rehearsal passed.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C14 — Приёмка и выпуск первого рабочего SMB (E1)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 14–15, 33–35, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C14.01 — Подготовить исполнимый план E1 приёмки

Работа: Подготовка и проектирование. Роль: Инженер проверки.

- Вход/зависимость: C13; контракты и материалы пакета.
- Результат: Матрица capabilities E1→AC→тесты и конфигурация стенда.
- Проверка: Отложенные поля и функции не названы реализованными.
- База оценки: AC E1 из §14; реальные host/collector/center.
- Статус: done; reviewed executable15scenario matrix; E1-T07 multi-agent and E1-T14 real24h remain explicit release gates.

## C14.02 — Запустить непрерывный 24-часовой прогон

Работа: Реализация. Роль: Инженер проверки.

- Вход/зависимость: C14.01; контракты и материалы пакета.
- Результат: Периодический сбор плюс restart/network outage с журналом.
- Проверка: Наблюдены реальные циклы, recovery, freshness, отсутствие дублей.
- База оценки: Минимум 24ч; конфигурация интервалов и точек отказа зафиксирована.
- Статус: planned; evidence отсутствует до исполнения.

## C14.03 — Разобрать дефекты и повторить затронутое

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C14.02; контракты и материалы пакета.
- Результат: Исправления в рамках E1 и протокол регрессии.
- Проверка: Нерешённые обязательные дефекты блокируют release claim.
- База оценки: Только выявленные дефекты, не расширение в E2.
- Статус: planned; evidence отсутствует до исполнения.

## C14.04 — Выпустить проверяемую SMB-поставку

Работа: Проверка и передача. Роль: Владелец продукта / руководитель проекта.

- Вход/зависимость: C14.03; контракты и материалы пакета.
- Результат: Release notes, ограничения, install/operations и приёмочный отчёт.
- Проверка: Публикация/деплой только при соответствующем поручении.
- База оценки: 1 релизный кандидат; все AC E1 с фактами passed/failed/unrun.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C15 — Постоянный Windows-агент (E2)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 6, 33, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C15.01 — Уточнить Windows capabilities и права

Работа: Подготовка и проектирование. Роль: Разработчик агента/коллектора.

- Вход/зависимость: C14; контракты и материалы пакета.
- Результат: Матрица ОС/архитектуры/полей и privileges.
- Проверка: Недоступные API не объявлены пустыми данными.
- База оценки: Выбранные Windows versions и стандартные/админ права.
- Статус: planned; evidence отсутствует до исполнения.

## C15.02 — Реализовать Windows-секции inventory

Работа: Реализация. Роль: Разработчик агента/коллектора.

- Вход/зависимость: C15.01; контракты и материалы пакета.
- Результат: Оборудование, ПО/KB, службы, группы, сеть/диски/защита.
- Проверка: Ошибка одной секции не уничтожает другие.
- База оценки: Матрица §6.1 по поддержанным API; scripts policy C01.
- Статус: planned; evidence отсутствует до исполнения.

## C15.03 — Оформить service lifecycle и update

Работа: Реализация. Роль: Разработчик агента/коллектора.

- Вход/зависимость: C15.02; контракты и материалы пакета.
- Результат: Install/start/stop/reboot/upgrade с identity/spool preservation.
- Проверка: После reboot агент не регистрируется новым asset без причины.
- База оценки: Windows service и поддержанный installer.
- Статус: planned; evidence отсутствует до исполнения.

## C15.04 — Проверить реальную Windows

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C15.03; контракты и материалы пакета.
- Результат: Протокол данных, секций, памяти/CPU и recovery.
- Проверка: Заглушки перечислены; реальные сценарии отличаются от mock.
- База оценки: Минимум 1 реальный/VM Windows стенд на профиль прав.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C16 — Постоянный Linux-агент и platform parity (E2)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 6, 33, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C16.01 — Уточнить Linux capabilities и дистрибутивы

Работа: Подготовка и проектирование. Роль: Разработчик агента/коллектора.

- Вход/зависимость: C14; контракты и материалы пакета.
- Результат: Матрица distro/init/package-manager/прав.
- Проверка: Указаны supported и unsupported сочетания.
- База оценки: Выбранные distro/версии из D-06.
- Статус: planned; evidence отсутствует до исполнения.

## C16.02 — Реализовать Linux-секции inventory

Работа: Реализация. Роль: Разработчик агента/коллектора.

- Вход/зависимость: C16.01; контракты и материалы пакета.
- Результат: CPU/RAM, пакеты, службы, accounts, сеть, mounts/security facts.
- Проверка: TCP/UDP и секции независимы; секреты фильтруются.
- База оценки: Матрица §6.1; ограниченные и root права.
- Статус: planned; evidence отсутствует до исполнения.

## C16.03 — Оформить daemon/service и переносимость

Работа: Реализация. Роль: Разработчик агента/коллектора.

- Вход/зависимость: C16.02; контракты и материалы пакета.
- Результат: Systemd/init packaging, data dirs, privileges и update.
- Проверка: Spool/identity сохраняются при обновлении.
- База оценки: Поддержанные service managers и дистрибутивы.
- Статус: planned; evidence отсутствует до исполнения.

## C16.04 — Проверить Windows/Linux контракты

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C16.03; контракты и материалы пакета.
- Результат: Эталонные нормализованные fixtures и resource measurements.
- Проверка: Различия ОС представлены statuses, не выдуманными значениями.
- База оценки: Общие fixtures C03; Linux measurements, полная Windows/Linux сверка в C24.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C17 — Безагентный SSH-сбор Linux (E2)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 6, 18, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C17.01 — Определить remote SSH profile

Работа: Подготовка и проектирование. Роль: Разработчик агента/коллектора.

- Вход/зависимость: C14; контракты и материалы пакета.
- Результат: Host-key policy, permissions, deadlines и attempts.
- Проверка: Unknown host key не принимается молча.
- База оценки: Ключ/пароль/sudo только выбранные безопасные способы.
- Статус: planned; evidence отсутствует до исполнения.

## C17.02 — Подключить scoped credentials через Bao

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C17.01; контракты и материалы пакета.
- Результат: Collector получает только разрешённый доступ задания.
- Проверка: Нет раздачи vault всем агентам и секретов в argv/results.
- База оценки: 1 static SSH credential и policy revoke/rotation.
- Статус: planned; evidence отсутствует до исполнения.

## C17.03 — Реализовать SSH-адаптер

Работа: Реализация. Роль: Разработчик агента/коллектора.

- Вход/зависимость: C17.02; контракты и материалы пакета.
- Результат: Сбор секций через native/read-only commands по решению D-03.
- Проверка: Timeout/cancel/partial отражены в общем контракте.
- База оценки: 1 поддержанная Linux family; расширение по matrix.
- Статус: planned; evidence отсутствует до исполнения.

## C17.04 — Проверить живой SSH и отказы

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C17.03; контракты и материалы пакета.
- Результат: Протокол host key, неверных прав, sudo и отмены.
- Проверка: Нет изменения конфигурации цели и утечки credential.
- База оценки: 1 реальная тестовая цель плюс негативные сценарии.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C18 — Безагентный WinRM-сбор Windows (E2)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 6, 18, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C18.01 — Выбрать защищённый WinRM профиль

Работа: Подготовка и проектирование. Роль: Архитектор.

- Вход/зависимость: C14; контракты и материалы пакета.
- Результат: Auth/TLS policy и prerequisites цели.
- Проверка: Нет требования AllowUnencrypted как безопасного default.
- База оценки: Один заявленный auth метод и cert trust.
- Статус: planned; evidence отсутствует до исполнения.

## C18.02 — Реализовать WinRM credential scope

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C18.01; контракты и материалы пакета.
- Результат: Bao reference и выдача по site/job/target.
- Проверка: Collector не получает весь vault.
- База оценки: 1 test credential и права сбора.
- Статус: planned; evidence отсутствует до исполнения.

## C18.03 — Реализовать WinRM inventory adapter

Работа: Реализация. Роль: Разработчик агента/коллектора.

- Вход/зависимость: C18.02; контракты и материалы пакета.
- Результат: Секции Windows со статусами, отменой/timeout.
- Проверка: Группы, KB, TCP/UDP и локализация не ломают весь scan.
- База оценки: Матрица Windows и политика PowerShell/native.
- Статус: planned; evidence отсутствует до исполнения.

## C18.04 — Проверить реальную Windows по WinRM

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C18.03; контракты и материалы пакета.
- Результат: Данные/ошибки/секреты проверены на поддержанном target.
- Проверка: Mock-run не заменяет живую проверку.
- База оценки: 1 Windows target; full/limited/denied connectivity.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C19 — SNMP и read-only сбор сетевых устройств (E2)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 6, 20, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C19.01 — Определить netdev capability matrix

Работа: Подготовка и проектирование. Роль: Разработчик агента/коллектора.

- Вход/зависимость: C14; контракты и материалы пакета.
- Результат: Vendor/OS/OID/API и поля идентичности/таблиц.
- Проверка: Поддержка декларируется по устройству, а не слову SNMP.
- База оценки: Выбранные Cisco/Huawei либо согласованные аналоги.
- Статус: planned; evidence отсутствует до исполнения.

## C19.02 — Реализовать SNMPv3 access profile

Работа: Реализация. Роль: Разработчик агента/коллектора.

- Вход/зависимость: C19.01; контракты и материалы пакета.
- Результат: Bao refs, security level, retries и rate limits.
- Проверка: v1/v2c доступны лишь по явному разрешённому профилю.
- База оценки: 1 SNMPv3 method; legacy profile отдельным флагом.
- Статус: planned; evidence отсутствует до исполнения.

## C19.03 — Реализовать нормализованный network inventory

Работа: Реализация. Роль: Разработчик агента/коллектора.

- Вход/зависимость: C19.02; контракты и материалы пакета.
- Результат: Interfaces/VLAN/VRF/LAG/FDB/ARP/routes/neighbors по capabilities.
- Проверка: Неизвестные таблицы помечены unavailable/unsupported.
- База оценки: Минимум 1 выбранная модель плюс fixtures другого vendor.
- Статус: planned; evidence отсутствует до исполнения.

## C19.04 — Проверить реальные и частичные ответы

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C19.03; контракты и материалы пакета.
- Результат: Протокол OID permissions, timeout и таблиц.
- Проверка: Секреты community/auth/privacy не попадают в данные.
- База оценки: Vendor lab/доступный стенд; unsupported случаи перечислены.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C20 — Многоисточниковое discovery (E2)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 20, 23, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C20.01 — Задать scope и разрешённые источники

Работа: Подготовка и проектирование. Роль: Backend Go-разработчик.

- Вход/зависимость: C17, C18, C19; контракты и материалы пакета.
- Результат: Tenant/site/VRF/VLAN ranges и запрет расширения scope.
- Проверка: Passive finding не запускает scan чужого диапазона.
- База оценки: Активный IP scope и пассивные DHCP/DNS/ARP/NDP источники.
- Статус: planned; evidence отсутствует до исполнения.

## C20.02 — Реализовать active discovery adapters

Работа: Реализация. Роль: Разработчик агента/коллектора.

- Вход/зависимость: C20.01; контракты и материалы пакета.
- Результат: ICMP/TCP и доступные ARP/NDP probes.
- Проверка: Rate limit/permissions/cancel соблюдены.
- База оценки: IPv4/IPv6 и платформенные ограничения из matrix.
- Статус: planned; evidence отсутствует до исполнения.

## C20.03 — Добавить imports авторизованных таблиц

Работа: Реализация. Роль: Разработчик агента/коллектора.

- Вход/зависимость: C20.02; контракты и материалы пакета.
- Результат: DHCP/DNS/ARP/FDB и базовые AD/hypervisor API наблюдения.
- Проверка: Источник/coverage/TTL фиксируются; API deep import отдельно.
- База оценки: Минимум 2 независимых типа источника, остальные явные capabilities.
- Статус: planned; evidence отсутствует до исполнения.

## C20.04 — Проверить сведение наблюдений

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C20.03; контракты и материалы пакета.
- Результат: Новые/повторные/перекрывающиеся IP обнаружены корректно.
- Проверка: Same IP в разных scopes не сливается.
- База оценки: 2 tenant/VRF и active+passive fixtures.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C21 — Presence и обнаружение пропавших/вернувшихся (E2)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 20, 23, 34, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C21.01 — Задать presence policy

Работа: Подготовка и проектирование. Роль: Архитектор.

- Вход/зависимость: C20; контракты и материалы пакета.
- Результат: TTL/coverage/thresholds и states по типам источников.
- Проверка: Нет перехода missing по одному ICMP failure.
- База оценки: Present/suspect/missing/unknown/reappeared сценарии.
- Статус: planned; evidence отсутствует до исполнения.

## C21.02 — Реализовать projection и evidence

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C21.01; контракты и материалы пакета.
- Результат: First/last seen, source health, transitions и события.
- Проверка: Late package не откатывает текущее presence.
- База оценки: Несколько источников с разными collected/received times.
- Статус: planned; evidence отсутствует до исполнения.

## C21.03 — Добавить UI/CLI представление

Работа: Реализация. Роль: Frontend-разработчик.

- Вход/зависимость: C21.02; контракты и материалы пакета.
- Результат: Причины изменений и фильтры freshness/presence.
- Проверка: Business lifecycle показан отдельно.
- База оценки: Карточка, список и журнал evidence.
- Статус: planned; evidence отсутствует до исполнения.

## C21.04 — Проверить массовые сбои источников

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C21.03; контракты и материалы пакета.
- Результат: Fault cases collector/site down и partial scan.
- Проверка: Отказ источника не вызывает массовое исчезновение.
- База оценки: 2 коллектора/области и пропуск одного полного цикла.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C22 — Доказательная топология L2/L3 (E2)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 5, 20, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C22.01 — Спроектировать нормализованные связи

Работа: Подготовка и проектирование. Роль: Архитектор.

- Вход/зависимость: C19, C20, C21; контракты и материалы пакета.
- Результат: Endpoints, evidence/confidence, VLAN/VRF/LAG и timestamps.
- Проверка: Предположение FDB отличается от подтверждённого LLDP.
- База оценки: L2 и L3 relation types; directional evidence.
- Статус: planned; evidence отсутствует до исполнения.

## C22.02 — Реализовать topology reconciliation

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C22.01; контракты и материалы пакета.
- Результат: Сведение соседей/интерфейсов, aging и конфликтов.
- Проверка: Повторные связи не дублируются, ручное подтверждение сохранено.
- База оценки: LLDP/CDP fixtures, trunk/aggregation/несколько hops.
- Статус: planned; evidence отсутствует до исполнения.

## C22.03 — Реализовать граф и экспорт

Работа: Реализация. Роль: Frontend-разработчик.

- Вход/зависимость: C22.02; контракты и материалы пакета.
- Результат: Фильтры, карточка связи, SVG/PNG и scoped выдача.
- Проверка: Большой граф ограничен и не раскрывает чужой tenant.
- База оценки: 1 live topology и крупный synthetic graph.
- Статус: planned; evidence отсутствует до исполнения.

## C22.04 — Проверить реальные устройства и неоднозначность

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C22.03; контракты и материалы пакета.
- Результат: Эталонный граф и объяснимые связи.
- Проверка: Схема не выдаёт MAC за прямой кабель.
- База оценки: Минимум 2 связанных устройства/поддержанных источника.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C23 — Portable-аудит и безопасный offline-пакет (E2)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 7–8, 18–19, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C23.01 — Утвердить portable schema/crypto ADR

Работа: Подготовка и проектирование. Роль: Архитектор.

- Вход/зависимость: C10, C11, C17, C18, C19; контракты и материалы пакета.
- Результат: Формат manifest/records, signature/encryption/key IDs и trust.
- Проверка: Нет самодельных примитивов и неясных подписываемых байтов.
- База оценки: 1 audited library/format, major/minor compatibility.
- Статус: planned; evidence отсутствует до исполнения.

## C23.02 — Реализовать разовый portable workflow

Работа: Реализация. Роль: Разработчик агента/коллектора.

- Вход/зависимость: C23.01; контракты и материалы пакета.
- Результат: Host/network/mixed collect, preview/progress, cancel и export.
- Проверка: Не устанавливает службу и не требует live PG/Bao offline.
- База оценки: Один выбранный язык/платформы по D-07; общий SDK.
- Статус: planned; evidence отсутствует до исполнения.

## C23.03 — Реализовать resume upload и import пакета

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C23.02; контракты и материалы пакета.
- Результат: Limits/quarantine/staging/checkpoints/mapping и dedup.
- Проверка: Path traversal/zip bomb/invalid signature отклонены.
- База оценки: File и HTTPS пути, same ID different digest.
- Статус: planned; evidence отсутствует до исполнения.

## C23.04 — Проверить offline parity и отсутствие секретов

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C23.03; контракты и материалы пакета.
- Результат: Один набор данных через online и file даёт эквивалентный реестр.
- Проверка: Пароли/bundle не входят в пакет; late observations сохранены.
- База оценки: Реальный аудит host и разрешённой network цели.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C24 — Приёмка агентного и безагентного сбора (E2)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 6, 14–15, 33–34, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C24.01 — Свести platform/vendor matrix

Работа: Подготовка и проектирование. Роль: Инженер проверки.

- Вход/зависимость: C15, C16, C22, C23; контракты и материалы пакета.
- Результат: Capabilities и тесты Windows/Linux/netdev/portable.
- Проверка: Unsupported не скрыты за общим claimed parity.
- База оценки: Все адаптеры C15–23 и их runtime dependencies.
- Статус: planned; evidence отсутствует до исполнения.

## C24.02 — Проверить один актив разными источниками

Работа: Реализация. Роль: Инженер проверки.

- Вход/зависимость: C24.01; контракты и материалы пакета.
- Результат: Agent+SSH/WinRM+portable+discovery reconciliation tests.
- Проверка: История/ответственные не теряются, неопределённость видна.
- База оценки: Смена IP/hostname, clone VM, source collision.
- Статус: planned; evidence отсутствует до исполнения.

## C24.03 — Проверить длительные циклы и cancellation

Работа: Реализация. Роль: Инженер проверки.

- Вход/зависимость: C24.02; контракты и материалы пакета.
- Результат: Многосуточный/согласованный E2 soak и network failures.
- Проверка: Нет гонок lease/повторных эффектов и ложного missing.
- База оценки: Длительность и workload фиксируются перед запуском.
- Статус: planned; evidence отсутствует до исполнения.

## C24.04 — Подготовить E2 release и документацию

Работа: Проверка и передача. Роль: Владелец продукта / руководитель проекта.

- Вход/зависимость: C24.03; контракты и материалы пакета.
- Результат: Руководства deploy/credentials/network scopes и limitations.
- Проверка: Каждый AC E2 имеет evidence или release blocker.
- База оценки: Один согласованный набор платформ/устройств.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C25 — Полная reconciliation, merge и split (E3)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 5, 19, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C25.01 — Уточнить сильные/слабые идентификаторы

Работа: Подготовка и проектирование. Роль: Архитектор.

- Вход/зависимость: C24; контракты и материалы пакета.
- Результат: Namespace/uniqueness/source-trust правила по типам активов.
- Проверка: IP/MAC/hostname по отдельности не универсальный ключ.
- База оценки: Physical/VM/network/cloud examples.
- Статус: planned; evidence отсутствует до исполнения.

## C25.02 — Реализовать conflict resolution

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C25.01; контракты и материалы пакета.
- Результат: Кандидаты и ручное подтверждение с аудитом.
- Проверка: Нельзя молча склеить конфликтующие serial/UUID.
- База оценки: Несколько источников и overlapping scopes.
- Статус: planned; evidence отсутствует до исполнения.

## C25.03 — Реализовать merge/split и redirects

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C25.02; контракты и материалы пакета.
- Результат: Canonical UID, aliases, перенос связей и provenance.
- Проверка: Старые UID разрешаются; split не переиспользует UID.
- База оценки: Две карточки merge и разделение ошибочного merge.
- Статус: planned; evidence отсутствует до исполнения.

## C25.04 — Проверить исправимость и конкурентность

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C25.03; контракты и материалы пакета.
- Результат: Rollback/compensating history и concurrent edits.
- Проверка: Наблюдения не потеряны, межtenant merge запрещён.
- База оценки: Conflict, merge/split, outbox/search replay fixtures.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C26 — AM/CMDB, ПО, компоненты и связи (E3)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 5, 9, 19, 28, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C26.01 — Уточнить asset/CI/component/service модель

Работа: Подготовка и проектирование. Роль: Архитектор.

- Вход/зависимость: C25; контракты и материалы пакета.
- Результат: ADR CMDB границ и типизированные отношения.
- Проверка: Рабочая трактовка smdb подтверждена либо явно ограничена.
- База оценки: Asset/CI/component/service/software types.
- Статус: planned; evidence отсутствует до исполнения.

## C26.02 — Реализовать типизированные сведения

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C26.01; контракты и материалы пакета.
- Результат: Software product/installations, components и business fields.
- Проверка: Сбор не затирает управленческие поля.
- База оценки: Основные фильтруемые поля нормализованы, вариативные в JSONB.
- Статус: planned; evidence отсутствует до исполнения.

## C26.03 — Расширить API и карточки

Работа: Реализация. Роль: Frontend-разработчик.

- Вход/зависимость: C26.02; контракты и материалы пакета.
- Результат: Вкладки/сравнение наблюдений/relations и optimistic concurrency.
- Проверка: Long/empty/partial данные доступны с provenance.
- База оценки: Типы активов и контракты выбранного объёма.
- Статус: planned; evidence отсутствует до исполнения.

## C26.04 — Проверить историю и ownership

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C26.03; контракты и материалы пакета.
- Результат: Migration/contract/UI tests и архитектурные проверки.
- Проверка: Модули не пишут в чужие таблицы.
- База оценки: Связи, события, cursor pagination и large lists.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C27 — Полная ответственность и оргструктура (E3)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 3, 21, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C27.01 — Определить subjects и оргисточники

Работа: Подготовка и проектирование. Роль: Архитектор.

- Вход/зависимость: C26; контракты и материалы пакета.
- Результат: Person/team, business owner/technical/custodian и ownership ADR.
- Проверка: Collector не считается ответственным лицом.
- База оценки: 1 локальный org source; внешний sync позже C31.
- Статус: planned; evidence отсутствует до исполнения.

## C27.02 — Реализовать назначения и передачу

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C27.01; контракты и материалы пакета.
- Результат: Atomic assignment, intervals/history, fallback при уходе сотрудника.
- Проверка: У актива не возникает периода без accountable role.
- База оценки: Person→person/team и deactivation cases.
- Статус: planned; evidence отсутствует до исполнения.

## C27.03 — Добавить операторские рабочие списки

Работа: Реализация. Роль: Frontend-разработчик.

- Вход/зависимость: C27.02; контракты и материалы пакета.
- Результат: На мне/на команде/не распределено и bulk assign по правам.
- Проверка: Bulk не обходит tenant и optimistic concurrency.
- База оценки: Фильтры и поддержанные массовые операции.
- Статус: planned; evidence отсутствует до исполнения.

## C27.04 — Проверить права и конкуренцию передачи

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C27.03; контракты и материалы пакета.
- Результат: Audit и concurrent assignment tests.
- Проверка: Не потеряны исторические интервалы и основания.
- База оценки: 2 оператора, removed user, group owner absent.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C28 — PoC полнотекстового поиска: Tantivy / Bluge (E3)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 24, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C28.01 — Определить тестовый корпус и критерии

Работа: Подготовка и проектирование. Роль: Архитектор.

- Вход/зависимость: C25; контракты и материалы пакета.
- Результат: RU/EN/IP/FQDN/serial fields, filters/ranking и workload.
- Проверка: Критерии и веса выбора известны до результатов.
- База оценки: Репрезентативный корпус с ACL/tenant и tombstones.
- Статус: planned; evidence отсутствует до исполнения.

## C28.02 — Собрать два изолированных PoC

Работа: Реализация. Роль: Разработчик поискового контура.

- Вход/зависимость: C28.01; контракты и материалы пакета.
- Результат: Tantivy и Bluge adapters без замены PG source of truth.
- Проверка: Одинаковые операции и данные у обоих движков.
- База оценки: Два кандидата; build/runtime/license matrix.
- Статус: planned; evidence отсутствует до исполнения.

## C28.03 — Измерить поиск и восстановление

Работа: Реализация. Роль: Инженер проверки.

- Вход/зависимость: C28.02; контракты и материалы пакета.
- Результат: Latency/resources/rebuild/update/delete и ACL leakage tests.
- Проверка: Отзыв доступа не зависит от устаревшего индекса.
- База оценки: Corpus size/железо/нагрузка опубликованы, без маркетинговых SLA.
- Статус: planned; evidence отсутствует до исполнения.

## C28.04 — Выбрать движок и runtime topology

Работа: Проверка и передача. Роль: Архитектор.

- Вход/зависимость: C28.03; контракты и материалы пакета.
- Результат: ADR с writer/readers, snapshots и последствиями CGO/Rust.
- Проверка: Решение опирается на факты, а не только язык backend.
- База оценки: 1 выбранный engine; оставшиеся риски перечислены.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C29 — Поисковая проекция, API и UI (E3)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 23–24, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C29.01 — Реализовать outbox index consumer

Работа: Подготовка и проектирование. Роль: Разработчик поискового контура.

- Вход/зависимость: C26, C28; контракты и материалы пакета.
- Результат: Idempotent upsert/delete/merge aliases с checkpoint.
- Проверка: Crash/replay не теряет и не дублирует актуальное состояние.
- База оценки: Выбранный engine, aggregate versions и tombstones.
- Статус: planned; evidence отсутствует до исполнения.

## C29.02 — Реализовать rebuild и degradation

Работа: Реализация. Роль: Разработчик поискового контура.

- Вход/зависимость: C29.01; контракты и материалы пакета.
- Результат: Snapshot/checkpoint/catch-up, lag и exact-PG fallback policy.
- Проверка: Fallback не называется эквивалентным FTS.
- База оценки: Rebuild на копии данных и отказ индекса.
- Статус: planned; evidence отсутствует до исполнения.

## C29.03 — Добавить search API/UI

Работа: Реализация. Роль: Frontend-разработчик.

- Вход/зависимость: C29.02; контракты и материалы пакета.
- Результат: Query/filters/facets/snippets с tenant/ACL enforcement.
- Проверка: Чужие counts/snippets и отозванные данные не раскрываются.
- База оценки: Все публичные search surfaces и pagination.
- Статус: planned; evidence отсутствует до исполнения.

## C29.04 — Проверить обновления и доступы

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C29.03; контракты и материалы пакета.
- Результат: Real PG/outbox/index integration и concurrent changes.
- Проверка: Rebuild сходится с authoritative PG.
- База оценки: Deletion, merge, revoked ACL, burst imports.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C30 — Нагрузка 100 активных пользователей и E3 приёмка (E3)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 12, 15, 27, 29, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C30.01 — Согласовать нагрузочный паспорт

Работа: Подготовка и проектирование. Роль: Инженер проверки.

- Вход/зависимость: C27, C29; контракты и материалы пакета.
- Результат: Registered/active users, mix, think-time, data size, hardware и SLO.
- Проверка: 100 пользователей определены операционно.
- База оценки: 100 concurrent active плюс background ingest, warmup/duration.
- Статус: planned; evidence отсутствует до исполнения.

## C30.02 — Реализовать воспроизводимый workload

Работа: Реализация. Роль: Инженер проверки.

- Вход/зависимость: C30.01; контракты и материалы пакета.
- Результат: Карточки/поиск/фильтры/правки/топология/импорт.
- Проверка: Нет нулевых операций или искусственно пустого корпуса.
- База оценки: Одна согласованная смесь с реальными API.
- Статус: planned; evidence отсутствует до исполнения.

## C30.03 — Измерить и устранить узкие места

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C30.02; контракты и материалы пакета.
- Результат: Профили SQL/pool/worker/search и исправления по данным.
- Проверка: Публикуются p95/p99/errors/resources/queue lag.
- База оценки: Один initial run и адресные повторные измерения.
- Статус: planned; evidence отсутствует до исполнения.

## C30.04 — Закрыть E3 приёмку

Работа: Проверка и передача. Роль: Владелец продукта / руководитель проекта.

- Вход/зависимость: C30.03; контракты и материалы пакета.
- Результат: Протокол функциональных/контрактных/performance проверок.
- Проверка: Без протокола нет заявления о ёмкости.
- База оценки: AC E3 и эксплуатационные ограничения.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C31 — Интеграции и внешние контракты (E4)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 11, 22–23, 28, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C31.01 — Определить первый набор интеграций

Работа: Подготовка и проектирование. Роль: Архитектор.

- Вход/зависимость: C30; контракты и материалы пакета.
- Результат: Scope/direction/version/auth и data ownership contracts.
- Проверка: Нет двусторонней конкурирующей master-записи.
- База оценки: Приоритетные org directory и 1 asset/API integration.
- Статус: planned; evidence отсутствует до исполнения.

## C31.02 — Реализовать import/export adapters

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C31.01; контракты и материалы пакета.
- Результат: Versioned CSV/API mapping и инкрементальная синхронизация.
- Проверка: Сохраняются source ids/provenance и tenant scope.
- База оценки: Два согласованных adapter направления.
- Статус: planned; evidence отсутствует до исполнения.

## C31.03 — Реализовать delivery/retry/audit

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C31.02; контракты и материалы пакета.
- Результат: Durable outbound delivery или webhook с idempotency и auth.
- Проверка: Replay не повторяет внешние действия без policy.
- База оценки: Подписанные/аутентифицированные endpoints по контракту.
- Статус: planned; evidence отсутствует до исполнения.

## C31.04 — Проверить контракты с реальными системами

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C31.03; контракты и материалы пакета.
- Результат: Integration evidence и совместимость версий.
- Проверка: Mock и реальное подключение разделены.
- База оценки: Только разрешённые стенды; внешние credentials prerequisite.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C32 — Миграция данных Python v1 (E4)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 13, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C32.01 — Инвентаризировать реально сохранённые данные v1

Работа: Подготовка и проектирование. Роль: Разработчик БД / DBA.

- Вход/зависимость: C30; контракты и материалы пакета.
- Результат: Mapping snapshot/JSON/surv/credentials и gaps.
- Проверка: Потерянные исходные facts не выдумываются.
- База оценки: Поддержанные v1 fixtures, app key и export layouts.
- Статус: planned; evidence отсутствует до исполнения.

## C32.02 — Реализовать миграционный adapter

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C32.01; контракты и материалы пакета.
- Результат: Idempotent import с tenant/source/status annotations.
- Проверка: Недостающие поля помечены unknown, UID mappings сохранены.
- База оценки: Одна зафиксированная версия v1 и целевая v2 schema.
- Статус: planned; evidence отсутствует до исполнения.

## C32.03 — Разработать процедуру credentials/cutover

Работа: Реализация. Роль: Архитектор.

- Вход/зависимость: C32.02; контракты и материалы пакета.
- Результат: Защищённый перенос либо re-enrollment, rollback и shadow plan.
- Проверка: Секреты не попадают в открытый dump.
- База оценки: Доступность старого key — prerequisite, не попытка его угадать.
- Статус: planned; evidence отсутствует до исполнения.

## C32.04 — Сверить миграцию на эталонах

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C32.03; контракты и материалы пакета.
- Результат: Counts/sections/identity/ownership/history и rollback report.
- Проверка: Известный дефект apply_role_guess не обходится молча заглушкой.
- База оценки: Использовать сохранённые fixtures; исправление v1 — отдельный scope.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C33 — Промышленная поставка и сопровождение (E4)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 4, 12, 16, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C33.01 — Закрепить platform/version support policy

Работа: Подготовка и проектирование. Роль: Инженер эксплуатации / сборки.

- Вход/зависимость: C31, C32; контракты и материалы пакета.
- Результат: Matrix ОС/CPU/Go/PG/Bao и сроки совместимости.
- Проверка: Непроверенные платформы не названы supported.
- База оценки: Поддержанные binary/container и agent installers.
- Статус: planned; evidence отсутствует до исполнения.

## C33.02 — Укрепить supply chain и upgrade path

Работа: Реализация. Роль: Инженер эксплуатации / сборки.

- Вход/зависимость: C33.01; контракты и материалы пакета.
- Результат: Pinned dependencies, signatures/SBOM, rollout/canary/revoke.
- Проверка: Обновление проверяется и имеет план остановки/восстановления.
- База оценки: Server/collector/agent/UI/CLI по одной версии релиза.
- Статус: planned; evidence отсутствует до исполнения.

## C33.03 — Оформить monitoring и эксплуатационные runbooks

Работа: Реализация. Роль: Инженер эксплуатации / сборки.

- Вход/зависимость: C33.02; контракты и материалы пакета.
- Результат: Install/upgrade/restore/cert rotation/reconnect/disk-full guides.
- Проверка: Независимый оператор воспроизводит критические процедуры.
- База оценки: Все основные состояния контура без секретов в документах.
- Статус: planned; evidence отсутствует до исполнения.

## C33.04 — Проверить чистую поставку и поддержку

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C33.03; контракты и материалы пакета.
- Результат: Install/upgrade/backup/restore acceptance на заявленной matrix.
- Проверка: Фактические проверки и ограничения опубликованы.
- База оценки: Чистые VM/образы по поддержанным сочетаниям.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C34 — Пилот, внедрение и стабилизация (E4)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 12, 14–16, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C34.01 — Подготовить согласованный пилотный scope

Работа: Подготовка и проектирование. Роль: Владелец продукта / руководитель проекта.

- Вход/зависимость: C33; контракты и материалы пакета.
- Результат: Цели, владельцы, доступы, окна, данные, успех и rollback.
- Проверка: Активные проверки ограничены разрешёнными диапазонами.
- База оценки: Одна пилотная организация/площадка и утверждённые targets.
- Статус: planned; evidence отсутствует до исполнения.

## C34.02 — Развернуть и обучить операторов

Работа: Реализация. Роль: Инженер эксплуатации / сборки.

- Вход/зависимость: C34.01; контракты и материалы пакета.
- Результат: Рабочая установка, accounts/roles, agent/collector rollout и обучение.
- Проверка: Пользователь выполняет типовые задачи без разработчика.
- База оценки: Пилотные системы и утверждённые доступы, не автоматический production deploy.
- Статус: planned; evidence отсутствует до исполнения.

## C34.03 — Собрать feedback и стабилизировать

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C34.02; контракты и материалы пакета.
- Результат: Реестр дефектов/приоритетов и исправления scope пилота.
- Проверка: Подтверждены сохранность, свежесть и recovery.
- База оценки: Согласованный период пилота и реальные сценарии.
- Статус: planned; evidence отсутствует до исполнения.

## C34.04 — Оформить передачу в эксплуатацию

Работа: Проверка и передача. Роль: Владелец продукта / руководитель проекта.

- Вход/зависимость: C34.03; контракты и материалы пакета.
- Результат: Пилотный отчёт, runbooks, владельцы и SLA/SLO proposal.
- Проверка: Незакрытые риски не скрыты в слове готово.
- База оценки: Acceptance sign-off и план rollout требуют решения заказчика.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C35 — Раздельные API/worker и несколько экземпляров (E5)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 28, 31, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C35.01 — Вынести процессы без смены доменной модели

Работа: Подготовка и проектирование. Роль: Backend Go-разработчик.

- Вход/зависимость: C34; контракты и материалы пакета.
- Результат: Роли api/worker/combined с общими контрактами и конфигом.
- Проверка: API не выполняет длительный scan/import внутри HTTP.
- База оценки: Те же данные и domain code, отдельные resource budgets.
- Статус: planned; evidence отсутствует до исполнения.

## C35.02 — Обеспечить конкурентное исполнение

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C35.01; контракты и материалы пакета.
- Результат: Lease/claim/version/locks без reliance на процессную память.
- Проверка: Два workers не применяют один эффект дважды.
- База оценки: 2 API и 2 workers; общий PG и artifacts.
- Статус: planned; evidence отсутствует до исполнения.

## C35.03 — Развернуть согласованную поисковую topology

Работа: Реализация. Роль: Разработчик поискового контура.

- Вход/зависимость: C35.02; контракты и материалы пакета.
- Результат: Writer/readers и snapshot access по ADR C28.
- Проверка: Нет конкурентной записи в общий файловый индекс.
- База оценки: Выбранный engine и multi-instance placement.
- Статус: planned; evidence отсутствует до исполнения.

## C35.04 — Проверить equivalence и отказ реплики

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C35.03; контракты и материалы пакета.
- Результат: Combined vs split, API failover и worker saturation.
- Проверка: Права/сессии/задачи не теряются, API SLO измерен.
- База оценки: AC-41/44/45 с реальным отключением процессов.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C36 — Пул SQL, индексы и эксплуатация PG (E5)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 9–10, 12, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C36.01 — Выбрать SQL pool продукт/режим

Работа: Подготовка и проектирование. Роль: Разработчик БД / DBA.

- Вход/зависимость: C35; контракты и материалы пакета.
- Результат: ADR PgBouncer/pgBalancer/иной по требуемой функции.
- Проверка: Pool не подменяет shard routing или HA.
- База оценки: Транзакции/prepared statements/миграции/jobs compatibility.
- Статус: planned; evidence отсутствует до исполнения.

## C36.02 — Измерить запросы и соединения

Работа: Реализация. Роль: Разработчик БД / DBA.

- Вход/зависимость: C36.01; контракты и материалы пакета.
- Результат: Slow queries, EXPLAIN и pool saturation baseline.
- Проверка: Оптимизация опирается на фактические запросы.
- База оценки: Нагрузка C30 на split deployment.
- Статус: planned; evidence отсутствует до исполнения.

## C36.03 — Настроить retention/partition обслуживание

Работа: Реализация. Роль: Разработчик БД / DBA.

- Вход/зависимость: C36.02; контракты и материалы пакета.
- Результат: Policy observations/artifacts/audit/outbox и maintenance.
- Проверка: Checkpoint/rebuild не теряет нужные события при очистке.
- База оценки: Объёмы/сроки из D-08, partitioning только при необходимости.
- Статус: planned; evidence отсутствует до исполнения.

## C36.04 — Проверить отказ пула и обновление

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C36.03; контракты и материалы пакета.
- Результат: Reconnect/transaction/timeout и migration tests.
- Проверка: Нет скрытой зависимости от session state.
- База оценки: Реальный pool и выбранные PG/driver версии.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C37 — Каталог шардов и перенос tenant (E5)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 10, 19, 25, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C37.01 — Уточнить partition key и catalog model

Работа: Подготовка и проектирование. Роль: Архитектор.

- Вход/зависимость: C36; контракты и материалы пакета.
- Результат: Tenant→shard/home/DR/residency/epoch ADR.
- Проверка: Large tenant и межплощадочные связи рассмотрены.
- База оценки: Ключ и ограничения межшардовых транзакций.
- Статус: planned; evidence отсутствует до исполнения.

## C37.02 — Реализовать routing и размещение jobs

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C37.01; контракты и материалы пакета.
- Результат: Доступ к shard по catalog с failure-closed policy.
- Проверка: Потеря catalog не пишет данные в случайную БД.
- База оценки: 2 логических shard и одна управляемая catalog authority.
- Статус: planned; evidence отсутствует до исполнения.

## C37.03 — Реализовать tenant migration workflow

Работа: Реализация. Роль: Разработчик БД / DBA.

- Вход/зависимость: C37.02; контракты и материалы пакета.
- Результат: Copy/catch-up/fence/cutover/verify/rollback.
- Проверка: Asset_uid не меняется, competing writer исключён.
- База оценки: Tenant A переносится между 2 тестовыми кластерами.
- Статус: planned; evidence отсутствует до исполнения.

## C37.04 — Проверить изоляцию и региональные запросы

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C37.03; контракты и материалы пакета.
- Результат: Cross-shard aggregation/ACL/UID/duplicates tests.
- Проверка: Нет глобальных JOIN/FK предположений.
- База оценки: 2 tenant/shard, partial failure и ограниченный fan-out.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C38 — HA PostgreSQL и георезервирование (E5)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 10, 25, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C38.01 — Определить регионы и RPO/RTO

Работа: Подготовка и проектирование. Роль: Архитектор.

- Вход/зависимость: C37; контракты и материалы пакета.
- Результат: Residency, RTT, sync/async, failure domains и ownership ADR.
- Проверка: Async loss и latency tradeoffs названы явно.
- База оценки: Одна home/DR пара на тестовый shard.
- Статус: planned; evidence отсутствует до исполнения.

## C38.02 — Подготовить replication и election/fencing

Работа: Реализация. Роль: Инженер эксплуатации / сборки.

- Вход/зависимость: C38.01; контракты и материалы пакета.
- Результат: Выбранный HA stack, promote и routing epoch changes.
- Проверка: Старый writer не принимает запись после promotion.
- База оценки: Один writer на shard; подтверждённый механизм fencing.
- Статус: planned; evidence отсутствует до исполнения.

## C38.03 — Реализовать failover/failback runbooks

Работа: Реализация. Роль: Инженер эксплуатации / сборки.

- Вход/зависимость: C38.02; контракты и материалы пакета.
- Результат: Endpoints/leases/jobs/search ownership recovery.
- Проверка: Задания старой epoch не создают повторных эффектов.
- База оценки: PG primary loss, region partition и intentional failback.
- Статус: planned; evidence отсутствует до исполнения.

## C38.04 — Измерить fault behaviour

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C38.03; контракты и материалы пакета.
- Результат: Потеря региона/partition/heal с measured RPO/RTO.
- Проверка: Не заявлены exactly-once и zero loss без доказательства.
- База оценки: Timestamped failure evidence и committed data checks.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C39 — Восстановление всего контура (E5)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 12, 18, 23–25, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C39.01 — Составить согласованный DR-набор

Работа: Подготовка и проектирование. Роль: Инженер эксплуатации / сборки.

- Вход/зависимость: C38; контракты и материалы пакета.
- Результат: PG/catalog/artifacts/Bao keys/outbox/checkpoints/search state inventory.
- Проверка: Нет компонента вне restore dependency graph.
- База оценки: Backup set и привязки версий/ключей/регионов.
- Статус: planned; evidence отсутствует до исполнения.

## C39.02 — Реализовать Bao/artifact recovery

Работа: Реализация. Роль: Инженер эксплуатации / сборки.

- Вход/зависимость: C39.01; контракты и материалы пакета.
- Результат: Unseal/restore/permissions и доступ к подписанным пакетам.
- Проверка: DR не теряет ключи расшифровки и audit policy.
- База оценки: Тестовые secrets/ключи, допустимый residency.
- Статус: planned; evidence отсутствует до исполнения.

## C39.03 — Восстановить jobs/dedup/search

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C39.02; контракты и материалы пакета.
- Результат: Replay/rebuild с checkpoints и ledger после DR.
- Проверка: Повтор старого package не дублирует эффект.
- База оценки: Один package до/после DR, merge aliases и tombstones.
- Статус: planned; evidence отсутствует до исполнения.

## C39.04 — Провести полный restore drill

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C39.03; контракты и материалы пакета.
- Результат: Новая чистая среда с восстановленными UI/CLI/collectors.
- Проверка: Measured restore time и data-loss согласованы с RPO/RTO.
- База оценки: Полный согласованный backup set без обращения к старому live primary.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C40 — Enterprise-приёмка и критерии выделения сервисов (E5)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 14–15, 25, 28–29, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C40.01 — Повторить нагрузку в распределённом профиле

Работа: Подготовка и проектирование. Роль: Инженер проверки.

- Вход/зависимость: C39; контракты и материалы пакета.
- Результат: Отчёт CPU/RAM/SQL/search/queue и API p95/p99.
- Проверка: Сравнение с C30 по одинаковым данным и workload.
- База оценки: 100 active как минимум согласованного профиля, не произвольный capacity claim.
- Статус: planned; evidence отсутствует до исполнения.

## C40.02 — Проверить географические отказы и upgrades

Работа: Реализация. Роль: Инженер проверки.

- Вход/зависимость: C40.01; контракты и материалы пакета.
- Результат: Fault/canary/rollback/cert tests на HA topology.
- Проверка: Resilience и version skew подтверждены.
- База оценки: Home/DR, 2 API/workers и поддержанные collector/agent версии.
- Статус: planned; evidence отсутствует до исполнения.

## C40.03 — Оценить необходимость отдельных сервисов

Работа: Реализация. Роль: Архитектор.

- Вход/зависимость: C40.02; контракты и материалы пакета.
- Результат: Измеренный decision record кандидатов extraction.
- Проверка: Выделение не делается ради количества пользователей.
- База оценки: Import/search/reports/integrations; ownership/contracts/backfill plan.
- Статус: planned; evidence отсутствует до исполнения.

## C40.04 — Закрыть первую волну и передать enterprise профиль

Работа: Проверка и передача. Роль: Владелец продукта / руководитель проекта.

- Вход/зависимость: C40.03; контракты и материалы пакета.
- Результат: Протокол AC-01–55 по целевой matrix, limitations/runbooks.
- Проверка: Плановые и непроверенные возможности не названы готовыми.
- База оценки: Scope первой волны, все релизы/коммиты и данные испытаний.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C41 — Процессы ЖЦ и модель склада (W2)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 21, 25, 35, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C41.01 — Согласовать scope второй волны

Работа: Подготовка и проектирование. Роль: Владелец продукта / руководитель проекта.

- Вход/зависимость: C30; контракты и материалы пакета.
- Результат: Процессы приём/выдача/возврат/ремонт/списание и границы учёта.
- Проверка: Финансовый/SAM учёт не включён молча.
- База оценки: Один утверждаемый минимальный набор бизнес-процессов.
- Статус: planned; evidence отсутствует до исполнения.

## C41.02 — Спроектировать складские сущности

Работа: Реализация. Роль: Архитектор.

- Вход/зависимость: C41.01; контракты и материалы пакета.
- Результат: ER serial item/lot/location/bin/reserve/movement и компонент.
- Проверка: Lot id не выдаётся за asset_uid экземпляра.
- База оценки: Серийные и количественные предметы, состояния/единицы.
- Статус: planned; evidence отсутствует до исполнения.

## C41.03 — Определить транзакционные инварианты

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C41.02; контракты и материалы пакета.
- Результат: Ownership lifecycle/stock и команды/события.
- Проверка: Нельзя двойную выдачу и отрицательный остаток.
- База оценки: Операции movements/reservations и concurrent cases.
- Статус: planned; evidence отсутствует до исполнения.

## C41.04 — Утвердить приёмку волны 2

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C41.03; контракты и материалы пакета.
- Результат: Новые process AC и traceability, версия спецификации.
- Проверка: Сценарии и документы актов согласованы до кода.
- База оценки: Роли/основания/approval и inventory reconciliation.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C42 — Жизненный цикл и передачи активов (W2)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 21, 25, INC-08, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C42.01 — Реализовать lifecycle state machine

Работа: Подготовка и проектирование. Роль: Backend Go-разработчик.

- Вход/зависимость: C41; контракты и материалы пакета.
- Результат: Переходы с guard/roles/revision и историей.
- Проверка: Missing не вызывает автоматическое списание.
- База оценки: Согласованные states и переходы из C41.
- Статус: planned; evidence отсутствует до исполнения.

## C42.02 — Реализовать выдачу/возврат и approvals

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C42.01; контракты и материалы пакета.
- Результат: Команды передачи, ответственные и основания/акты.
- Проверка: Технический owner и материально-ответственный не смешаны.
- База оценки: Предусмотренные юридически/организационно процедуры.
- Статус: planned; evidence отсутствует до исполнения.

## C42.03 — Добавить UI/CLI процессов

Работа: Реализация. Роль: Frontend-разработчик.

- Вход/зависимость: C42.02; контракты и материалы пакета.
- Результат: Рабочие списки, документы и доступные переходы.
- Проверка: Backend проверяет все guards независимо от UI.
- База оценки: Оператор/согласующий/получатель по scope.
- Статус: planned; evidence отсутствует до исполнения.

## C42.04 — Проверить transitions и concurrent actions

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C42.03; контракты и материалы пакета.
- Результат: Process tests возврата/списания/отмены.
- Проверка: История и ответственность не теряются.
- База оценки: Два оператора и частичный сбой процесса.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C43 — Склад, партии, резервы и остатки (W2)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 25, INC-08, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C43.01 — Реализовать catalog/locations/items

Работа: Подготовка и проектирование. Роль: Backend Go-разработчик.

- Вход/зависимость: C41; контракты и материалы пакета.
- Результат: Модели серийных экземпляров/партий и мест хранения.
- Проверка: Один serial не существует как два экземпляра без конфликта.
- База оценки: Item/lot/serial/unit/location/bin из C41.
- Статус: planned; evidence отсутствует до исполнения.

## C43.02 — Реализовать stock movement ledger

Работа: Реализация. Роль: Разработчик БД / DBA.

- Вход/зависимость: C43.01; контракты и материалы пакета.
- Результат: Atomic receive/issue/return/transfer и derived balance.
- Проверка: История восстанавливает остаток; отрицательные запрещены.
- База оценки: 2 склада, serial и количественная партия.
- Статус: planned; evidence отсутствует до исполнения.

## C43.03 — Реализовать reservations и UI

Работа: Реализация. Роль: Frontend-разработчик.

- Вход/зависимость: C43.02; контракты и материалы пакета.
- Результат: Резервирование/снятие/expiry и состояние available/reserved.
- Проверка: Резерв не считается фактической выдачей.
- База оценки: Роли кладовщик/ответственный и поддержанные операции.
- Статус: planned; evidence отсутствует до исполнения.

## C43.04 — Проверить конкурентный складской учёт

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C43.03; контракты и материалы пакета.
- Результат: Parallel issue/reserve/cancel и replay tests.
- Проверка: Один предмет не выдан дважды.
- База оценки: Две конкурентные транзакции и повтор команды.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C44 — Запчасти, ремонт и движение компонентов (W2)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 19, 25, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C44.01 — Определить component compatibility policy

Работа: Подготовка и проектирование. Роль: Архитектор.

- Вход/зависимость: C42, C43; контракты и материалы пакета.
- Результат: Проверяемая модель part/installed component и допустимых связей.
- Проверка: Замена компонента не меняет UID родительского asset.
- База оценки: Выбранные категории деталей и serial/lot правила.
- Статус: planned; evidence отсутствует до исполнения.

## C44.02 — Реализовать install/remove/replace workflow

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C44.01; контракты и материалы пакета.
- Результат: Связанный lifecycle+stock процесс с транзакциями/compensation.
- Проверка: Предмет не числится одновременно на складе и установленным.
- База оценки: Операции замены и возврата неисправной детали.
- Статус: planned; evidence отсутствует до исполнения.

## C44.03 — Добавить repair и movement history UI

Работа: Реализация. Роль: Frontend-разработчик.

- Вход/зависимость: C44.02; контракты и материалы пакета.
- Результат: Состояние ремонта, маршрут детали и история asset.
- Проверка: Источник/назначение/основание/ответственные видны.
- База оценки: Repair job, stock move и asset relation timeline.
- Статус: planned; evidence отсутствует до исполнения.

## C44.04 — Проверить сквозной ремонт

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C44.03; контракты и материалы пакета.
- Результат: Приём→выдача→замена→ремонт→возврат/списание.
- Проверка: Баланс/UID/ownership/events согласованы.
- База оценки: Серийная и несерийная деталь, отмена в середине.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C45 — Физическая инвентаризация и приёмка волны 2 (W2)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 25, INC-08, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C45.01 — Реализовать inventory reconciliation

Работа: Подготовка и проектирование. Роль: Backend Go-разработчик.

- Вход/зависимость: C44; контракты и материалы пакета.
- Результат: Фактическая проверка склада, расхождения и корректировки с основаниями.
- Проверка: Correction аудируется, ledger не переписывается молча.
- База оценки: 1 склад, пропажа/излишек/неверное место.
- Статус: planned; evidence отсутствует до исполнения.

## C45.02 — Подготовить документы и process reports

Работа: Реализация. Роль: Frontend-разработчик.

- Вход/зависимость: C45.01; контракты и материалы пакета.
- Результат: Утверждённые акты/экспорты/история выдачи.
- Проверка: Чувствительные данные и права сохранены.
- База оценки: Шаблоны по согласованным процедурам C41.
- Статус: planned; evidence отсутствует до исполнения.

## C45.03 — Проверить сохранность и конкурентность процессов

Работа: Реализация. Роль: Инженер проверки.

- Вход/зависимость: C45.02; контракты и материалы пакета.
- Результат: Backup/restore/migration/event replay wave2 tests.
- Проверка: Остатки и назначения восстанавливаются из ledger/history.
- База оценки: Сбой на stock/lifecycle границе и concurrent actions.
- Статус: planned; evidence отсутствует до исполнения.

## C45.04 — Провести пилот и приёмку склада/ЖЦ

Работа: Проверка и передача. Роль: Владелец продукта / руководитель проекта.

- Вход/зависимость: C45.03; контракты и материалы пакета.
- Результат: Process acceptance report, инструкции и ограничения.
- Проверка: Бизнес-пользователь подтверждает сценарии на стенде.
- База оценки: Утверждённые AC второй волны, rollout отдельно разрешается.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C46 — Модель ITSM и каталог услуг (W3)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 25, INC-08, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C46.01 — Согласовать минимальный ITSM scope

Работа: Подготовка и проектирование. Роль: Владелец продукта / руководитель проекта.

- Вход/зависимость: C45; контракты и материалы пакета.
- Результат: Услуги/пользователи/типы обращений/роли и процессы.
- Проверка: Не обещан полный ITIL suite без объёма.
- База оценки: Incident/request/problem/change, SLA и exclusions.
- Статус: planned; evidence отсутствует до исполнения.

## C46.02 — Спроектировать сущности и ownership

Работа: Реализация. Роль: Архитектор.

- Вход/зависимость: C46.01; контракты и материалы пакета.
- Результат: ER service/offering/ticket/task/approval и связи CI/asset_uid.
- Проверка: Нет конкурирующего каталога assets в ITSM.
- База оценки: ITSM module boundary и API/event contracts.
- Статус: planned; evidence отсутствует до исполнения.

## C46.03 — Спроектировать state machines и аудит

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C46.02; контракты и материалы пакета.
- Результат: Переходы/приоритеты/ответственные/очереди/комментарии.
- Проверка: Tenant/visibility и приватные записи формализованы.
- База оценки: Роли сотрудник/оператор/manager, workflow guards.
- Статус: planned; evidence отсутствует до исполнения.

## C46.04 — Утвердить процессные AC ITSM

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C46.03; контракты и материалы пакета.
- Результат: Приёмка каждой заявки/изменения и связи с ЖЦ.
- Проверка: Критерии и лицензируемые внешние интеграции названы.
- База оценки: Минимальный end-to-end service scenario.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C47 — Инциденты и проблемы (W3)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 25, INC-08, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C47.01 — Реализовать incident workflow

Работа: Подготовка и проектирование. Роль: Backend Go-разработчик.

- Вход/зависимость: C46; контракты и материалы пакета.
- Результат: Создание/классификация/назначение/escalation/resolve/reopen.
- Проверка: Приоритет/ответственность/аудит согласованы.
- База оценки: State machine C46, ручные и разрешённые API источники.
- Статус: planned; evidence отсутствует до исполнения.

## C47.02 — Реализовать problem и known-error связи

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C47.01; контракты и материалы пакета.
- Результат: Problem/root cause/workaround и связанные incidents.
- Проверка: Проблема не дублирует asset/CI identity.
- База оценки: Incident→problem→CI/service relationships.
- Статус: planned; evidence отсутствует до исполнения.

## C47.03 — Добавить рабочее место оператора

Работа: Реализация. Роль: Frontend-разработчик.

- Вход/зависимость: C47.02; контракты и материалы пакета.
- Результат: Очереди, фильтры, карточка, impact и история.
- Проверка: Права private/public комментариев соблюдены.
- База оценки: Роли и типы обращений выбранного scope.
- Статус: planned; evidence отсутствует до исполнения.

## C47.04 — Проверить полный процесс

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C47.03; контракты и материалы пакета.
- Результат: Incident+problem+asset linkage и concurrent assignment.
- Проверка: Повторы внешних notifications не создают дубли.
- База оценки: Отказ интеграции, re-open и изменение ответственного.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C48 — Запросы обслуживания и портал (W3)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 25, INC-08, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C48.01 — Реализовать service catalog forms

Работа: Подготовка и проектирование. Роль: Frontend-разработчик.

- Вход/зависимость: C46; контракты и материалы пакета.
- Результат: Услуги/предложения, формы и видимость по роли.
- Проверка: UI использует версионированные backend schemas.
- База оценки: Один каталог и минимальный набор услуг из C46.
- Статус: planned; evidence отсутствует до исполнения.

## C48.02 — Реализовать request/approval/fulfillment

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C48.01; контракты и материалы пакета.
- Результат: Заявка, согласования, задачи исполнения и отмена.
- Проверка: Guards/segregation/tenant проверяются backend.
- База оценки: Запрос→approval→fulfillment с audit.
- Статус: planned; evidence отсутствует до исполнения.

## C48.03 — Связать запрос со складом/ЖЦ

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C48.02; контракты и материалы пакета.
- Результат: Команды выдачи/замены с idempotency и ссылками.
- Проверка: Нет скрытой двойной записи stock и ticket.
- База оценки: Один сквозной сценарий выдачи оборудования.
- Статус: planned; evidence отсутствует до исполнения.

## C48.04 — Проверить портал и исполнение

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C48.03; контракты и материалы пакета.
- Результат: Employee/operator/approver end-to-end checks.
- Проверка: Sensitive fields и права внешнего requester защищены.
- База оценки: Несколько ролей, rejected/cancelled request и повтор команды.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C49 — Изменения и влияние на услуги (W3)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 25, INC-08, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C49.01 — Определить change policy и риски

Работа: Подготовка и проектирование. Роль: Архитектор.

- Вход/зависимость: C47, C48; контракты и материалы пакета.
- Результат: Типы изменений, risk/approval и impact model.
- Проверка: Автоматическая топология не выдаётся за доказанную бизнес-зависимость.
- База оценки: Связи service/CI/asset и confidence.
- Статус: planned; evidence отсутствует до исполнения.

## C49.02 — Реализовать change lifecycle

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C49.01; контракты и материалы пакета.
- Результат: План, approval, окно, execution, rollback и review.
- Проверка: Нет выполнения вне полномочий и согласованного окна.
- База оценки: State machine и ограничения C46.
- Статус: planned; evidence отсутствует до исполнения.

## C49.03 — Добавить календарь и impact UI

Работа: Реализация. Роль: Frontend-разработчик.

- Вход/зависимость: C49.02; контракты и материалы пакета.
- Результат: Конфликты окон и связанные services/assets/incidents.
- Проверка: Visibility и текущие версии данных проверяются.
- База оценки: Timezones, overlapping changes и partial topology.
- Статус: planned; evidence отсутствует до исполнения.

## C49.04 — Проверить change/rollback сценарий

Работа: Проверка и передача. Роль: Инженер проверки.

- Вход/зависимость: C49.03; контракты и материалы пакета.
- Результат: Запланированное изменение, отказ, откат и review.
- Проверка: История причин/согласований/исполнения сохранена.
- База оценки: Один согласованный production-like стенд, без самовольного deploy.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.


# C50 — SLA, интеграции и приёмка ITSM (W3)

Входы: результаты зависимостей, [спецификация 0.5](../../specifications/go-asset-management-v2.md), разделы 25, INC-08, [архитектура](../../architecture/go-target-architecture.md).
Проверить решения и claims по фактическому checkout; не считать предыдущую эпоху выполненной без evidence.

## C50.01 — Реализовать SLA calendars и timers

Работа: Подготовка и проектирование. Роль: Backend Go-разработчик.

- Вход/зависимость: C49; контракты и материалы пакета.
- Результат: Response/resolve, часы/паузы/праздники/escalation.
- Проверка: Timezone/DST и смена приоритета рассчитаны по policy.
- База оценки: Согласованные SLA классы/календари; это не uptime SLA платформы.
- Статус: planned; evidence отсутствует до исполнения.

## C50.02 — Подключить каналы и уведомления

Работа: Реализация. Роль: Backend Go-разработчик.

- Вход/зависимость: C50.01; контракты и материалы пакета.
- Результат: Разрешённые email/API/webhook adapters с delivery ledger.
- Проверка: Нет повторных писем по replay и утечки tenant data.
- База оценки: Только явно разрешённые каналы/адресаты в реализации.
- Статус: planned; evidence отсутствует до исполнения.

## C50.03 — Проверить сквозные бизнес-процессы и нагрузку

Работа: Реализация. Роль: Инженер проверки.

- Вход/зависимость: C50.02; контракты и материалы пакета.
- Результат: Ticket→asset→stock/change→close, rights/audit/recovery tests.
- Проверка: Новые процессы не ломают inventory и freshness.
- База оценки: Полный выбранный scope W3 и согласованный workload.
- Статус: planned; evidence отсутствует до исполнения.

## C50.04 — Оформить эксплуатацию и roadmap следующего релиза

Работа: Проверка и передача. Роль: Владелец продукта / руководитель проекта.

- Вход/зависимость: C50.03; контракты и материалы пакета.
- Результат: ITSM acceptance, runbooks, support ownership и backlog.
- Проверка: Различены implemented, deferred и customer-specific.
- База оценки: Утверждённые AC W3; нет обещания всех функций аналогов.
- Статус: planned; evidence отсутствует до исполнения.

## Выход пакета

Все четыре подзадачи имеют артефакт и фактический результат проверок, либо явно заблокированы.
Приёмка по перечисленным сценариям и применимым AC; неподдержанное обозначено явно.
В handoff указать ветку/коммит, changed files, выполненные команды и counts, passed/failed/skipped/unrun,
mock-vs-live, blockers и следующий готовый пакет. До фактической записи в GitHub результат локальный.
Обновить статусы в plan.json/TASK_INDEX и краткий STATUS/REQUESTS. При частичном выполнении
не помечать весь пакет done; следующий чат продолжает оставшиеся task IDs.
