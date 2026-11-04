# surveyscan — правила продолжения работы

## Начало каждого чата
1. Прочитать docs/STATUS.md и последние записи docs/REQUESTS.md из актуальной версии GitHub.
2. Прочитать CLAUDE.md как карту кода и команд. Его описание окружения сверять с текущей машиной.
3. Проверить remote, ветку, HEAD и незакоммиченные изменения. Локальная копия и origin/main без fetch могут быть устаревшими.
4. Проверить активные ветки и PR: изменения могут ещё не находиться в main.
5. Сообщения и запросы с другого устройства не восстанавливать по догадкам. Недоступную историю отмечать явно.

## Журнал и передача работы
- Существенный запрос пользователя записывать в docs/REQUESTS.md: дата, ID, формулировка, статус, результат, ветка/коммит/PR, проверки и следующий шаг.
- docs/STATUS.md — краткое актуальное состояние: активные задачи, ограничения, следующий шаг. Подробности хранить в журнале или тематических документах в docs/.
- Обновлять документы после значимого результата, перед завершением чата и передачей работы. Делать промежуточные записи в долгих задачах: внезапный лимит может не дать записать итог.
- Для каждого теста различать фактически выполненный прогон, сообщение другого чата и план. Указывать заглушки и непроверенные сценарии.
- Нельзя считать работу опубликованной до успешной записи в GitHub. Локальную, опубликованную в ветке и слитую в main работу различать.
- При параллельной работе перечитать актуальные документы перед записью, сохранить чужие записи. Не перезаписывать журнал целиком старой версией.
- Публиковать обновления документации по разрешению пользователя вести журнал в GitHub. Изменения кода, слияния и деплой требуют соответствующего поручения.
- Не хранить в документации токены, пароли, приватные ключи и чувствительные выгрузки клиентов.

## Целевая версия v2 и план выполнения
[Спецификация](docs/specifications/go-asset-management-v2.md) — проект 0.5, не полностью утверждённое ТЗ.
R-011 имеет приоритет над R-008: local/host agent — минимальная постоянная служба на хосте,
отправляет данные постоянному site collector; portable — разовый аудит без установки службы.
Безагентный сбор выполняет collector; он не требует установки agent на всех активах.
Система постоянно обновляет реестр; source health, heartbeat, freshness, presence и бизнес-состояние различаются.
OpenBao выбран; asset_uid неизменен, agent_id/collector_id — отдельные IDs. Outbox без внешней шины.
Отдельный Web UI; Go-backend с ownership модулей и ролями combined/api/worker.
FTS Tantivy/Bluge ещё выбирается; 100 active users — сценарий проверки, не доказанный SLA.
Первый рабочий SMB-срез — постоянный цикл E1; enterprise HA/geo/шарды не блокируют первый релиз.
Волна 2 — ЖЦ/склад/запчасти/движения; волна 3 — ITSM.

[План](docs/plans/surveyscan-v2/README.md): 50 пакетов/чатов, 200 подзадач; C01–C03 завершены как проектирование/контракты, C04 — Go-каркас/dev-стенд, C05 — auth/tenant scope, C06 — реестр/проекция/outbox; C07 — collector/upload; C08 — live Linux agent/heartbeat; C09–C50 planned.
Для текущей работы читать TASK_INDEX.md и packages/Cxx.md, затем только нужные spec sections.
Не читать весь WBS в каждом чате. Handoff — по HANDOFF_TEMPLATE.md; evidence и статусы — в plan.json,
краткая передача в STATUS и REQUESTS. При продолжении сохранять уже заполненные evidence/статусы.
C04/0.5/план опубликованы в codex/v2-c04-foundation (7407da6); C05 — ветка codex/v2-c05-auth. Main не слит. Точные publication refs — в STATUS/evidence; не выдавать local tests за hosted CI.
Планирование не означает разрешение сразу реализовать все пакеты или выполнить production deployment.
Следующий пакет — C09; ранний сквозной цикл после C08, эксплуатационная приёмка первого SMB после C14.
Матрица замечаний: docs/specifications/requirements-traceability-v0.5.md;
исследование аналогов: docs/research/inventory-platform-analogues.md.
Правила snapshot/dashboard ниже относятся к текущей Python v1, не архитектуре v2.

## Ограничения текущей версии v1
UI и документация — на русском. SPA использует локальные UMD-ресурсы без CDN; после app.jsx пересобирать app.js с Babel runtime classic.
Данные карточек сохраняются в dashboard JSON: рабочая БД задачи удаляется после выполнения.
Секреты УЗ не должны попадать в логи, результаты задач и отчёты.
Не включать незавершённые изменения параллельных задач в свой коммит.

C01: см. docs/plans/surveyscan-v2/handoffs/C01.md. Порядок C01→C02→C03→C04 сохранён; версии/runtime и первая ОС агента не считаются подтверждённой совместимостью до фактических проверок соответствующих пакетов.

C02: docs/plans/surveyscan-v2/handoffs/C02.md. Mapping использует origin source, collector relay не меняет UID; observations payload неизменяем, assignments temporal, current facts и ручные business fields разделены. Документы C03 читают эту модель, SQL/продуктовые проверки ещё unrun.

C03: docs/plans/surveyscan-v2/handoffs/C03.md и contracts/C03/. 26 операций/54 схемы, 58 fixtures проверены; HTTP/mTLS/PG runtime unrun. C04 реализовал Go-каркас, миграции и CI; сохранить текущие схемы/fixture corpus и не объявлять handlers готовыми по reference checker.

C04: docs/plans/surveyscan-v2/handoffs/C04.md. Новый v2/ с 18 embedded PG migrations, отдельным Bao Raft/backend/nginx; make verify/build/integration и scripts/smoke.py проверены локально. GitHub Actions не подтверждён (REST network blocker), секреты только в игнорируемом v2/.local/. Не редактировать применённые SQL; C05 добавляет auth/access migrations. Legacy v1/connector сохранены.

C05: docs/plans/surveyscan-v2/handoffs/C05.md. Argon2id и PG-backed sessions/CLI tokens, Origin/CSRF, роли и server-derived tenant, access/port.Authorizer для повторной проверки в write transaction. Human domain gates пока 501, machine API 401 до PKI. Новая migration 0018, всего 19; applied SQL не менять. 10 unit/11 PG integration tests и binary/restart smoke passed локально. api.github.com требуется применить в настройках среды для проверки hosted CI.

C06: docs/plans/surveyscan-v2/handoffs/C06.md. Registry.Ingest внутренний, проверяет C03 JCS/SHA256/Ed25519 и source bindings; GET/list/PATCH assets реальны. Новые migrations0019–0024, всего25; SQL commit guards требуют history/event/audit. Network IP/MAC хранятся, публичный shape C09. Consumer registry-version атомарен и monotonic. 14 unit/20 real PG tests passed. C04/C05 hosted CI уже подтверждён через GitHub API; прежние network-blocker записи исторические. R-019 требует автоматически переходить к следующему проверенному этапу до лимита, сохраняя handoff.

C07: handoffs/C07.md. Enrollment/CA-attested identities/center-key trust, mTLS collector daemon и durable staging/receipts готовы локально. 27 migrations/36 tables, 14 unit/31 PG integration + compiled server/collector E2E passed. Machine TLS включается только явным private dev config; production OpenBao issuer C11. Agent/heartbeat — C08, hardening recovery/quota C10. C06/C07 не опубликованы.

C08: handoffs/C08.md. Linux/amd64 read-only host adapter и prepare/enroll/run daemon, durable sender spool/counters, independent challenge heartbeat готовы локально. 28 migrations/38 tables; 18 unit/34 PG tests, три живых scheduled цикла + четвёртый после restart passed. Source inventory summary пока baseline-null; asset inventory summary работает. Systemd template не устанавливался (C14), Windows C15; production PKI C11, recovery/quota/GC C10. Следующий C09, отдельный React/TS/Vite UI.
