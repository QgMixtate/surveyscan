# Журнал запросов и передачи работы

Этот журнал хранит существенные запросы и результаты, а не полный экспорт чатов.
Время указывать по Москве. Историю с других устройств включать только по проверенным сообщениям; неизвестные детали не додумывать.

## R-001 — Полная инвентаризация и карточка актива
Дата: 2026-10-29 (по истории коммитов).
Запрос: полная инвентаризация вместо отображения только nmap-сервисов; полноценная карточка Windows/WinRM и других активов.
Результат: 6c3f5cf — передача inventory в dashboard и вкладки карточки; eb73cbb — classic JSX runtime; ba8f735 — расширение сети, служб, групп и устройств по референсу Security Vision.
Статус: опубликовано в main, последующие исправления находятся в отдельных ветках.
Ограничение: в ba8f735 обнаружена зависимость от отсутствующей apply_role_guess.

## R-002 — Проверить актуальную работу на другом устройстве
Дата: 2026-11-02.
Запрос: «проверь мой гит, я уже далеко ушел на другом устройстве»; затем «смотри с чем последним работал, я остановился на запросах там токены закончились».
Выполнено: проверены GitHub main, ветки codex/baseline-audit и codex/asset-inventory, PR №1 и его обсуждение.
Результат: c678ead — аудит ядра; c333c32 — исправления инвентаризации; PR №1 открыт как черновик. Детали проверок — в STATUS.md.
Статус: состояние GitHub установлено; точный последний запрос из другого чата пока не восстановлен. Доступные локальные чаты содержат старую историю.
Следующий шаг: получить исходный последний запрос из того чата либо продолжать по новому явному поручению пользователя.

## R-003 — Документация в GitHub для работы с разных устройств
Дата: 2026-11-02.
Запрос: «ты веди в гите тогда всю доку, чтобы я с разных устройств мог последние запросы смотреть и продолжать работу».
Результат: созданы docs/STATUS.md, docs/REQUESTS.md и корневой AGENTS.md с правилами обновления, проверки веток и передачи контекста. Публикация — в main.
Статус: первоначальная документация подготовлена; ведение журнала — постоянное правило следующих задач.
Проверка: чтение опубликованных файлов через GitHub после записи. Код и ветки разработки не объединяются.
Следующий шаг: каждый новый существенный запрос добавлять ниже; обновлять STATUS.md после проверенного результата.

## R-004 — Новый компилируемый стек и Asset Management
Дата: 2026-11-02.
Запрос: Go-монолит, Go-коллектор, портативная версия (обсудить Rust и автономную передачу),
«smdb», PostgreSQL с расчётом на шардинг, «Pgbalancer», Asset Management.
Статус: обсуждение. Пользователь явно попросил сначала обсудить; миграция кода не разрешена этим запросом.
Подготовлено: [архитектурное предложение](architecture/go-asset-management-discussion.md).
Рекомендации ассистента пока не утверждены. Требуют уточнения CMDB/SMDB, продукт балансировки,
режим портативного сбора, допустимость скриптов и масштабы.
Следующий шаг: согласовать эти решения и первый вертикальный срез; затем планировать реализацию.

## R-005 — Полная схема целевой архитектуры
Дата: 2026-11-02.
Запрос: «покажи мне полностью архитектуру, схему дай как это будет».
Статус: схема подготовлена для обсуждения, не утверждена.
Результат: [архитектура с Mermaid-схемами](architecture/go-target-architecture.md): сервер-монолит,
режимы Go-сборщика, offline/online импорт, постоянная модель активов, PostgreSQL и будущие шарды,
эксплуатация и первый проверяемый срез.
Публикация: документация в main; код не изменён.
Следующий шаг: обсудить и утвердить модель/ограничения из открытых вопросов R-004.

## R-006 — Новая спецификация под Go-архитектуру
Дата: 2026-11-02.
Запрос: «мне нужна так же новая спека под это все».
Статус: проект документа подготовлен и опубликован, согласование ожидается.
Результат: [спецификация surveyscan v2, версия документа 0.1](specifications/go-asset-management-v2.md).
18 разделов: Go-монолит/сборщик, portable, контракт пакета и импорт, Asset Management/CMDB,
модель данных, PostgreSQL и шардинг, пул/HA, API/UI, безопасность, эксплуатация, миграция,
этапы E0–E5, 24 сценария приёмки, комплект поставки, решения D-01–09.
Проверки: уникальность идентификаторов требований; чтение опубликованного документа.
Тесты продукта не запускались: код не изменён.
Следующий шаг: согласовать D-01–09 и границы E1; после согласования выпустить спецификацию 1.0.
Документ не подтверждает реализацию требований и не начинает миграцию.

## R-007 — Сохранить контекст для другого устройства
Дата: 2026-11-02.
Запрос: сохранить всё, чтобы 3 ноября продолжить с другого устройства, и дать стартовый запрос.
Статус: точка передачи опубликована в STATUS.md; спецификация и архитектура уже в main.
Сохранены решения/предложения, неопределённости, ссылки, ограничения и следующий шаг.
Открытые решения D-01–09 не утверждены, реализация Go не начата.
Следующий шаг: новый чат читает GitHub и проверяет изменения после этой записи, затем продолжает обсуждение.

## R-008 — Уточнить архитектуру и волны развития
Дата: 2026-11-02.
Запрос: local — частный случай portable; vault выбран OpenBao; обязательны безагентное
сканирование сетевых устройств/топология, сквозной ID, обнаружение новых/выпавших разными
способами, ответственность за каждый asset, CLI/открытый API, георезерв шардов,
событийная логика без шины, полнотекстовый поиск Tantivy или Bluge.
Вторая волна — процессы ЖЦ, склад/запчасти/движения; далее ITSM.
Статус: требования внесены в проект спецификации 0.2 и архитектуру 0.2, код не менялся.
OpenBao — решение пользователя; движок поиска ещё выбирается, Bluge только рекомендация.
Модель asset/CI и global asset_uid, mapping offline records, aliases/merge/split требуют ADR.
Результат: 27 разделов спецификации, 39 критериев приёмки; добавлены VAULT, ID, DISC, NET,
OWN, CLI, EVT, SEARCH и GEO требования. Первоначальный R-004 помечен историческим.
Проверки: уникальность ID требований; соответствие каждого замечания разделу; чтение
опубликованных файлов. Прогоны кода не выполнялись.
Следующий шаг: согласовать ER-модель, discovery/presence, ответственность, секреты/offline,
географию/RPO/RTO; выполнить PoC Tantivy/Bluge и утвердить ADR перед реализацией.

## R-009 — Отдельный frontend и возможность разделения backend
Дата: 2026-11-03.
Запрос: сомнение во встроенном Web UI, ориентир 100 пользователей, независимые люди/команды;
backend-монолит может потребовать последующего разделения. Затем пользователь попросил продолжить.
Статус: внесено в спецификацию/архитектуру 0.3; код не менялся.
Решение в проекте: отдельный серверный Web UI, контракт OpenAPI, независимые сборки/релизы;
Go-backend — модульный монолит с ownership данных, явными интерфейсами и outbox.
Предложение: роли combined/api/worker для независимого масштабирования до микросервисов.
Embedded UI возможен только как опция portable. Внешняя шина пока не вводится.
Предел «100 пользователей» не подтверждён: добавлен предлагаемый профиль 100 активных
пользователей с фоновым импортом; нагрузка/SLO требуют согласования и измерений.
Результат: 30 разделов спецификации, 43 критерия приёмки, новые WEB/MOD/PERF требования.
Следующий шаг: согласовать D-16–18 (frontend, границы/роли, нагрузка) вместе с моделью данных.
Проверки: уникальность ID, ссылки/согласованность изменённых разделов, чтение файлов GitHub.
Нагрузочные и кодовые тесты не запускались.

## R-010 — Продолжение обсуждения аналогов и общая архитектура
Дата: 2026-11-03 (Москва). Источник: приложенная пользователем переписка и текущий чат.
После R-009 обсуждались аналоги; затем пользователь вернулся к архитектуре, подтвердил
направление api/worker + combined и запросил общую схему/спецификацию. Подготовлен локальный
проект 0.4 вне checkout; публикация/реализация не выполнены.

## R-011 — Постоянный агент, SMB→enterprise и исследование аналогов
Дата: 2026-11-03 (Москва).
Запрос: учесть весь список требований; выпускать рабочее по эпохам, система работает постоянно;
«Локал от портабл отличается тем что стоит минимальный агент на машине и отдаёт в коллектор,
а портабл это разовый аудит»; изучить аналоги.
Результат: проект 0.5 с AGT/CON/INC, 237 требованиями и 55 AC, постоянным циклом E1,
матрицей всех 19 замечаний. Документально исследованы официальные GitHub-источники
Device42, GLPI/Agent, runZero, Snipe-IT; сеть не позволила проверить сайты остальных кандидатов.
Статус: локальная документация. Сбой среды прервал обновление журнала в предыдущем ходе;
данная запись восстанавливает только подтверждённые вводные/результаты.
Публикация и реализация Go v2 не выполнялись; продуктовые/нагрузочные тесты не запускались.

## R-012 — Полный план работ и разбиение по чатам
Дата: 2026-11-03 (Москва).
Запрос: «дай план работ полностью по новой архитектуре; все раздели по задачам и подзадачам;
дабы экономить токены давай разобьем по нужному кол во чатов».
Результат: docs/plans/surveyscan-v2 — 50 пакетов, 200 подзадач с ролями/зависимостями/
результатами/проверками/базой оценки. Индекс, WBS, JSON/CSV, 50 файлов пакетов и 50 коротких
стартовых запросов, шаблон handoff, coverage всех 237 требований/55 AC/19 замечаний.
E0 C01–03; E1 C04–14; E2 C15–24; E3 C25–30; E4 C31–34; E5 C35–40;
волна 2 C41–45; волна 3 C46–50. Ранний живой цикл C08, эксплуатационный SMB после C14.
Пакеты — логические границы, не гарантия числа сообщений/токенов или сроков.
Статус: план подготовлен локально, все задачи planned. Разрешение на реализацию всех пакетов,
production deployment/merge этим планированием не подразумевается.
Проверки: ацикличные зависимости, 50/200 уникальных IDs, поля каждой подзадачи, соответствие
всем требованиям и AC, ссылки и состав архива. Это статические проверки документов, не тесты продукта.
Ветка work, базовый HEAD 73ced7e; коммит/PR/публикация не выполнены.
Следующий шаг: C01. Для нового окружения передать архив либо использовать опубликованные документы;
по одному пакету на чат, без повторного чтения всей спеки и WBS.

## R-013 — Начать поэтапное выполнение с самого начала плана
Дата: 2026-11-03 (Москва).
Запрос: «начинай поэтапно выполнять»; затем «погнали тогда по плану» и уточнение
«начинаем самого начала плана как ты и создал, все поэтапно делать будем».
Порядок исходного плана сохранён: C01→C02→C03→C04; вопрос о сервере не привёл к перескоку в C04.
Выполнен только C01: baseline GitHub/локальных документов, границы SMB E1, решения-кандидаты,
план реальных проверок C08/C14, machine-readable status и handoff.
Конкретные версии проверены по официальным метаданным/тегам; совместимость/продуктовые тесты
не проверялись. Agent OS остаётся proposed до C08; это не блокер серверного проектирования.
Статус: C01 done как проектирование, 4/200 задач; C02–C50 planned. Код Go v2 не реализован.
Проверки: статическая согласованность документов/сценариев/AC/ID/status/links, git diff --check.
Ветка work, HEAD 73ced7e; коммит/push/PR/merge/deploy не выполнялись.
Артефакт: docs/plans/surveyscan-v2/handoffs/C01.md. Следующий пакет: C02.

## R-014 — Продолжить по плану: C02
Дата: 2026-11-03 (Москва). Запрос: «погнали дальше».
Выполнен C02 как проектирование: 24 сущности в JSON-каталоге и ER, наблюдения/проекции,
ownership 9 модулей, 14 инвариантов и 4 явно межмодульные транзакции, 22 контрпримера.
Уточнён ID-03: origin source сохраняется при смене collector-посредника; UID не зависит от маршрута.
История observations и temporal assignment отделены от current mapping/facts; manual business fields защищены.
Минимум ответственности требует transaction/guard, а не только UNIQUE. E1 conservative matching,
полный merge/split позже. Есть вопросы C03 о digest/generation/ACK, SQL/concurrency — C04/C06/C10.
Проверки: каталог PK/FK/fields/tenant scopes/owners, references инвариантов, статусы/порядок плана,
ссылки и git diff --check. 22 сценария рассмотрены на уровне проекта, runtime/mock все unrun.
Статус: C01/C02 done документально, 8/200 задач. Код и миграции не создавались.
Ветка work, HEAD 73ced7e; commit/push/PR/merge/deploy не выполнены.
Артефакт: docs/plans/surveyscan-v2/handoffs/C02.md. Следующий пакет: C03.

## R-015 — Продолжить по плану: C03
Дата: 2026-11-03 (Москва). Запрос: «дальше».
Завершён C03: envelope 1.0, OpenAPI 3.1 (26 операций/54 schema definitions), delivery/receipt,
JCS/SHA256/Ed25519 origin и center signature, scoped prebound CSR enrollment, renewal proof,
fresh heartbeat challenge, job lease/fencing/cancel и outbox/checkpoint contracts.
Подготовлены 58 fixtures (19 positive/39 negative), 12 state-edge примеров, 2 JCS golden vectors,
3 HTTP формы. Все фактически проверены runner с ожидаемыми результатами; схемы/OpenAPI валидны.
Private keys fixture generation не сохранялись. Зависимости проверки — в отдельном venv, не приложении.
Runtime handlers/HTTP/mTLS/PG commit/leases и soak не выполнялись; Python checker под docs не является приложением.
Статус: C01–C03 done, 12/200 задач; Go runtime-продукт ещё не реализован.
Ветка work, HEAD 73ced7e; commit/push/PR/merge/deploy не выполнялись.
Артефакт: docs/plans/surveyscan-v2/handoffs/C03.md. Далее C04 — код нового Go-каркаса, миграции, dev-стенд и CI.

## R-016 — Продолжить по плану: C04
Дата: 2026-11-03 (Москва). Запрос: «дальше».
Выполнен C04.01–04: Go-каркас v2/ с server/collector/agent entrypoints и import boundaries,
18 checksummed/atomic PG migrations (24 domain tables C02), отдельный постоянный dev PG/Bao Raft,
backend/nginx и CI workflow. Agent/collector пока только version; operational invocation exit 2.
Проверено локально: build трёх бинарников, fmt/vet, 8 unit/architecture и 5 live PG integration tests,
6 live HTTP/restart smoke groups, 58 C03 fixtures. PG row сохраняется после restart; Bao unseal recovery.
CI GitHub hosted, production/TLS/mTLS/auth/ingestion crypto/soak — unrun; workflow ещё локальный.
Старый Python v1 и connector/ сохранены. Секреты вне Git в private v2/.local/, не в evidence/архиве.
Ветка work, HEAD 73ced7e; commit/push/PR/merge/production deployment не выполнялись.
Статус: C01–C04 done, 16/200; 184 planned. [Передача C04](plans/surveyscan-v2/handoffs/C04.md).
Следующий пакет C05 — bootstrap admin, auth, tenant scope и негативные проверки. C05 не начат.

## R-017 — Опубликовать C04, проверить GitHub Actions и продолжить C05
Дата: 2026-11-03. Пользователь явно поручил публикацию, проверку Actions и следующий этап.
C04 опубликован: codex/v2-c04-foundation, commit 7407da60ae22b77c37b0d26121a51cba744d3857;
git push succeeded, ls-remote подтвердил SHA. Main 73ced7e сохранён, PR/merge/production не выполнялись.
Push workflow trigger отправлен. Hosted run пока не подтверждён: gh api Forbidden,
api.github.com отсутствует в runtime allowlist. Домен и новые install/start instructions сохранены
в черновике среды; runtime update требует применения настроек через интерфейс среды.
После публикации C04 выполнен C05.01–04 в codex/v2-c05-auth: bootstrap/private file/Argon2id,
PG sessions, роли, CLI tokens, expiry/revoke, Origin/CSRF, server-derived tenant, transaction Authorizer port.
Новая migration 0018, старые SQL не менялись. Local tests: 10 unit, 11 real PG integration,
10 binary/CLI/HTTP auth smoke, 6 infrastructure smoke; C03 58 fixtures — passed, final failures/skips 0.
Argon2id: 3 iterations ~203ms/op/64MiB на этом runner, не production SLO. Legacy v1/connector сохранены.
[Передача C05](plans/surveyscan-v2/handoffs/C05.md), evidence/runtime/validation и threat cases сохранены.
C05 опубликован commit 07a62f08987b74b237847f173dcea8c23aa04bc2 в codex/v2-c05-auth.
Последующее исправление lock order и финальная проверка — см. R-018.
Статус: C01–C05 done, 20/200; 180 planned. Следующий C06; C06 не реализован.
Незакрытая внешняя часть запроса — проверка Actions после применения api.github.com в настройках среды.

## R-018 — Проверить добавленные PR и закончить исправление C05
Дата: 2026-11-04 (Москва). Пользователь: «ну я вроде добавил», screenshots PR #2/#3.
Подтверждено по screenshots: PR #2 C04 и PR #3 C04+C05 созданы; для 07a62f0 push check success,
pull_request check ещё in progress на момент снимка. Прямой GitHub API всё ещё Forbidden;
проверка runtime policy подтверждает api.github.com отсутствует, текущая revision1.
Продолжено авторизованное завершение C05: исправлен воспроизведённый inverse lock order,
Authorize блокирует user до credential и повторяет проверку после ожидания.
Make verify/build и полный suite (10 unit + 11 real PG integration) повторены, exit0.
Исправление опубликовано в существующий PR #3: 28e0e714badcad8eef71e7e5e316799a9ba20c88; git push succeeded.
Готовый binary/CLI/HTTP smoke также повторён, exit0. Новые hosted checks не считать прошедшими
по screenshot старого 07a62f0. Main/merge не меняются. Next package C06 пока не начат.

## R-019 — Последовательно продолжать этапы
Дата: 2026-11-04 (Москва). Запрос: продолжить этапы и после каждого проверенного этапа сразу начинать следующий до лимита.
C06 завершён локально в codex/v2-c06-registry от C05 f64cb89. C04/C05 hosted CI теперь подтверждён success через API.
Предыдущие настройки среды повторно не применяются. Публикация/merge в текущем продолжении не выполняются.
C06: 25 migrations, 14 unit/20 real PG tests, C03 и live smoke passed; 24/200 done.
Передача handoffs/C06.md. C06 checkpoint 2a217b9.
C07 также завершён локально: handoffs/C07.md, 27 migrations/36 tables, 14 unit/31 PG tests,
8 compiled server/collector TLS E2E + regression checks passed. Источник C07 синтетический.
C07 checkpoint8cd353c. C08 завершён локально: handoffs/C08.md, 28 migrations/38 tables,
18 unit/34 PG tests,58 fixtures,11 live-agent checks; три scheduled цикла и четвёртый после restart, один UID.
C08 checkpoint c5a3eef. C09 начат:01/02 done,03/04 in progress. Separate build и13 Chromium
checks с real API/PG/strict CSP passed; IP/provenance/full acceptance pending, handoffs/C09.md.
C09 завершён локально после продолжения: handoffs/C09.md; 29 migrations/39 tables,
18 unit/37 PG/58 fixtures/14 Chromium checks passed. Card/IP/MAC/provenance/source summaries реализованы.
C09 checkpoint8081188. C10.01/02 выполнены локально: quota/retention/single writer/cachedACK/backoff;
22 unit/37 PG tests,7 real SIGKILL/reconnect checks,1 real ENOSPC passed.
Прогресс38/200; C10.03 центральные lease/admission/checkpoints продолжаются, whole C10 не done.
C06–C10 локальны, без push/merge; handoffs/C10.md.

## Шаблон новой записи
- ID и дата:
- Запрос пользователя:
- Статус: запланировано / в работе / заблокировано / готово в ветке / слито.
- Что сделано:
- Ветка, коммит, PR:
- Проверки и ограничения:
- Незавершённое и следующий шаг:

R-019 продолжение: пользователь «дальше, делай все этапы пока не упрешься в лимит».
C10 завершён локально: handoffs/C10.md,30 migrations/40 tables,22unit/42PG/58fixtures,8process recovery,
1 real ENOSPC/14 browser checks passed.40/200done. Далее автоматически C11 OpenBao/PKI.
Никаких push/merge/deploy или повторной публикации среды.

C11 в работе локально: 01/02 done,03/04 in_progress (42/200 done). Scoped OpenBao KV/Transit,
non-exportable CA/receipt keys, private token/policy, declarative masked audit, no private-key fallback.
4 live scoped checks +15 compiled pipeline checks passed: actual seal/unseal, readonly sealed restart,
staging retained→automatic ACK/no duplicates. make verify/build и43PG passed.
Renewal/rotation/clone matrix ещё не готова; продолжать C11.03, не переходить к C12.
Передача plans/surveyscan-v2/handoffs/C11.md; production HTTPS/custody/restore rehearsal unrun.
Без push/merge/deploy/повторной публикации среды.

R-019, 2026-11-04 (Москва), продолжение «делай все этапы пока не упрешься в лимит»:
C11.01/02 завершены локально (checkpoint10a3f93),03/04 продолжаются. Реальный scoped Bao:
KV refs/Transit CA+receipt non-exportable, policy/root rejection, token renew/revoke/replacement,
declarative audit masked; sealed restart/readonly и retained staging→ACK послеunseal.
Добавлены C03 cert_renew сервер/relay, immutable result replay и Linux agent atomic TLS rotation.
Live test: actual disconnect после certificate commit, next process retries same pending и получает
один прежний cert; restart→inventory seq2/тотжеUID; revoke закрывает renewal.24unit/46PG/58fixtures,
8live rotation,8SIGKILL recovery,14Chromium regression passed.31migrations/42tables,42/200done.
Далее collector self-renewal и оставшаяся lifecycle/clone/expiry acceptance; wholeC11 не done.
No push/merge/deploy/env publication. Подробности handoffs/C11.md.

C11 checkpoint8754e1c: server/agent renewal и ACK-loss recovery сохранены. Дополнительно auth10/infra6
passed; initial auth run конфликтовал с infrastructure stopPG, повторён последовательно; own leaked DB удалена.
Transport guard hardened: parsed URL scheme (mixed-case HTTP), verify/build+liveBao passed. Далее collector self-renew.

R-019, продолжение «Продолжай»,2026-11-04 (Москва): C11 завершён локально в bounded E1 scope.
Checkpoint3d591e8 shared engine+collector rotation; затем host-binding/legacy adoption и final trust matrix.
30unit/46PG/58fixtures,10agent/10collector,17Bao,8recovery/14browser passed. Collector hot reload прошёл-race
с injected scheduler clock; реальные issuer/Bao/PG/TLS.44/200done;31migrations/42tables.
Hardware clone identity/identical keys+machine-id, automatic expired reissue, production/24h/DR остаются
ограничениями, см. evidence/C11-lifecycle-matrix.json. Далее автоматически C12. No push/merge/deploy/env publication.

C11 final checkpointb22efa2; начат C12 на codex/v2-c12-cli. C12.01 done: surveyscanctl login/context/
assets/sources/status/logout поверх existing API, private session0600, TLS/redirect/timeout/exitcodes,
33unit/58fixtures и16live checks (8existingpipeline+8CLI groups),2real tenants/viewer passed.
45/200done. C12.02central profiles/configuration,03metrics,04operator scenario не выполнены.
No push/merge/deploy/env publication. handoffs/C12.md хранит следующую задачу.

C12.02 готов локально: managed versioned profiles, signed origin/center delivery/ACK, CLIupdate,
agent runtime/cache и collectorheartbeat.36unit/49PG/58fixtures/10livechecks passed.32migrations/44tables,
46/200done. C12.03diagnostics вработе,04operator pending. No push/merge/deploy/env publication.

C12 целиком готов локально:39unit/50PG/58fixtures,13operator/17CLI/16browser,8recovery,
10agent/10collector renewal (race) passed. Signed centralprofiles/ACK+offlinecache,tenant diagnostics/
metrics/alerts,CLIJSON/table/localstatus и readonlyUIprofiles. Реальный120→60cadence/UID/revoke verified.
33migrations/45tables;48/200done. Далее C13 service/install/versions/backup/restore, handoffs/C12.md.
No push/merge/deploy/env publication; no production/24h/DR/hardwareidentity claim.

C13 начат локально: codex/v2-c13-operations отC12d55a23d.01in_progress (48/200done).
Stagedsystemdunits/installer(privatecredentials/data paths) и5stagingchecks,real system-mode
systemd-analyze staticverifyexit0вnetworklesscontainer. Actualboot/reboot/services не проверены:
managedhostPID1tail/UID1000. No host service install/start. handoffs/C13.md содержитточнуюграницу.
C13.02–04release/backup/restore ещёplanned; no push/merge/deploy/env publication.

R-019, продолжение «Дальше / продолжи», 2026-11-05 (Москва): C13.01/02 in_progress.
Подготовлены signed Ed25519 release bundle, SHA256/size/mode manifest, SPDX2.3 dependency inventory,
все пять component versions/revisions/dirty, проверка до atomic staging в пустой root.
14 real signature/tamper/trust/path/mode/staging checks + make verify39unit/58fixtures и Web build passed.
Production key custody, actualboot/reboot/live update/backuprestore не проверены; done48/200 не изменён.
Нет QEMU/KVM/nspawn, Docker cgroupdriver none; host service changes не выполнялись.
GitHub fetch подтвердил прежние refs; нет push/merge/deploy/env publication. Handoff C13 хранит следующий шаг.

R-019, далее2026-11-05: C13.03 начат компонентом PostgreSQL17. Private custom archive,
checksum/size verification, restore только в другую пустую БД без DROP/--clean, single transaction.
17 real pipeline+restore checks passed:46tables fingerprints preserved, UID/access/history/retry/outbox,
33migration hashes/current migrate0, прежний admin login и карточка через restored TLS server.
Fixture processes quiesced, retrycheckpoint явно SQLfixture; own backup/DBs cleaned. Runbook v2/deploy/BACKUP.md.
PG-only не complete-system backup: Bao/filesystem/custody/previous-schema upgrade/boot ещёpending.
C13.01–03 in_progress,04planned,done48/200; cc242c5 release checkpoint. No push/merge/deploy/env publication.

R-019, далее2026-11-05: PG checkpoint b874302. Добавлен настоящий OpenBao Raft restore в отдельный
initially empty disposable node; исходный volume не reset/restore/seal.9 checks passed: cluster ID/KV/
scoped policy, оба non-exportable Transit CA/receipt keys реально подписывают; forbidden/foreign token
denied; target restart→sealed→source-custody unseal→sign. Source active/audit masked, private snapshot,
fixtures и target state удаляются. Это не full PG/Bao/filesystem checkpoint или clean OS/production DR.
Подробности/evidence вhandoffs/C13.md; C13.01–03 всё ещёin_progress,48/200. No push/merge/deploy/env publication.

C13 final continuation checks: PG18 (добавлен actual post-restore CSRF/If-Match PATCH,
тотжеUID и ровноодин audit/outbox), Bao9 finalcleanup, release14 independent Webversion/APIhashes,
Chromium16 passed.39unit/58fixtures makeverify ранее в этом продолжении passed.
Separate Web release сохранён; source provenance latest tested b874302+dirty, не clean current release.
Полныеevidence и nextstep вhandoffs/C13.md. Fullcheckpoint/liveupdate/previousschema/boot/twoOS pending;
done48/200, C13.01–03 IP/C13.04 planned; no push/merge/deploy/env publication.

## R-020 — Продолжить C13 и опубликовать накопленные изменения

Дата: 2026-11-05 (Москва). Запрос: «Дальше и на гит потом все опубликуй то что сделал».
Разрешены push всей текущей ветки, PR и GitHub Actions; прежний no-push снят этим поручением.
Merge/main/production deployment/перепубликация среды не поручены.
Common checkpoint10 passed: остановленные реальные agent/collector/server, PG+Raft+private files,
restore в новую DB/отдельный Bao/другие FS paths при недоступных original host/issuer directories.
UID/session/pending bytes сохранены, replay exactly once, sequence3/queues drain, новый leaf через restored CA.
Actual old C11 source b22efa2 compiled: schema31 data→current33, ровно2 migrations, repeat0,
old rows/hashes/UID/access/history/outbox сохранены, new login/write/default profile1 работают —13checks.
39unit/58C03/50PG passed перед публикацией. Workflow расширен всеми C13 checks и separate Web build.
Публикация pending; точные remote refs/PR/hosted CI записать только после фактической записи GitHub.
C13.01–03 IP/C13.04planned,48/200; следующие gates systemd boot/live update/two clean OS.

R-020 publication: git push успешен, GitHub branch codex/v2-c13-operations@f1ea70f подтверждена,
draft PR4 https://github.com/QgMixtate/surveyscan/pull/4. C04–C13 опубликованы одной последовательной веткой,
main/PR1–3 не слиты/не изменялись. Actual hosted v2 run41924693360 и Web41924693362 стартовали;
результат покаin_progress. После metadata sync проверить latest PR head и конечные Actions results.

R-020 завершение публикации: hosted v2 run41924907145 и Web run41924907471 SUCCESS на215f10c.
Actual downloaded artifacts подтверждают release14/static0/PG18/Bao9/common10/upgrade13/Web16,
agent11/auth10/machine8/recovery8/ENOSPC1/scopedBao4/BaoPipeline17/renewal10/collector10/CLI17/profiles13/infra6.
Evidence: plans/surveyscan-v2/evidence/C13-hosted.json (reportdigests и URLs).
Последующий [skip ci] commit меняет только журнал/evidence; application/workflow source совпадает с215f10c.
Всё опубликовано в PR4 featurebranch; main не слит. C13.01–03IP/04planned,48/200; boot/liveupdate/twoOS pending.

R-019/R-020, далее2026-11-05: пользователь просит автоматически переходить к следующему этапу до лимита.
Checked updater18 local passed: signed/schema-aware prepare, actual server stop/migrate0/switch/ready,
privateconfigs/TLSkeys/artifact/UID preserved, failed-start exact-schema rollback, actual SIGKILL+durable
fence/journal/recovery, drift fixture refuses old writers. New CLI schema-catalog/schema-check, signed
metadata, systemd gate. SQL/C03/C09 unchanged. New hosted CI pending; next actual systemd stand.

## R-021 — Непрерывное последовательное выполнение
Дата2026-11-05 (Москва). Запрос: «Сразу запускай следующие этапы как только закончишь, пока не упрешься в5часовойлимит».
Продолжатьавтономно, безподтвержденияпакетов, приёмкунеподменятьожиданием/mock/fakeclock.
C13 завершён boundedE1: two fresh nativeVM9+9 actualkernelreboot/nonrootautostart/scopedBao/LoadCredential,
realcombinedserver+collector+agentupdate/CLI/Web, sourceUID/session/queues preserved. Updater19 включает
actualprivatecompiled schema34 checkpoint/fencedfailure/no old33rollback/recover. ProductSQL не менялись.
40unit/50PG/58fixtures/release14/static0; earlierPG18/Bao9/common10/C11upgrade13 сохраненыкак отдельныеruns.
Failed fixture attempts corrected: PGready TypeNotify, transientcredentialpaths, RootTTY/operatorstart,
HTTP liveness wait, Raftinit60timeout. Успешныonly финальные2independentVM reports.52/200done.
Далее C14.01matrix/evidence review, C14.02actual24h persistentsoak. Until24h elapsed нельзяpass/release.
07adce1 published hostedv2/Websuccess; latestnativeVM/codefixes ещёlocal, pushразрешёнR020.
Main merge/deploy/envpublication не поручены.

R021 checkpoint C14: C14.01 reviewed executable15scenario matrix done,53/200. New runner real24h,
privatefsyncedstatus/events/samples/frozenbinaryhashes/twoTLSlinkfaults/realrenewal required; actualsoak
notstartedyet. Finalpreflight121.597s passed, explicit accepted_24h=false. Первые2short attemptsfailed
45sdrain withactiveproducer; finitefinaldrain fixed andpassed. Reconnect5passed real3agents/onehost,
smallquota/backpressure/retry/pendingpreserved/simultaneousreconnect/onceonly+cachedACKreplay.
41unit/58fixtures passed. Devbootstrapservervalidity bounded1h..168h default24h preserved;
soakserverleaf120h avoids expirybefore24hwindow; machineleaf24h mustrotate onactualclock.
C13 latestpublished8568927 hostedv2 41940421426/Web41940421462/boot41940421446 SUCCESS;
downloaded reports+hashes in C13-published-final/native-hosted. Nextcleancommit/build/startactual24h,
thenpersist exactrunID/start/deadline andcontinue E1acceptance/CI, noC15 untilrealC14gate.

C14 actualsoak started: run10812e7a-8a6a-4dae-9dd5-b0583f503c83 PID3505270,
measuredstart2026-11-05T00:31:49.765786Z, earliestcomplete2026-11-06T00:31:49.765786Z.
Clean source8560f57b11e9ed0fecd5774942c4d616b3afddc6 publishedPR4; all3 Go components record
source_dirty=false, frozenbinarySHA256/runnerSHA/configintervals in evidence/C14-soak.json.
Private localstatusv2/.local/c14-soak/<run-id>/status.json; scripts/soak_status.py checks livePID/age.
Actual24h RUNNING/notpassed; C14.02IP,53/200done; noC15beforeactualacceptance.
New8560f57hostedv2/Web/boot stillpending; C13old8568927all3SUCCESS retainedprecisely.
No shareddevPG/Bao outage/seal tests duringsoak. Detached runner survives tool/chat exit,
not machine/environmentshutdown. Persisted running marker alone neverPASS.

C14: реальный суточный прогон продолжает работать на зафиксированных binaries8560f57.
Добавлен архитектурный guard для E1-T15:92 production Go files,7 негативных контрпримеров.
`make verify` прошёл; точный JSON count —41 top-level tests +3 subtests (44 named PASS),
0 named fail/skip и58 C03 fixtures. Package-level skip означает отсутствие test files.
Guard меняет только тесты; исполняемый код суточного комплекта не менялся. Его ограничения
и pgx.Tx transaction coupling описаны в C14-architecture.json; API/worker production — C35/C40.
Обновлены устаревшие RELEASE/systemd/UPDATE docs по реально принятому C13.
C14.03/04 по-прежнему planned; C14-defects.json — журнал уже исправленных условий
предварительной проверки, не заключение о ещё не закончившемся суточном прогоне.

Уточнение architecture guard: исходные TestImportBoundaries и TestContractsUnchanged уже были.
При расширении файл временно заменён; исходные bytes восстановлены из8560f57, расширение вынесено
в sql_boundaries_test.go. Все4 architecture tests прошли вместе; final full verification выполняется.
Новый guard добавляет SQL ownership и client/PG ограничения; старые проверки сохраняются.
Реальные binaries8560f57 и работающий суточный прогон не менялись.

R-022 (2026-11-05): пользователь повторил «Продолжи» и «После автоматически продолжай остальные этапы».
Продолжать последовательный план после фактической приёмки зависимостей, без новых routine confirmations.
На текущий момент24h C14 остаётся обязательным gate; выполнять проверки/диагностику/подготовку
внутри C14, не подменять elapsed time и не помечать C15 как начатый раньше приёмки.

Продолжение R-022: подготовлен private candidate27files с clean8560f57 Go/Web;3 daemon hashes
совпадают с actualsoak. Отдельные test sign/verify/staging прошли, private signing key удалён.
Точные candidate Web/Go прошли Chromium16 с реальным PG/API; mocked display matrix указана.
README/backup/systemd/release docs актуализированы, добавлены draft release notes и read-only
soak_report.py (actual/preflight/failed old-format проверены, fake24h acceptance не возникает).
1a6c611 hosted v2/Web SUCCESS; boot secondVM failed, first9passed. Старый supervisor выбросил
guest diagnostic, точная причина неизвестна. Безопасные phase/line/error diagnostics сохранены;
два local VM9+9 повторно passed без воспроизведения. Независимый доказанный startup hazard
collector TypeSimple active-before-TLS устранён явным CA+collector DNS liveness wait передenroll;
edge также ждётTLS liveness. Не выдавать эту исправленную гонку за доказанную причину старого сбоя.
Final source/native/hosted checks pending. Actual24h8560f57 не менялся, C14.02IP/53done.

C14 native continuation: e3fe449 failed hosted boot at second_unseal_replay after4checks; safe
phase/line retained, old until-helper line did not identify the exact replay condition. Local e3
also reproduced first_bao_init/sys/mounts/transit failure immediately after unseal. Operator now
waits HTTPS health200 initialized=true/sealed=false/standby=false before provisioning, without
write retries/storage reset/custody regeneration. Two fresh local VM9+9 passed with this gate.
5954f5c published the gate and granular readiness/inventory/queue phases plus numeric guest call
lines/Bao HTTP status; no raw journals/custody upload. Hosted repeat pending. Actualsoak8560f57
passed both real two-minute cuts;124+ observations/oneUID/no duplicates/both queues drained,
max sampled inventoryage184.44s<300. Stillrunning/not24hPASS;53done and C15 waits.

C14 publication checkpoint: source5954f5c hosted v2 41956828439/Web41956828524/native41956828433
всеSUCCESS. Скачаны21 sanitized v2 reports (reconnect5/updater19), Web16, native twoVM9+9,
хеши в C14-hosted.json/C14-native-hosted.json.136 runtime inputs побайтно равны measured8560f57.
Actualsoak10812e7a-8a6a-4dae-9dd5-b0583f503c83 ещёrunning; обе реальных networkfaults восстановлены,
53done/C14.02IP. Final docs/evidence-only commit with[skip ci] не меняет validated code.
Следующие C14.03/04→C15 после фактического86400s PASS без нового routine confirmation;
private rawserial/keys/disks/custody/soakstate не опубликованы.

Продолжение2026-11-05: actualrun10812e7a пережил≥8h, оба network cuts и restart collector/center;
491+ observations/oneUID/no duplicates/queuesempty. Добавлен read-only evidence guard:
10 synthetic unit tests passed (не actual24h);965 live samples согласованы соstart reference,
maxmonitor gap32.027s, resultpending/accepted_24h=false. Проверяются fingerprint/ledgers/time/
counters/faults/finaldrain/realrenewal. Private pinned follow-up PID843094 сохранитreview после
терминального run, без Git/plan/release/C15 изменений. C14.02 ещёIP,53done; code stages после
реального24h результата в активной сессии. Новые source/tests/workflow publicationpending.

C14 follow-up: e7a07fe validator10 synthetic tests CI41999415338 иfullv2 41999415657 SUCCESS,
ноnative41999415334 failed после8checks на CLI-login. Safe phase/call lines сохранены в
C14-native-cli-failure.json; это новый расследуемый C14-D08. Добавлены command exit/duration/
allowlisted CLI error diagnostics иуспешные timings безargv/stderr/credentials.5 redaction tests
прошли, всегоPython15 (10 evidence+5redaction). Два local fresh VM9+9 passed, login4.286s/4.706s.
Причина remoteCLI пока не подтверждена; timeout/production code не менялись, retries не добавлялись.
Новый instrumented source нужно проверить вhosted. Actualsoak8560f57 продолжаетработать.

Checkpoint8024972: все4hosted SUCCESS (v2 42003198591/Web42003198611/native42003198599/
evidence-guard42003198780), дополнительный boundednative42004731564 тожеSUCCESS.
C14-hosted-802.json:21 v2 reports/Web16/дваprimaryVM9+9+дваextraVM9+9;15 Python unit tests
(10evidence+5redaction). CLI e7 incident не повторился в6freshVM; causeunconfirmed, C14-D08
сохранён дляC14.03, auth/timeouts не менялись, VM retry нет. Actualsoak уже≥9h, все4fault/restart
действия выполнены, queuesempty, evidence audit pending.53done/C14.02IP. Private pinnedfollow-up
843094 запишетreview автоматически послеfinish; не меняетGit/plan/C15 и не запускает чат.


## R-023 — Продолжать независимую подготовку, пока заканчивается суточный прогон

Дата: 2026-11-06, Москва. Запрос: «Есть ли смысл дожидать этого времени, уже почти 24 часа прошло, может продолжим?»
Статус: in_progress. Пользователь разрешает продолжать; независимая подготовка Windows C15.01
вынесена в отдельный worktree `/workspace/surveyscan-c15`, ветка `codex/v2-c15-windows` от f253a27.
Это уточняет прежний R-022: ожидание C14 не блокирует проектирование следующего пакета.
C14.02 всё ещё running, не PASS; release/acceptance C14 и фактический Windows runtime не объявлены готовыми.

Проверено live: PID3505270 совпадает с run10812e7a, sample свежий; elapsed80023.77s
(22h13m), observations1313, обе очереди0, renewal_receipts0 до ожидаемого окна около23h.
Earliest finish остаётся6 ноября03:31:49МСК; pinned runner/reference/follow-up и общие PG/Bao не менялись.
C15.01: подготовлена матрица 12 секций §6.1, API/права/ошибки, ОС Windows11 x64/Server2022 x64
как цели реализации; обнаружены C03 three-section contract и Linux-only locks/host binding/privatefile
ограничения. Windows/amd64 cross-build на Go1.27.3 exit0, PE32+; native Windows/API/ACL/SCM/reboot unrun.
Architecture guards прошли. C15 branch evidence/матрица публикуются отдельно по R-020.
Следующее: аддитивный observation/detail contract, затем Windows adapter/service и фактические тесты;
C14 после настоящих24h — read-only acceptance, triage C14-D08 и C14.04.
53/200 done; C15.01 in_progress, C14 completion не подменён подготовкой C15.

Продолжение R-023: C15.01 проектирование завершено (54/200 done с учётом отдельной ветки);
C15.02 начат с draft observation1.2 для12 typed sections.19 synthetic fixture cases matched
(7valid/12invalid); runtime/Windows unrun. Старые C03/C09, applied SQL, Go runtime не менялись.
Запрос «Продолжи следующие этапы после окончания» подтверждает автопродолжение без routine approvals.
C14.02 на последней live-проверке80432.676s/1320observations, queues0, sample8.58s, running.

C15.02 продолжение: отдельный Go NewInventory12 payload validator (пока без handler dispatch),
JCS/duplicate JSON keys/uint64/time/unique counts/IP-family limits и copy parity.3 top-level tests,
19 corpus +7 semantic subtests +3 malformed probes passed; make verify (format/vet/unit/C03 58) passed.
Full make verify сначала упёрся в sandbox socket prohibition, затем разрешённый loopback прогон passed.
Hosted Windows42125403759 на bb5c344 failed в Python-checker cp1252/UTF-8 до выполнения Go/version;
explicit UTF-8 fix и Python/Go-compatible regex проверены локально, repeat требуется.
Это изолированные C15 изменения; исходная C14 рабочая копия/pinned files/PG/Bao не менялись.
Draft stacked PR5: https://github.com/QgMixtate/surveyscan/pull/5 (base codex/v2-c13-operations).

C15 hosted repeat42126106107 на142b889 SUCCESS: Python19, Go payload corpus и build/version
реально выполнены на Windows Server2022; native API тогда ещё не запускались. Первый failed run сохранён.
Следующий изолированный native baseline добавлен: GetComputerNameEx/HKLM64 boundedMachineGuid/
RtlGetVersion/net.Interfaces;3 partial sections,9 unsupported. Windows test executable cross-compiled
локально; actual native API тест ожидает следующего hosted run. Служба и delivery не подключены.

Следующий C15 increment: расширен изолированный native baseline до8секций; CPU/RAM/BIOS,
Uninstall machine/currentuser32/64, read-only SCM states, fixed volumes/free space и IPv4/IPv6routes.
Данные partial,4секции unsupported; C15.02 не done. Windows cross-compile и vet passed, hostedpending.
Предыдущий3-section source3eb6c79 реально прошёл Windows42126656625; synthetic envelope указан.

Новый C14-D08 evidence: hosted boot42126656841/source3eb6c79 failed после8checks вCLIlogin.
Sanitized artifact13461866650 показывает command_exit5/HTTP503/5.741s. Это повтор того же этапа,
но внутренний root cause не установлен;5s auth context и медленныйTCG/PG — гипотезы.
HTTP timeout/auth/runtime не менялись, retry не добавлен; C14.03 gate открыт.
Failed proof сохранён вC14-native-cli-recurrence.json, не заменён успешным Windows CI.

R-023 checkpoint: Windows42127549414 на13702a8 SUCCESS —8native baseline sections, elevatedtoken
true, Go payload/Python19/CLIversion;3 native test functions passed. Windows facts real, envelope
synthetic. C15.02 partial,54done. Всё вPR5; E1fullregression/boot13702a8 ещёпроверять отдельно.
C14-D08 recurring503 остаётсяopen; actualsoak не заменён Windows/API тестами.


R-023 publication follow-up: C15 опубликован отдельно в draftPR5/baseE1. C15.01 design done,
C15.02 in_progress; общий54-task status находится в C15 branch, исходная E1 plan copy содержит53.
Hosted Windows42126106107 passed schema/Go payload/build/version;42126656625 на3eb6c79 passed
actual3-section native API baseline с synthetic origin/scope/sequence. Source13702a8 добавляет
8baseline sections, localWindows cross-compile/vet passed, hostedpending. Standarduser/LocalService/
Windows11/fullinventory/SCM/reboot/delivery не приняты. Original E1 runtime/frozen soak неизменны.

Синхронизация C15 с E1 parent9e880ed: сохранены журналы обеих веток;
новые C15 runtime libraries остаются изолированными от измеряемого E1 checkout.



R-023 продолжение2026-11-06 («Дальше»): actualC14.02 завершён, независимыйread-only acceptance
exit0 и pinnedfollow-up exit0:86400.914s/2740samples/1419observations/2renewals/queuesdrained.
Публичный sanitized C14-soak-result.json создан; pinned startreference C14-soak.json не менялся.
C14.02done, C14.03in_progress/D08 investigation, C14.04planned. E1done54 + C15.01design=55global.
13702a8 fullv2 42127549066 иnative42127549126 SUCCESS; D08 failure не закрыт успешным повтором.
Следующее — безопасная backenddiagnostic stage/reason, воспроизведение и исправление по фактам.

C14.03 checkpoint: добавлена fixed-vocabulary backend login diagnostic(stage/reason/elapsed_ms/verify_ms),
без username/password/SQL/rawerror; API response/error policy/5s budget/Argon2 unchanged.
Guest/supervisor экспортируют только allowlisted fields.2Go redaction tests +17Python tests passed;
make verify/C03 58 passed. Это диагностическое изменение после measured8560f57, не новый24hproof.
Следующее — fresh nativeVM и hosted CI с диагностикой; D08 покаopen.

C14.03 checkpoint:4a589d2 all4hosted SUCCESS (v2 42180569553/native42180569494/Web42180569517/evidence42180569485).
Local firstVM9passed/login3.886s; secondVMkernelstalled beforePID1 afterHPET clocksource,
173%QEMU CPU/no kernelprogress >=8min. Owned supervisor interrupted; campaign failed, notPASS.
C14-D09 fixture change Q35 hpet=off pending freshVM. Controlled PGlock test passed:
503/5004ms, passwordverify121ms, stageuser_recheck, zero credentials; explicit recoverycreates1.
Optional CPUpressure probe in disposable VM added (runtime quota only; host unaffected); expected
5s deadline after slow Argon2 requires actualVM verification. No product timeouts/crypto changes yet.

C14.03 controlled native probe039af35:10checks PASS, Q35hpet=off actualboot/reboot;48%serverCPUquota
→ passwordverify6464ms, elapsed6528ms, session_begin/deadline_exceeded, HTTP503, no credential minted.
Afterquota restore explicitlogin succeeds. Confirms post-hash requestdeadline class; historical503
exactcause stillunprovable without originalbackendtrace. Fix currentGo:login budget5→8s, below
serverWrite10s/CLI15s; Argon2/rate/hashslots2 unchanged, no implicitretries. Same48% after-testpending.
Controlled PGlock stillmusttimeout/rollback/no-cookie/no-session at8s; targetedtest rerunning.


C15 sync: E1 parent39e401f merged, C14.02done and C15.01done preserved;55/200global.
Login budget8s/diagnostics and testfixture HPET fixes included; combined CI pending.


39e401f native after-test10checks PASS: same48%CPUquota→HTTP201/6336ms, exactly1credential
created andexplicitlyrevoked; no implicitretries; explicit recoveryCLI also succeeds.
Old5s source039af35 at48% gave503/verify6464ms/session_begin; controlleddeadlineclass nowremediated.
Historicalinstance rootcause not retrospectivelyclaimed. RealPGlocknew8s→503/8007ms/verify119ms,
zero credentials; explicitafterunlocklogincreates1. Both Q35hpet=off before/after freshVM10checks pass.
Final realPG/fullhosted regression39e401f pending; C14.03 remainsIP until requiredregressionpasses.

C14.04 preparation: clean39e401f candidate27files/test-Ed25519-sign/verify/stage passed;
temporary private signingkeydeleted. Exactcandidate server/collector/contracts/staticWeb
(Go39e401f/Webclean8560f57 independentversion) passedChromium16 withrealPG/API;
synthetic signed source andexplicitmockdisplaycases declared. Notwholecandidate24hproof:
24h baseline8560f57 + authdeltaPG/nativeCPU/hostedregression remain separate.
Native39e401f hosted42183074101 twofreshVM9+9 SUCCESS; fullv242183074129 stillrunning.
Local fullPGintegration51 passed, post-fix blockeduser stillfailsclosedat8s.

C14 завершение:39e401f all4hosted SUCCESS;21 sanitized E1 reports и2freshVM9+9 сохранены/хешированы
вC14-hosted-39.json. LocalPG51 иcandidate27files/sign/verify/stage/exactChromium16passed.
C14.03/04done вbounded LinuxE1;57/200global сC15.01design. C14-acceptance.json явно разделяет
measured24h8560f57 иauthdelta39e401f, сохраняет historicalfailures/residualunknowns.
Внутреннийкандидат не является productiontrust/officialGitHubRelease; main/deploy/envpublication нет.
Следующий шаг по автопродолжению — C15.02 в /workspace/surveyscan-c15/PR5:4native sections
иnegotiated signedpipeline, затемDACL/SCM/reboot. Не считать8partial sections полноценным C15.


C15 continuation: C14 accepted/fa73e47 metadata merged,57done. Combined981f4e7 all5hosted
SUCCESS (v242183377291/boot42183377336/Web42183377340/C15Windows42183377357/evidence42183368906).
Продолжать C15.02 users/groups native; полнаяpipeline/ordinaryrights/SCM/reboot всё ещёunrun.

C15.02 следующий increment после C14: native local users/groups/membership публичныеSID,
NetUserEnum0 иNetLocalGroupEnum/GetMembers0; boundedpages/limits/cancellation; SIDlookup
localNetBIOS/BUILTIN. DC исключён: LOCAL_SAM_UNSUPPORTED_ON_DC, без domainSAMenumeration.
Windows cross-compile/vet + Linuxarchitecture/wire tests passed; native CIpending.
NativeLocalAccountsAndMembership test проверяет users/groups/members/SID без вывода имён/SID.
Триremainingсекцииupdates/protection/neighbors; C15.02fullpipeline/DACL/SCM/reboot ещёнеdone.

Windows42186520226 наf32a755 SUCCESS: native9baseline/elevated, localSAM users5/groups27/
memberships8; names/SIDs невыводились. Следующийnative increment — GetIpNetTable2 local
ARP/NDPcache, max10000rows, ABItest, noactiveprobes/notcompletetopology. Optional interface_index
добавленвdraft1.2networkRow (дляNIC/routes/neighborsjoin, неpersistentUID); C03/C09 unchanged.
Crosscompile/vet/wire/architecture/Python19passed; новаяWindowsCIpending. Updates/protection
иfullcoverage/signeddelivery/storage/API/DACL/SCM/standarduser/reboot остаютсянепринятыми.

C15 Windowsf577436/42188089781 SUCCESS:10nativebaseline sections,5testfunctions;
elevatedtoken=true, users5/groups27/memberships8, ARP/NDPcache25rows. Noactiveprobes/fulltopology
claim. Two sections updates/protection иfullcoverage/pipeline/rights/SCM/reboot ещёunrun.
Web42188089767SUCCESS, fullv2/bootf577 продолжаются; C14acceptedsource39 остаётсяseparateproof.

C15.02 продолжение2026-11-06: updates/protection adapters добавлены через fixed local COM/WMI
worker в том жеWindowsagentbinary. Parent30s/1MiB/stdout validation/kill+reap; profiles незадают
произвольные executable/query/target. QFEsubset, realfirewall booleans, Defender/AV provider
availability; locale InstalledOn неугадывается. go-ole1.3.0MIT pinned, noPowerShell/Win32_Product.
Windows crosscompile/vet + makeverify/C03 58 passed; Section validation tests passedLinux.
Windows native COM и synthetic helper failure/isolation tests ещёpendinghosted.
FullC15.02wire/storage/API/fieldcoverage иC15.03/04неприняты,57done unchanged.

Первый Windows COM job42191352349/source3d680cb: actualQFE5/protection6/native12baseline
passed, ноwholejobFAILED наsyntheticoversize child. Причина: promotedbytes.Buffer.ReadFrom
позволялio.Copy обходитьWrite bound. Fixed privatebuffer/noReaderFrom; Linuxreader-only
regressionpassed, Winchildtestsrepeatpending. FailureC15-D03сохранён, не переименованвPASS.
Проверено: текущийE1scheduler sequential, не independentheartbeat при долгойcollection.
Это обязательныйC15gate передruntimeenable; draftNativeSDK всёещёизолирован.

C15 d9e6206 verification: all4hosted SUCCESS (Windows42192291716/v242192291708/
boot42192291745/Web42192291735). Native12baseline/QFE5/protection6, provider availability
partial; failureisolation, blockedchild2s→kill/reap, crash/invalid/overflow/canary allpassed.
C15-D03 fixed privatebuffer +Linux/Windows io.Copy regression. makeverify/C03 58passed.
Не считатьЭтоготовымWindowsagent: fullfieldcoverage, signed1.2pipeline, PGprojection/API,
independentcollection scheduler, DACL/locks/SCM/reboot/ordinaryrights ещёнеприняты.57done.
Следующее — C15.02 backendintegration по decisions/C15-pipeline-gates.md.

R-020/R-022/R-023 продолжение2026-11-06: C15.02 server projection foundation.
Новая миграция0033 (34/47), отдельные typed record facts с per-field provenance и partial
preservation; unknown legacy sections reject; registry locator + current token SID для HKCU.
Local makeverify/C03 58, Python24, Winbuild/vet, PG53 + отдельный upgrade33→34passed.
Подписи в PGfixture синтетические; trusted internal primitive, rollback, не signed HTTP E2E.
Публикация/новый hosted proofpending; C15.02IP/57done, дальше API/negotiation/scheduler gates.

C15 продолжение2026-11-06: 999c6e1 publishedPR5, v2/Web/WindowsSUCCESS; boot42197490003
FAILED наstale expected33 послеreboot, C15-D04fix34 preserveschecksumcheck/repeatpending.
Добавлен additive paginated readAPI1.2 + OpenAPI, typedfields/per-fieldevidence/lastattempt,
100items/2MiB, cursorboundtenant/asset/section/revision,409PROJECTION_CHANGED. ActualTLS/auth/
PG56passed соsignedsynthetic internal-store setup иrealcommitguards; это не1.2machineE2E.
ПубликацияAPIpending; C15.02IP/57done, negotiation/coverage/scheduler/lifecycle gates остаются.

C15.02 продолжение: f6e3047 все5hostedSUCCESS; boot2freshVM9+9 подтвердилC15-D04fix.
Следующийlocalincrement: isolatedsigned/batch12 contract+parser, trustedbindingEd25519,
all-hop effective limits512/576/768KiB/100records; C03handlersstillunchanged.
НайденC15-D05JSONHTMLexpansion incollector: mTLS/C03-valid479558bytebatch becomes
2324798byteoldpacket>2MiBreader; nonexpandingcodec+finalsizeguard fixed479799. Actual
mTLS/admission/signature/disk/replay202 +race+verify/build/Wincompile/vet passedlocal.
Документы decisions/C15-transport.md/evidenceC15-transport.json, pendingpublication.
No1.2machinepipeline/capabilityHTTP/profileimplemented,57done/C15.02IP unchanged.

Продолжение пользователя «Продолжай»: 7ce0fda опубликован и все5hostedSUCCESS, C15-D05fixed.
СледующийC15.02increment — authenticated capabilities с audience/nonce/expiry и отдельным
signaturedomain, затемruntime1.2dispatch. Поканеadvertise12 безготовыхhandlers.57done.

C15.02 continuation: center POSTinventory-capabilities implemented, active collector mTLS/
PG authorization; signednonce/audience/tenant/generation/expiry with existingcentertrust,
newsignaturedomain. Current[1.0]truthfuloffer; no false12advertisement. PG57passed; actual
scopedOpenBao/nonexportableTransit compiledpipeline20passed inclcap200/seal503/unseal200,
no privatefallback. NewreportsC15only; E1sharedcredentials reusedread-only, no keycopies.
Publicationpending, thenopt-in1.2dispatch/admission/projection/ACK andcollectorforwarding.

C15.02: b709eef all5hostedSUCCESS. Optincenter1.2 implemented(defaultoff), advertised
onlywhenadmission+registry agree; frozenC03/C09 preserved. PG58passed; realcompiled
mTLS/courier/delegatedsyntheticagent/scopedTransit/PG12sections/typedAPI/ACK/replay6passed.
Downgrade retains stagedbytes withoutlease/retry; complete12notimplemented/rejected,
committedACK remainsavailable. ExistingHTTPPOST202 preserved; tests/docs corrected.
Collector12relay/threehopcapabilityforwarding andactualWindowsdaemon stillnext;57done.

C15.02 next: aa58bd2all5hostedSUCCESS. Collectoroptin12(defaultoff/managedidentity),
sameSourceTLS/crypto/scope andboundedspool; finalACK1.0boundtooriginalbatch12. Actual
compiledmTLS/scopedTransit/PGAPIrelay9passed withsyntheticagent, includingowncenter
outage +collector/centercoldrestart, originalsignedbytes/UID retained,2observations1asset,
deleteonlyverifiedACK. Threehopcapabilityexchange/actualWindowsdaemon stillunrun.57done.

C15.02 continuation «Продолжай»: fbca7ac published in draftPR5; all five exact-SHA
hosted workflows SUCCESS, including fullv2 42227311999/relay9 and nativeboot42227312025.
Evidence C15-hosted-fbca.json; superseded cancelled runs retained explicitly. Global57done;
manual opt-in relay does not close Windows daemon/three-hop negotiation. Next plan:
decisions/C15-agent-capability-next.md. No main merge/deploy/env publication.

Продолжение «Продолжай»: authenticated three-hop capability chain implemented locally.
Collector signs nonce/tenant/issuer/audience/generation/expiry + unchanged center frame;
Go agent verifies actualTLS attested key and own enrollment-pinned centerkey, intersects
all3 offers. No daemon enable/profile/spool rewrite. Compiled actualmTLS/scopedTransit/PG
relay10passed with Python syntheticagent; Go method separately realmutualTLS/production
collector and center Ed25519 testdouble. verify/C03 58, PG58, race3packages/Winbuildpassed.
Evidence C15-capability-chain.json; publication pending. Next Winprofile1.2/scheduler;57done.

Автоматическое продолжение: независимый collection worker без доступа к Client/
keys/counters/spool; actor alone commits signed results. Deadline/late-result reject/
no overlap иheartbeat progress passed with HTTPS testdouble. Actual compiled Linux
agent+collector+server/mTLS/PG11 passed (3cycles+restart4th, sameUID/counters/ACK/lock/
revocation), verify/build/C03 58/race/Winbuild passed. C15-independent-collection.json;
publication pending. Windows daemon/SCM/provider termination/new24h not claimed,57done.

44803bf: fourhostedSUCCESS but fullv2 42231190362 failed at isolatedBao snapshot-force.
C15-D06 preserves failure; original numericstatus lost/causeunconfirmed. Added active
leader readiness before singlewrite and safe numericstatus; actual localrestore9passed,
no write retry/source reset. Native Windows newincrement isolates all12providers in
ownbinary bounded processes; Winbuild/testcompile passed, native executionpending.
C15-all-provider-workers.json; scheduler bf6c9a8 committedlocalnotyetpushed.57done.

2fe4b93 publication: fullv2/Windows/Web/evidence SUCCESS; actual Windows all12 child
providers inclsoftware crash/later services passed; hosted restore9 confirmsD06guard.
Boot42233416959 failedfirstVM afterrebootsecond_queue_drain/4checks, D07causeunknown.
SameLinuxproductcode freshlocalVM9/reboot/update/CLI passed(login4.938s). Added safe
queue counts/closed reasons and8privacytests, no product/timeout change onguess.
Two instrumented hostedVM repeat next; all5 not yetgreen. Windows profile nextplan
prepared; notimplemented, global57done/C15.02IP. Exactevidence C15-hosted-2fe.json.

5fb5838 hosted boot42236193133 passed two independently fresh VM9+9; D07notreproduced
in3freshVM total, causeunconfirmed. Newlocal D08: report durable verifiedACK removal
progress separately from a new transport-only pending packet; actor resets backoff
onlyon actualprogress, publicFlush contract unchanged. Mixedpacket regression/race/
verify/C03 58/Winbuild passed; actual3agents reconnect/quota/network/replay5passed,
drain21.347s. Not claimedasprovenD07cause. AGENTS checkpoint history preservedwhole
in AGENTS_HISTORY.md; currentrules keptconcise toreduce nextchat context.57done.

D08fix published asd4ae425130fab36f80ff58dd4de08ace41052e9e inPR5; exact-SHA five
workflows launched (v242237739720/boot42237740069/Windows42237739729/Web42237739727/
evidence42237739732). Localverify/build/race/Wincompile/mixedACK/real3agent5 passed;
newhostedpending. Prior5fb twoVM9+9 confirmed;57done. No merge/release/deploy/envpublish.

Final d4ae425 exact-SHA all5 hosted SUCCESS: v242237739720/Windows42237739729/
Web42237739727/boot42237740069/evidence42237739732. Downloaded23sanitized v2reports
andtwofreshVM9+9 reports, hashes C15-hosted-d4.json. PG58/relay10/center6/agent11/
reconnect5/restore9 andnativeall12/failureisolation passed. D07historicalcause still
unproven; independentD08fix verified.57done/C15.02IP; nextWinprofile1.2/securestate,
SCM03/04 remainsafter02acceptance. No merge/release/deploy/envpublication.

2026-11-06 продолжение «Погнали»: реализован signedWindowsprofile1.2core — closedDTO/schema,
отдельныедомены/nonce/tenant/generation/collector, commoncadence+fixedpartial12policy30s/420s.
Sources0034 separate offered/appliedprogress/readAPI;35migrations/48tables. C12/freshness
не изменяются. Go client read-only fetch requires freshthreehopproof, неapply/cache/ACK.
verify/build/C0358/PG60/race3packages/Winbuild-vet/compiledrealmTLS/Transit/PGrelay11passed.
Agentdata synthetic; Linuxfsync acceptancefixture explicit, Windowscacheunrun. NewSQL
appendonly, privateupdate0035/schema35→36. Publicationpending; далееsecureWindowsstate/
cache/runtime внутри02, SCM03/04 после02acceptance.57done. No merge/deploy/envpublish.

4ff977f profilecore all5hostedSUCCESS: v242304020057/Windows42304020149/Web42304020116/
boot42304020084/evidence42304019982. Downloaded sanitizedreports:relay11/center7/twoVM9+9;
PG60/backup49tables/privateupdate35→36passed. Далееlocalunadopted winstate module:
protectedDACL/localroot/finalpath+relativeNTfiles/bounds/nooverwrite/exclusiveprocesslock,
Wincompile/vetpassed, nativeexecutionpending. Неatomiccache/hostbinding/runtime;57done.

Winstate57e305b published; firstnative42306359060 FAILED atCreateNew file_type validation.
Lock acrossprocesses andredactionpassed, wholesuite notpassed. C15-D09: writer handle
lackedFILE_READ_ATTRIBUTES forGetFileInformationByHandle; added explicitright, no guard
relaxation. Crosscompile/vetpassed; native repeatnext. Runtime stillnotadopted,57done.

Winstatebase c7e2f0a all5hostedSUCCESS; nativeWindows42306657936 provesD09fix andall
DACL/reparse/hardlink/crossprocesslock/redaction cases. Nextlocal atomicreplacement: held
writerlock, private stagedfsync, root-relativeNT rename, typedoptionalreads/whole snapshots,
sharingfailurecleanup andbefore/after-process-crash tests prepared. Wincompile/vetpassed;
nativepending, not runtime/cache adoption. C15-winstate-atomic.json,57done unchanged.

Atomic6768d8f native42308645680 failedconcurrentreader code32 duringpublication; all
lockedreplace/sharingfailurecleanup/before+afterprocesscrash/old+newwholedata/lockrelease
andDACLbase casespassed. C15-D10 targeted bounded1s read-only sharing retry; write/rename
not retried, ACL/I/O never treatedasabsence. Native repeatnext; module unadopted,57done.

## R-024 — Переход на Claude, продолжение C15.02 (atomic_rename)
Дата: 2026-11-08. Запрос: прежнюю разработку (Codex) больше не вести; продолжить с текущей точки,
историю хранить в git (экономия контекста), далее работать по этапам плана.
Ветка: claude/peaceful-goodall-a8u9sk (fast-forward от codex/v2-c15-windows 5fe78c5, без force). Единственный писатель.
Сделано: f04274f — сырой NTSTATUS в winstate-ошибках (число, без путей). Windows run 42514937997:
`atomic_rename code=5 status=0xc0000022` = настоящий STATUS_ACCESS_DENIED (не DELETE_PENDING/CANNOT_DELETE).
Причина (по статусу и коду; не доказана отдельным экспериментом): классический FileRenameInformation не заменяет файл,
открытый читателем, даже с FILE_SHARE_DELETE. Исправление C15-D11: FileRenameInformationEx (65),
REPLACE_IF_EXISTS|POSIX_SEMANTICS, без IGNORE_READONLY; открытие/DACL/reparse/hardlink-проверки не менялись; retry не добавлялись.
Ограничение: Windows 10 1709+/Server 2019+, NTFS; Server 2016 не поддержан этим вызовом.
Проверки: Windows cross-vet passed; нативный Windows CI на исправлении — см. STATUS (до результата не считать закрытым).
Следующий шаг: подтвердить все 5 workflow на точном SHA, затем orphan recovery, адаптеры private file/spool, MachineGuid.

R-024, итог 8 ноября. C15-D11 закрыт на native Windows Server 2022: 505f7a4 (atomic replace) прошёл c15 42515121234.
3566cf7 добавил RecoverOrphans; run 42515414808 упал только в моём тесте PreservesUnsafeLeftovers (root.Read по дизайну
отвергает файл с 2 ссылками; продукт сохранил и остаток, и цель). 7d67248 исправил тест: c15 42515541316, v2 42515541308,
boot 42515541314 — success. Прогоны 505f7a4 v2/boot отменены новым пушем, итог принят на 7d67248. web/evidence не запускались.
Не доказано: ordinary rights, Windows 11, Server 2016 (FileRenameInformationEx недоступен), power-loss durability.
Следующий шаг: общие private file/disk spool адаптеры, затем host continuity (MachineGuid), signed durable cache.

R-024, адаптеры 8 ноября. e3fecbf: Windows privatefile.Read и diskspool.Lock/Atomic/SyncDir/RecoverTemps поверх winstate
(Linux-код вынесен в !windows без изменения поведения). Run 42517551862 упал: два новых нативных теста адаптеров прошли,
упали три старых POSIX-теста files_test.go, которые я сам начал гонять на Windows (пишут через Atomic без lock). 1c29799:
files_test.go помечен !windows; c15 Windows, v2, boot — success. Не портированы Capacity/Data (os.ReadDir по пути); каталоги
после обычного MkdirAll адаптер отвергает — runtime обязан создавать состояние через winstate. Не adopted агентом.
Следующий шаг: host continuity (MachineGuid), клоны/повторный enrollment, затем signed cache.

R-024, host continuity 8 ноября. b25f07a: пакет platform/machineid (Linux /etc/machine-id как раньше; Windows MachineGuid из
64-битного реестра; прочие платформы unavailable), agent.localMachineID через него. c15 Windows2022, v2, boot — success.
Граница: клон ВМ без sysprep сохраняет MachineGuid, привязка ловит замену хоста, но не клон. Повторный enrollment/клоны,
signed durable cache, apply+applied ACK и Windows runtime не сделаны. Агент на Windows не запускается.

R-024, signed cache 8 ноября. 9e7538c: wire.VerifyCachedInventoryProfile12 (отдельный офлайн-путь без nonce/срока: подпись, ключ центра,
tenant, origin+поколение, collector) и agent-кэш inventory-profile12.json (точные подписанные байты, перепроверка при каждой
загрузке; ревизия не убывает, та же ревизия с иной конфигурацией отвергается). 3 Linux-теста; v2 и boot — success, c15 не
запускался (пути). Нативная запись кэша через Windows-адаптеры не проверена. Никто не вызывает кэш: apply, applied ACK после
durable commit и Windows runtime — следующие шаги. Найдена и исправлена потеря завершающего \n при json.RawMessage.

R-024, sync/applied 8 ноября. 8cff618: Client.SyncInventoryProfile12 (applied сообщается только из durable-кэша, кэш заменяется после проверки
свежего ответа), CachedInventoryProfile12 (офлайн, лимиты не шире агента/профиля/максимумов), нативный Windows-тест записи кэша через
приватные адаптеры (диск как приватный корень, без lock запись невозможна). c15 Windows 42521990391, boot 42521990366, v2 42521990363 — success.
Граница: Windows runtime не вызывает Sync/Cached, на очередь наблюдений не влияет; re-enroll/клоны и runtime — дальше.

R-024, Windows runtime, путь 1 (решение пользователя: отдельный Windows-цикл, Linux E1 не менять). Разбиение остатка C15.02:
W1 состояние+блокировка (ensureStateDir над winstate, lockState над diskspool.Lock; Linux-поведение прежнее) — в работе;
W2 секции windowsinventory -> Observation 1.2 -> подписанный batch -> очередь (в агенте такого пути ещё нет, есть только wire/collector);
W3 цикл RunWindows: Sync/Cached профиля, один collection task, heartbeat, delivery; W4 enroll/prepare/renew на Windows с проверкой
в CI; затем C15.03/04. Клоны: известное ограничение MachineGuid до C15.04.

R-024, W1 итог. 8497cfb: c15 Windows2022 42525213933, v2 42525213892, boot 42525213856 — success; нативно проверены приватный state-каталог (повтор/вложенный spool),
вторая блокировка отвергается, каталог с унаследованным ACL отвергается. Дальше W2 (секции -> Observation12 -> batch -> очередь).

R-024, W2 итог и W3a. W2 513d7d7: buildBatch12/queueSections12 (канонический payload, подпись агента, batch 1.2 через согласованный транспорт; проверено на
корпусе C15) — c15 42526462370, boot 42526462385, v2 42526462373 success. W3a: flushProgress12 (копия доставки под InventoryDecoder; Linux flushProgress не менялся),
diskspool.Remove и winstate.Root.Remove (удаление через приватный корень под lock). Находка: принимающий декодер отвергает секции ok/complete в 1.2, поэтому buildBatch12
теперь отвергает их сам (иначе пакет застрял бы в очереди навсегда); старый C03 flushProgress батч 1.2 не принимает — доказано тестом. Не подключено к циклу (W3b).

R-024, W3a итог и W3b. W3a 8ff6de9: c15 42527719494, boot 42527719501, v2 42527719469 — success (flushProgress12, diskspool/winstate Remove, партиальные секции).
W3b: runLoop12 (цикл над узким интерфейсом client12) + windowsClient12 + RunWindows + dispatch runAgent в surveyscan-agent (Linux по-прежнему agent.Run). Правила:
сбор только при проверенном профиле 1.2 (negotiate+Sync); сетевой сбой -> последний принятый профиль в памяти или durable-кэш; отказ по протоколу/ошибка кэша -> новые сборы
прекращаются, heartbeat и доставка продолжаются; один сбор за раз, лимит = collection_timeout профиля. Проверено на Linux фейковым клиентом (-race): нет сбора без профиля, офлайн
со старта только при кэше, остановка после отказа, классификация сбоя. НЕ проверено: RunWindows ни разу не запускался (нет Windows-enroll, W4), реальные сеть/центр/PG с Windows-агентом,
Windows 11/обычные права, SCM. Namespace кандидатов Windows (hostname.raw, windows-machine-guid) требует подтверждения сопоставления в центре (C15.04).

R-024, W3b итог. 900a1d2: c15 42529093397, boot 42529093501, v2 42529093597 — success (цикл проверен на Linux фейками; RunWindows не запускался). Далее W4: нативный тест Prepare/ReadConfig на Windows.

R-024, W4a итог. e3802d5: c15 Windows2022 42530303711 success — нативно: Prepare на свежем state (приватный корень), повтор не заменяет личность, tls.key != signing.key,
ReadConfig читает конфигурацию из приватного каталога (defaults 900/60) и отвергает обычный каталог; os.Chmod(state,0700) безвреден. Не проверено: enroll/bind-host/renew (нужны collector+center),
RunWindows целиком, SCM. Решение за пользователем: где гонять интеграцию Windows-агента с центром/PG в CI (см. STATUS).

R-024, решение пользователя: вариант 4 (сквозная интеграция на Windows-ВМ, не в CI). d3c0138: c15 Windows2022 42534540858 success — шаг "compiled agent prepare with an icacls-made private config":
оператор-процедура (icacls на каталоге и файле) принята проверкой ACL, prepare скомпилированным агентом стабилен и не печатает ключи. Находка: любой файл в приватном каталоге
должен иметь явный защищённый DACL (унаследованные ACE отвергаются), т.е. conf/CA/grant защищает оператор или установщик C15.03. Подготовлен runbook
handoffs/C15-windows-vm-integration.md (проверено/не проверено разделено). C15.02 остаётся in_progress до фактического прогона на ВМ; счётчик 57/200 не меняется.

R-024, C15.03 начат (вне ВМ; решение пользователя: пока ресурса ВМ нет, продолжать). Шаг 1: доверие ACL для службы. Служба обычно работает от LocalSystem, а состояние готовит администратор;
запись с личным SID администратора делала бы каталог недоверенным для службы. Теперь для токена с включённой группой Administrators (SYSTEM тоже) корень получает только SY+BA, для обычного
пользователя прежний SID сохраняется. Нативный тест AdministratorRootHasNoUserSpecificEntry. Проверка — в CI (см. следующую запись).

R-024, C15.03 шаг 1 итог. 91610e7: c15 Windows2022 42535220492 success. Первая попытка (10f437c, run 42535078561) упала в новом тесте: IsMember не работает с основным токеном процесса,
личный SID администратора остался в DACL; исправлено явным разбором групп токена (enabledAdministrator). Теперь корень администратора/SYSTEM содержит только SY+BA.
Шаг 2 (в работе): пакет platform/winservice (Install с отложенным автозапуском LocalSystem и 3 перезапусками при сбое, Start/Stop/Uninstall/Status, Run с кодами выхода по этапам)
и нативный тест жизненного цикла через SCM (службой выступает тестовый бинарник). Команды install-service/uninstall-service/service агента — следующий шаг. Reboot/обновление/Windows 11 — не проверены.
