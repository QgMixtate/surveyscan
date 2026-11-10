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

R-024, C15.03 шаг 2 итог. 9355cfb: c15 Windows2022 42535410146 success; в логе job 128898524546 TestServiceLifecycleThroughSCM — PASS (не SKIP, 0.22s): Install (delayed-automatic LocalSystem,
3 перезапуска), повторная установка отвергается, Start->RUNNING, Stop->STOPPED код 0, Uninstall, неверное имя/относительный путь отвергаются; тестовый бинарник запущен SCM как служба.
Не проверено: команды агента install-service/uninstall-service/service (следующий шаг), поведение SYSTEM-службы на состоянии, подготовленном администратором (целевой тест: служба доходит до
этапа Open, а не отвергает ACL), перезагрузка, обновление с сохранением личности/очереди, Windows 11/обычные права. Передача новой сессии: контекст прежней достиг ~490 тыс. токенов.

R-024, C15.03 шаг 3 (в работе, результат CI — следующей записью). В cmd/surveyscan-agent добавлены Windows-команды install-service (LocalSystem, delayed-auto, 3 перезапуска, требует абсолютный --config), uninstall-service и service (вход SCM → agent.RunWindows). RunWindows теперь помечает этапы agent.StageError: 1 — состояние/блокировка/.tmp-*, 2 — Open (не зарегистрирован), 3 — очередь, 4 — клиент 1.2/лимиты; код идёт в SERVICE_EXIT_CODE службы. Linux agent.Run не менялся; на Linux команды службы возвращают ошибку платформы. Локально: go build/vet, GOOS=windows vet, go test internal/agent — проходят. Новый шаг c15.yml: установка службы из скомпилированного агента на состоянии шага prepare (icacls, администратор), запуск, ожидание STOPPED, требование SERVICE_EXIT_CODE=2 (код 1 = ACL отвергнут), затем uninstall. Оговорка: код 2 доказывает, что состояние принято блокировкой (этап 1), но Open падает на отсутствии identity.json; ACL отдельных файлов внутри Open отдельно не различается. Не проверено: перезагрузка, обновление с сохранением личности/очереди, Windows 11, обычные права, клоны, сквозной прогон на ВМ.

R-024, C15.03 шаг 3 итог. e3759bd: c15 Windows2022 42537133764 success (нативно, администратор). Из скомпилированного агента: install-service отвергает относительный --config и повторную установку; служба LocalSystem, delayed-auto (по sc qc); запуск SCM; служба остановилась с WIN32_EXIT_CODE 1066 / SERVICE_EXIT_CODE 2 — дошла до этапа Open (identity.json нет, агент не зарегистрирован), блокировка и ACL состояния, подготовленного администратором (только SYSTEM+Administrators), приняты LocalSystem; uninstall-service удалил службу. Факт для оператора/установщика: служба под SYSTEM отвергла конфиг, у которого в DACL есть личный SID пользователя (первый прогон 5b9aa15^: "config: private file unavailable", код 1053) — файлы состояния для службы должны иметь DACL только SYSTEM+Administrators (модель доверия, не дефект). Прогоны-провалы 024d9cb/8da6509/8b36ab8 (тестовая настройка: SID пользователя в DACL; затем проверка кода выхода после uninstall) сохранены в истории. Добавлен необязательный --error-file для диагностики завершения службы. Оговорка: код 2 не отличает падение внутри Open от ошибки ACL отдельного файла внутри Open; ACL корня/конфига принят (этап 1 пройден). Не проверено: перезагрузка, обновление с сохранением личности/очереди, Windows 11, обычные права, клоны, сквозной прогон на ВМ (enroll/bind-host/run). C15.02 in_progress, 57/200 без изменений.

R-024, C15.04 начат (решение пользователя: проверку на реальной Windows зафиксировать и вернуться позже). Создан handoffs/C15-04-verification.md: таблица V1–V10 «к чему вернуться» (ручная проверка установки службы пользователем V1, сквозной прогон enroll/run V2, перезагрузка V3, обновление поверх работающей службы V4, обычные права V5, Win10/11 V6, клоны V7, протокол данных/секций V8, CPU/память/recovery V9, перечень заглушек V10) — всё, кроме частично V4, НЕ выполнено. Без ВМ добавлен нативный CI-шаг: переустановка службы с другого пути бинарника на том же состоянии, служба снова доходит до Open, личность (source_id, csr_sha256) не меняется. Результат CI — следующей записью. C15.04 остаётся planned, 57/200.

R-024, C15.04 шаг 1 итог. e3136f5: c15 Windows2022 42538385739 success. Нативно (администратор, без enroll и перезагрузки): переустановка службы из бинарника по другому пути на том же состоянии — служба снова доходит до Open (код 2), source_id и csr_sha256 после обновления прежние. Это только часть V4; V1–V3, V5–V10 из handoffs/C15-04-verification.md остаются НЕ выполненными, к ним нужно вернуться. C15.04 planned, C15.02 in_progress, 57/200.

R-025, C16.01 (пользователь: выполнять план без остановки; C16 зависит только от принятого C14). Создан decisions/C16-linux-capabilities.md: факт — Linux-агент собирает 3 секции (identity, os, network); таблицы целевых секций §6.1 с источниками и правами, предложение дистрибутивов (Debian 13 целевой по D-06 proposed; supported/unsupported указаны), профили прав, открытые вопросы. Это проектный документ по чтению кода: живых прогонов на дистрибутивах нет, дистрибутивы не утверждены. C16.01 — draft, не done; 57/200 без изменений. Параллельно остаются невыполненными V1–V10 из C15-04-verification.md. Следующее: C16.02 (реализация секций), чистые /proc-парсеры с тестами на фикстурах.

R-025, C16.02 шаг 1. Пакет v2/internal/agent/linuxinventory: чистые парсеры (на содержимом, без чтения ФС) — Hardware (cpuinfo/meminfo), Packages (dpkg status, только установленные), Accounts (passwd/group, без shadow и без поля пароля), Mounts (mountinfo без служебных ФС), Sockets (/proc/net tcp/udp, IPv4/IPv6, без PID), Routes (/proc/net/route). Тесты на фикстурах, включая отсутствие утечки поля пароля и мусорный ввод: go test/vet локально — ok (Linux, 6 тестов). НЕ сделано: чтение реальных /proc на живом хосте, rpm/apk, службы systemd, DMI, защита, соседи; НЕ подключено к Collect/протоколу. Блокер подключения: контракт профиля 1.2 Windows-only (InventoryPlatform12; recordKey12 требует registry_key для software и sid для users_groups; Linux-ключи — name+arch, uid/gid) — нужно решение о схеме (Linux platform в 1.2 либо отдельная версия), затрагивает подписи, центр и миграции. C16.02 остаётся planned/in_progress, не done; 57/200.

R-025, решение пользователя «1»: Linux — внутри профиля 1.2. Зафиксирован проект decisions/C16-linux-profile12.md: факты (константы policy/platform, центр не знает платформу источника, Windows-ключи записей), 6 этапов (enum политик/платформ; платформа из регистрации источника + миграция 0035+; Linux-схемы записей и recordKey12; capabilities; агент; проверка), риски. Открытый вопрос этапа 2 — источник платформы (рекомендовано: регистрация источника, сверка с запросом). Код контракта не менялся, тесты не запускались; этапы 1–6 не начаты. C16.02/03 остаются незавершёнными, 57/200.

R-025, C16 этап 1 (решение пользователя: платформа из регистрации источника, этап 2 — следом). Схемы профиля 1.2 (profile.schema.json и records.openapi.json, обе копии docs/v2): policy_id и platform из const в enum {windows-amd64-partial-baseline-v1 | linux-amd64-partial-baseline-v1} / {windows/amd64 | linux/amd64} (по 4 места в каждом файле). Go: константы InventoryPolicyLinux12/InventoryPlatformLinux12, InventoryPolicyFor12(platform); inventoryConfig12 требует соответствия пары policy↔platform (схема допускает пары по отдельности). Тест TestInventoryConfig12PlatformPolicyPairing: Windows-пара и Linux-пара принимаются, смешанная и неизвестная платформа отвергаются. Локально: go build/vet (+GOOS=windows), go test ./... (без PG-интеграции), validate.py 24/24 — ok. НЕ сделано: CHECK(policy_id='windows-…') в SQL 0034 всё ещё отвергает Linux-политику (нужна миграция 0035 — этап 2), центр по-прежнему строит только Windows-конфиг, Linux-схемы записей/ключи, capabilities, агент. Центр/PG-интеграция и CI на этом SHA ещё не запускались. 57/200.

R-025, C16 этап 1 итог. 6d59c6b: c15 42606711115, boot 42606710937, web 42606711047, v2 42606710889 — все success. Этап 1 принят как код/CI; этап 2 (платформа из регистрации источника + миграция 0035) не начат. 57/200.

R-025, C16 этап 2 (платформа из регистрации источника — выбор пользователя). Миграция sources/0035_inventory_platform (append-only, 0000–0034 не менялись): sources.agents.inventory_platform (DEFAULT 'windows/amd64', CHECK windows|linux) и ослабленный CHECK policy_id в inventory_profile_progress12 (обе политики). Заявка на grant получила необязательное поле inventory_platform (EnrollmentGrantRequest; wire.schema.json и openapi.json — обе копии v2/docs; поле опционально, прежние клиенты и Windows-поведение не меняются; только для source_kind=agent, неизвестная платформа → Invalid). PollInventoryProfile12 берёт платформу из sources.agents и отвергает запрос с другой платформой (Invalid); конфиг строится wire.InventoryConfigForPlatform12 (старый InventoryConfigFromCommon12 = Windows); InventoryProfile12View тоже. Ожидания счётчиков миграций 35→36 (guest.py, upgrade_smoke 4→5 добавленных, auth_smoke, machine_smoke), тест миграции сдвинут на 0035. Новый интеграционный тест TestC15ProfilePlatformComesFromRegistration (Linux grant→Linux-политика, несовпадение платформы отвергается, по умолчанию Windows, неизвестная платформа отвергается). Локально на реальном PG16: go test -tags=integration ./... — все пакеты ok (internal/app 71s). CI на этом SHA — следующей записью. НЕ сделано: Linux-схемы записей/recordKey12 (этап 3), capabilities (4), агент (5), реальные хосты. Агент по-прежнему шлёт platform=windows/amd64 в запросе профиля. 57/200.

R-025, C16 этап 2 итог CI и этап 3. CI 7436e7f: boot success, web success (после перегенерации v2/web/src/generated/c03.ts для нового поля inventory_platform — первая попытка db5a8f3 падала на `git diff --exit-code src/generated`), v2 failure: шаг "Previous C11 server data upgraded with current binary" (upgrade_smoke): сравнение хэшей полных строк старых таблиц до/после миграции видит новую колонку sources.agents.inventory_platform. Исправлено: хэш считается без этой колонки ((to_jsonb(t)-'inventory_platform')); данные прежних колонок по-прежнему сверяются. Локально это не воспроизводится (нужен docker и предыдущий ref), результат — только в CI следующего коммита.
Этап 3 (Linux-строки): схема наблюдения c15.schema.json (+docs observation.schema.json): softwareRow/users_groupsRow/routes_portsRow = anyOf[Windows, Linux]; Linux: software source dpkg|rpm|apk без registry_*; users_groups kind user|group|membership с uid/gid/group/shell без sid; routes_ports interface вместо interface_index; resources kind mount + read_only. Схема чтения (c15-records.schema.json, c15.openapi.json + docs копии): новые поля uid/gid/group/shell/interface/read_only, source +dpkg/rpm/apk, resources.kind +mount; architecture программного обеспечения теперь шаблон ^[A-Za-z0-9_.+-]{1,64}$ вместо enum (Windows-значения — подмножество, строгость для Windows чуть ниже — сознательно). recordKey12: Linux-ключи по форме строки (software: source+scope+name+architecture; users: user→uid, group→gid, membership→gid+name; routes: +interface; ключи Windows не изменены, тесты на старых фикстурах проходят). Парсеры linuxinventory подогнаны (device_id, shell без пустых) и проверены настоящей схемой наблюдения. Тесты: records12 Linux ключи/схема/смешанная строка, wire Linux-факты (допустимые и недопустимые значения). Локально: go vet, go test -tags=integration ./... на PG16 — все ok; validate.py 24/24. НЕ сделано: этап 4 (capabilities), этап 5 (агент: Collect читает /proc, запрос с runtime.GOOS), реальные хосты. 57/200.

R-025, C16 этап 3, CI fff1855: c15, web, boot — success; v2 — failure на шаге "Verified release update…" (update_smoke): приватная тестовая миграция-фикстура называлась 0035_c13_update_acceptance и ждала итог 36 — после настоящей 0035_inventory_platform она сдвинута на 0036_c13_update_acceptance, ожидание 37, тексты проверок schema36→37 (по правилу AGENTS «сдвигать private update fixture»). Шаг upgrade_smoke после правки хэша без inventory_platform прошёл в этом же прогоне. Остальные шаги v2 после update_smoke в том прогоне не выполнялись — результат только в CI следующего коммита. Локально update_smoke не воспроизводится (docker/подписанные релизы).

R-025, C16 этапы 2–3 итог CI. 31d3e05: surveyscan-v2 42617851027 — success (все шаги, включая upgrade_smoke и update_smoke после исправлений). Для этапа 3 (fff1855) c15/web/boot были success. Этапы 1–3 приняты как код/CI; Linux-агент по-прежнему не подключён. Следующее: этап 4 (capabilities), этап 5 (Collect и запрос профиля на Linux). 57/200.

R-025, C16 этап 4 и этап 5 (агент). Этап 4: схема capabilities (c15-capabilities) согласует только лимиты (байты/записи), платформы и секций в ней нет — изменений не потребовалось. Этап 5: internal/agent/linux_collect12.go — CollectLinux12 (identity/os/network прежними источниками + hardware, software(dpkg), users_groups, routes_ports, resources через linuxinventory; чтение /proc и /etc без внешних команд, ограниченные размеры; все секции partial, updates/services/protection/neighbors — явно unsupported/SECTION_UNSUPPORTED, нет dpkg → PACKAGE_MANAGER_UNSUPPORTED); RunLinux12 (цикл runLoop12 на Linux, этапные коды как у Windows; StageError вынесен в stage.go) и команда агента run12 (явное включение; прежний Run/профиль 1.0 не менялся); платформа в запросе профиля — platform12() по runtime.GOOS/GOARCH (linux/amd64, windows/amd64, иначе пусто → запрос отвергается схемой); namespace machine_uuid по платформе. ЖИВАЯ проверка на этом хосте (Ubuntu 24.04, не фикстура): тест CollectLinux12 — 12 секций, 7 partial, 4 unsupported, строки проходят настоящую схему наблюдения; тест проекции — 8 секций, 1023 записи проходят preparePartial12. Живой тест нашёл реальную ошибку: stacked mounts дают дубль ключа (kind,name) и отвергли бы секцию целиком — парсер Mounts оставляет верхнее монтирование. Также выяснено: валидатор требует collected_at секции ≤ collected_at наблюдения. Локально: go vet (+GOOS=windows, darwin build), go test -tags=integration ./... на PG16 — всё ok. НЕ проверено: сквозной прогон скомпилированного Linux-агента с центром (enroll linux/amd64 → профиль → batch → чтение фактов) — следующий шаг; rpm/apk, systemd-службы, DMI, защита, соседи; Linux на других дистрибутивах/архитектурах; права non-root vs root (тест шёл от root). 57/200.

R-025, C16 этап 5, CI 482a357: c15, boot — success; v2 — failure на первом шаге (make verify): ЖИВЫЕ тесты на CI-хосте (другие данные, чем на моей машине) упали — TestCollectLinux12LiveHostPassesObservationSchema и TestRecord12LiveLinuxSnapshotProjects: схема наблюдения отвергла живой снимок раннера. Причина (по коду валидатора inventory12Addresses, которое не ослабляется): сокеты /proc/net/tcp6 с IPv4-mapped адресами (::ffff:a.b.c.d, обычны у двухстековых слушателей) в строках family=ipv6. Парсер Sockets теперь разворачивает такие сокеты в family=ipv4 (адреса распакованы, "::"→0.0.0.0), смешанные пары IPv4/IPv6 пропускает; чистый ipv6 не изменён; тест TestSocketsIPv4MappedBecomeIPv4. Причина выявлена по коду и подтверждена юнит-тестом; сам CI-снимок раннера не воспроизводился локально — окончательное подтверждение даст CI. Добавлено: команда агента collect12 (разовый локальный сбор секций 1.2 в JSON, без сети, Linux) и Linux-режим сквозных smoke (C15_SMOKE_PLATFORM=linux/amd64 для c15_center_smoke.py и c15_relay_smoke.py: grant с inventory_platform, секции из скомпилированного агента collect12, политика linux-amd64-partial-baseline-v1, 8 секций с фактами из 12, чтение фактов software; новые шаги v2.yml и отчёты c15-*-smoke-linux.json). Эти Linux-smoke локально не запускались (нужен docker-стенд) — результат только в CI.

R-025, C16 этап 5 итог CI. 4cfc949: v2 42621493864, c15 42621493794, boot 42621495170 — success. В v2 выполнены (не пропущены) шаги: make verify (в т.ч. живые Linux-тесты на раннере после исправления IPv4-mapped), "Linux agent inventory1.2 live host snapshot through center (platform bound at registration)" и "Linux agent inventory1.2 collector relay, offline spool and cold restart". Факт: платформа linux/amd64 из регистрации источника → Linux-политика профиля 1.2 → реальный снимок скомпилированного агента (collect12) → подпись/mTLS/Transit/PG-проекция → типизированное API → replay/офлайн-спул/холодный рестарт — на CI-хосте (ubuntu, root). Ограничения: в smoke подпись и транспорт ведёт Python-имитация агента с реальным TLS-согласованием скомпилированного клиента; цикл RunLinux12 целиком (демон) этими шагами не запускался; non-root, другие дистрибутивы/архитектуры, rpm/apk, systemd, DMI, protection, neighbors — не проверены. Этапы 1–5 плана «Linux внутри 1.2» закрыты как код/CI; C16.02 частично (секции реализованы не все), C16.03 (демон/служба/переносимость) и C16.04 не начаты. 57/200.

R-025, C16.03 (часть). 2869f44: v2 42661647508, c15 42661647099, boot 42661647171 — success; шаг "Linux agent run12 stage exit code (not enrolled = 2) and non-root collection" выполнен на CI-хосте: незарегистрированный run12 завершается кодом 2 (этап Open), сбор collect12 от nobody даёт 7 partial + 4 unsupported, замена бинарника на другой путь на том же состоянии не меняет prepare-личность (source_id/csr_sha256 побайтно). Сделано: drop-in deploy/systemd/surveyscan-agent.service.d/run12.conf (ExecStart run12, RestartPreventExitStatus=2; systemd-analyze verify локально без замечаний), коды выхода по этапам для Linux CLI (agent.StageError → код процесса), раздел README systemd. НЕ проверено: запуск под systemd PID1, другие дистрибутивы/init, обновление зарегистрированной службы с непустой очередью для run12, DMI/PID/firewall (не собираются). C16.03 частично, C16.04 не начат, C16.01 draft, C16.02 частично. 57/200.

R-025, подготовка ручной проверки на ВМ пользователя (Windows Server 2019 по RDP, Linux-ВМ по SSH, GitHub доступен). f95afc8: c15 42680281198 success; шаг публикует артефакт surveyscan-agent-windows-amd64-test (exe + sha256 + BUILD.txt с SHA коммита; только результат сборки, без ключей/данных; хранение 14 дней). Server 2019 (сборка 1809) — первая проверка на версии, отличной от CI (Server 2022); FileRenameInformationEx требует Windows 10 1709+/Server 2019 — граница допустимая, но не проверена. V1–V9 по-прежнему не выполнены.

R-025, V1 выполнена пользователем вручную на ВМ стенда: Windows Server 2019 Standard build 17763, Windows PowerShell 5.1.17763.5830, администратор, скрипт windows-vm-check.ps1 из артефакта c15 f2d715d (прогон 42694435542), exe sha256 cdaafccb3cefde64dab290a3655f52aa89d16c834a5ef5812c4760beb8baf1d8. Факт по выводу пользователя (приведён им в чате): prepare OK и идемпотентен (source_id=91dc29ce-…); install-service: LocalSystem, AUTO_START (DELAYED); sc start → START_PENDING; sc queryex → STOPPED, WIN32_EXIT_CODE 1066, SERVICE_EXIT_CODE 2; uninstall-service rc=0, служба удалена; RESULT: PASS. Файл ошибок службы: "run: private regular file required" (этап Open, ожидаемо для незарегистрированного агента; текст не указывает, какой именно файл — код 2 это Open). Это первая проверка не на CI: Server 2019 (1809), граница FileRenameInformationEx пройдена, ACL SYSTEM+Administrators принят службой LocalSystem. Замечание: `--version` печатает stage "C12 Linux agent…", revision/source_dirty "unknown" — устаревшая метка сборки, на проверку не влияет (к исправлению). НЕ проверено: enroll/bind-host/run с центром, reboot, обновление зарегистрированной службы, Windows 10/11, обычные права, клоны; V2–V5, V7–V10 открыты. C15.02/03 остаются in_progress, 57/200.

R-025, стенд для V2. 9896c56: v2 42695849488 success — шаг "VM center stand selftest": scripts/vm_center.py --selftest поднимает центр+collector (collector слушает C15_COLLECTOR_BIND:C15_COLLECTOR_PORT, env добавлены в machine_smoke), по OUT/prepare.json выдаёт grant (inventory_platform), СКОМПИЛИРОВАННЫЙ Linux-агент делает prepare, enroll и держит демон run12, факты (≥8 секций) в PG, SIGTERM демона даёт чистую остановку, sources.agents.inventory_platform=linux/amd64. Это первое подтверждение демона RunLinux12 против настоящего центра (на CI-хосте, loopback, root). e904fcd: c15 42698060248 success — windows-vm-enroll.ps1 (prepare/enroll/status/remove) под PowerShell 5.1: prepare даёт prepare.json с source_id/csr_sha256/signing_public_key; шаги enroll/service против центра в CI НЕ запускались (центр на другом job). Runbook: handoffs/C15-vm-stand-runbook.md. Пользователь: Linux-ВМ Ubuntu 24.04 без docker (ставим), интернет есть, sudo есть, сеть между ВМ есть. Сквозной прогон V2 на ВМ — не выполнен.

R-025, первый запуск vm_center.py на Linux-ВМ пользователя (Ubuntu 24.04, root): Docker/compose, Go 1.27.3 (с github.com/actions/go-versions, т.к. go.dev резолвился только по IPv6), make build — прошли, ревизия 0d27397. Запуск упал: "OpenBao API did not become reachable" — скрипт не поднимал dev-стенд (в CI это отдельный шаг dev.py up). Исправлено: vm_center.py вызывает ensure_stack() (dev.py up при недоступном OpenBao). Побочные факты: репозиторий приватный (git clone просит логин/пароль), DNS на ВМ нестабилен. Результат нового запуска на ВМ — следующей записью.

R-025, V2 первый сквозной прогон на ВМ (Windows Server 2019 агент ↔ Ubuntu 24.04 центр, dev-стенд vm_center.py). Факт со слов пользователя и его выводов: центр READY (collector 10.170.108.2:18443), Test-NetConnection True, prepare → grant (платформа windows/amd64 из регистрации) → enroll: "agent_enrolled", служба SurveyscanAgentVm установлена и RUNNING (SERVICE_EXIT_CODE 0), heartbeat доходит до центра (sequences heartbeat=6; в БД heartbeat_state last_contact 22:02:43Z, sources.state=active, agents.inventory_platform=windows/amd64). НО данные инвентаризации не пошли: консольный запуск `run` печатает profile_unavailable_cached_or_local, inventory_profile_rejected (отказ по протоколу, не сеть, за ~25 мс), heartbeat_accepted, inventory_waiting_profile; в БД нет строки sources.inventory_profile_progress12 (центр не выдал профиль 1.2); observations=0. Тот же стенд с Linux-агентом (selftest в CI) проходит. Причина отказа пока неизвестна — агент по дизайну не печатает тексты ошибок. Добавлена явная диагностика: при SURVEYSCAN_AGENT_DEBUG=1 цикл печатает "detail:<где>: <текст ошибки>" (по умолчанию выключено, тексты ошибок наружу не идут). Это НЕ PASS: V2 не пройден; отказ профиля 1.2 на Windows-агенте — открытая проблема (D-кандидат).

R-025, V2 диагностика отказа. Причины по шагам (факты из выводов пользователя): (1) часы Windows опережали Linux на ~50 с (Source: Free-running System Clock, нет NTP) → центр отвергал запрос профиля 1.2 по окну свежести (±30 с) как 422 SCHEMA_INVALID (общий код; HTTP 422 увидели благодаря debug-режиму cad091c); после Set-Date по заголовку Date HTTP-сервера Linux профиль принят (inventory_profile_synced), сбор прошёл за ~2 с (inventory_queued). (2) Пакеты Windows дошли до центра (imports.deliveries completed_with_errors, claims completed), но центр отверг наблюдение: квитанция disposition=rejected, reason_code=SCHEMA_INVALID, spool_action=retain; observations=0. Следовательно, реальные данные Windows нарушают схему наблюдения (аналог Linux-находок IPv4-mapped/дубли — теперь на Windows). Добавлен scripts/validate_pending.py: проверка *.pending из spool collector схемой C15, печать путей ошибок. Требование стенда: синхронизация времени агента и центра (допуск 30 с вперёд / 2 мин назад) — без NTP профиль 1.2 не выдаётся. V2 НЕ пройден: данные не приняты центром.

R-025, V2 причина отказа найдена. Центр отвергал ВСЕ наблюдения Windows-агента с SCHEMA_INVALID из-за кандидата идентичности machine_uuid = "15b9bc6bf4234db283a367df09c5db84" (32 hex без дефисов, namespace windows-machine-guid): ассеты Normalize требует канонический UUID (identifier.Valid), иначе domain.Invalid → reason SCHEMA_INVALID на весь пакет (upload.go отображает любой Invalid в SCHEMA_INVALID). Линейные данные не затрагивались, потому что Linux-кандидат хранил дефисы. Путь поиска (факты из выводов пользователя): HTTP 422 профиля (часы +50 с, исправлено Set-Date) → deliveries completed_with_errors → квитанция disposition=rejected/SCHEMA_INVALID → схема данных без ошибок (validate_pending.py) → Go-проверки секций OK (diag_pending_test.go, 12 секций, ключи, адреса) → декодер центра nil, digest верен → подпись верна (verify_pending_signature.py) → шапка наблюдения: кандидат без дефисов. Исправление: agent.canonicalMachineUUID в candidatesFromSections + тест. Урок: центр отвергает пакет целиком из-за одного кандидата; один и тот же reason скрывает причину — полезно различать причины в диагностике (кандидат на следующий пакет работ). Результат повторной проверки на ВМ — следующей записью; V2 пока не пройден.

R-025, V2 ПРОЙДЕН частично (консольный run, не служба). acef4a0 (exe sha256 03481370…2514 — совпал на Linux и Windows): агент Windows Server 2019 (build 17763, PowerShell 5.1) → collector 10.170.108.2:18443 → центр на Ubuntu 24.04 (vm_center.py, dev-стенд, одноразовая dev-CA) → PostgreSQL. Факт (вывод STATUS из окна центра, приведён пользователем): observations=1, assets=1, facts_by_section: hardware=10 identity=4 neighbors=191 network=4 os=4 protection=24 resources=5 routes_ports=96 services=759 software=424 updates=15 (11 секций; users_groups — unsupported, 0 строк, по причине платформенного отказа сборщика, вероятно LOCAL_SAM_UNSUPPORTED_ON_DC — причина не подтверждена выводом). Путь к успеху = три найденных на ВМ дефекта/условия: (1) часы агента должны быть в окне ±30 с/−2 мин относительно центра (без NTP профиль 1.2 не выдаётся, 422); (2) machine_uuid кандидат без дефисов отвергал весь пакет (исправлено acef4a0); (3) нужна очистка очереди агента от старых отвергнутых пакетов. НЕ проверено: режим службы SCM с центром, reboot, обновление зарегистрированной службы, обычные права, Windows 10/11, клоны, повторные циклы/дедупликация, память/CPU, users_groups на не-контроллере домена. Счётчик 57/200 не менялся; C15.02 остаётся in_progress до приёмки по перечисленным пунктам.

R-025, V2 режим службы подтверждён на ВМ (факт со слов пользователя, выводы приведены им): служба SurveyscanAgentVm (LocalSystem, delayed-auto, PID 40624, один процесс агента, консольный run остановлен) доставляет данные в центр: inventory.observations count=8, source_sequence 9,10,11,12,13,14,15,16 подряд, assets=1 (повторные циклы не плодят дубликат), sequences.json на Windows inventory=16 совпал с центром; служба RUNNING. Время: на Linux-ВМ поднят chrony (allow 10.170.108.0/24, local stratum 10; предварительно убит зависший 72 дня apt-get update, держал блокировку), Windows w32time Source=10.170.108.2 — дрейф часов без NTP был причиной отказа профиля 1.2. Не проверено: reboot (V3), обновление зарегистрированной службы, обычные права, Windows 10/11, клоны, CPU/память, users_groups на не-DC. C15.02 остаётся in_progress; 57/200.

R-025, V3 (перезагрузка) выполнена пользователем на ВМ Windows Server 2019 (вывод приведён им): после Restart-Computer время синхронизировано с 10.170.108.2 (w32tm Source), служба SurveyscanAgentVm сама перешла в RUNNING (первая проверка показала STOPPED — отложенный автозапуск; следующая проверка: PID 1300, старт 22:42:11Z), sequences.json inventory=17→18, в центре source_sequence 9..18 подряд (17, 18 — после перезагрузки), assets=1, sources(agent)=1: личность сохранена, новый актив не создан. Не измерено: точная задержка старта (LastBootUpTime не прислан), жёсткое выключение (power-off без остановки службы), повторные перезагрузки, поведение при недоступном центре при загрузке. C15.02 остаётся in_progress; 57/200.

R-025, V3 уточнение (измерение): LastBootUpTime = 10.11.2026 1:38:46 (местное, UTC+3), процесс службы стартовал в 1:42:11 → задержка отложенного автозапуска после загрузки ≈ 3 мин 25 с на этой ВМ (Server 2019, build 17763). Единичное измерение, не статистика.

R-025, V9 (первая оценка, не полноценный замер) и V4 частично. Перезапуск службы (stop→start, бинарник тот же; Copy-Item сделал только копию .v1, это НЕ обновление): состояние сохранилось, source_sequence в центре 9..19 подряд, assets=1, sequences.json inventory=20 (20-й в доставке). Ресурсы родительского процесса службы (Server 2019, ВМ стенда, данные пользователя): CPU 0,53 с → 1 с накопленно за ~4–5 циклов, WS 24,3→24,5 МБ, PM 60,0→60,2 МБ, HandleCount 177 — рост памяти не наблюдается на этих точках. НЕ измерено: дочерние процессы inventory-worker (12 на цикл), пиковая память во время сбора, длительные периоды (часы), нагрузка при большой очереди. Настоящее обновление бинарника (V4) ещё не выполнено.

R-025, V4 выполнена пользователем на ВМ Windows Server 2019 (вывод приведён им). Обновление: служба SurveyscanAgentVm остановлена (STOP_PENDING→STOPPED), exe заменён собранным на Linux-ВМ с ldflags Version=0.0.1-upgrade-test (sha256 7CB003509D61F8FBCA836E7278878A504D990A834A615AA1799F602B62F4AA9C, совпал на обеих сторонах; прежний сохранён как .exe.prev), `--version`: 0.0.0-c13 → 0.0.1-upgrade-test; служба запущена (PID 4800, старт 1:46:43 местного), sequences.json inventory 21→22, в центре source_sequence 9..22 подряд (14 наблюдений), assets=1 → личность, нумерация и актив сохранены при обновлении. НЕ проверено: откат на предыдущий бинарник, обновление при непустой очереди/недоступном центре, обновление через установщик (установщика нет), обновление схемы состояния между версиями (в этом прогоне формат состояния не менялся). C15.02 остаётся in_progress; 57/200.

R-025, передача сессии: создан handoffs/C15-C16-session-handoff.md (проверено/найдено/открыто/стенд/следующие шаги), STATUS.md обновлён. Новый чат продолжает проверки (фоновый прогон, Linux-агент под systemd) и этапы плана по этому файлу и REQUESTS R-025.

R-025, база длительного прогона (soak-start 2026-11-09 22:51 UTC): Windows inventory=26, heartbeat=74, WS 24,27 МБ, PM 59,2 МБ, handles 161; центр observations=18 (9..26), assets=1; w32tm Source 10.170.108.2. Прогон — результат ожидания, не отдельная команда; итог снимается утром сравнением с этим снимком (в handoff). Не проверено: что стенд дожил до утра.

R-026 (Claude), 2026-11-10. Пользователь: «продолжай этапы». Выводы «soak-end» от пользователя НЕ получены — сравнение с базой soak-start не выполнено, результат не записан (не PASS и не FAIL). Центр на Linux-ВМ не перезапускать до получения снимка.
vm_center.py: теперь принимает заявки по трём файлам — prepare.json (платформа --platform), prepare-linux.json (linux/amd64 → grant-linux.json), prepare-windows.json (windows/amd64 → grant-windows.json); за один запуск центра можно зарегистрировать агентов обеих ОС. Selftest использует прежнюю пару prepare.json/grant.json. Проверка: py_compile локально; selftest — в CI v2 на точном SHA (результат ниже по факту). Пользователю выданы команды подготовки Linux-агента под systemd (сборка, пользователь, unit+run12, prepare под сервисным пользователем) — их вывод не получен. Напоминание: перезапуск центра пересоздаёт БД и CA, Windows-агент после этого регистрируется заново (новый CA в cfg).

R-026, CI d525ac5: все 5 workflow (v2 42727730610, boot, web, c15-contract-preparation, acceptance-evidence) завершились failure за ~2 с без единого шага — аннотация GitHub: задания не запущены из-за биллинга аккаунта (неуспешные платежи / лимит расходов). Это инфраструктурный отказ, код не проверялся: selftest vm_center для d525ac5 НЕ выполнен (ни PASS, ни FAIL по существу). Нужно действие пользователя в Billing & plans; затем перезапуск (re-run) без новых коммитов.

R-026, C16.02 (код, локально; CI недоступен — биллинг). linuxinventory: RPMPackages (rpm -qa --qf), APKPackages (/lib/apk/db/installed), SystemdServices (systemctl list-units + list-unit-files → state/start_mode/display_name), DMI (/sys/class/dmi/id → hardware kind=bios; serial/uuid только если читаются, заглушки вендоров отбрасываются). Подключено в CollectLinux12: пакеты dpkg → иначе rpm → иначе apk; services через systemctl (абс. путь, пустое окружение, таймаут 20 с, лимит вывода); ошибка источника → секция unavailable, не придумывается. Проверено: go test ./internal/agent/... и linuxinventory (в т.ч. строки проходят настоящую схему наблюдения), vet linux и GOOS=windows. НЕ проверено: реальный systemctl/rpm/apk (на этом хосте нет systemd и rpm — services дали unavailable, это штатный путь), DMI от root на ВМ, hosted CI. Сегодня на ВМ пользователя это даст первый факт по services/DMI после обновления бинарника (шаг 2).

R-026, C17.01/C17.03 (код, локально). Решение: decisions/C17-ssh-profile.md. Пакет internal/remote/sshlinux: строгий пин ключа хоста (без TOFU), FetchHostKey, пароль/ключ с редактированием секрета, сроки, лимит вывода, отмена с частичным результатом, повторы только при сетевых сбоях; сбор теми же парсерами linuxinventory. Проверено go test -race ./internal/remote/... (8 тестов на настоящем SSH-протоколе через in-process сервер: успех, пустой/неверный ключ, FetchHostKey без команд, неверный пароль без повтора, таймаут команды, отмена, лимит вывода, редактирование секрета) + vet. НЕ проверено: живой sshd/ВМ, Bao (C17.02), sudo, привязка к collector job и контракту передачи, CI (биллинг). C17.* остаются in_progress/planned; счётчик 57/200 не менялся.

R-026, C17 живой OpenSSH (локально, не ВМ пользователя). Добавлен cmd/ssh-probe (fingerprint / collect; секреты только из файлов, вывод — статусы и счётчики). В песочнице поднят настоящий OpenSSH sshd (127.0.0.1:2222, ключ, непривилегированный пользователь) — сбор прошёл: hardware 2, software 845 (dpkg), users_groups 152, resources 10, routes_ports 2 — partial/REMOTE_SSH_PARTIAL; services=unavailable (в песочнице нет systemd — ожидаемо). FetchHostKey совпал с ssh-keygen -lf. Негатив на живом sshd: неверный отпечаток → ErrHostKeyMismatch, пустой → ErrHostKeyRequired (до соединения), несуществующий пользователь → ErrAuth. Первая попытка дала ErrAuth из-за заблокированной УЗ тестового пользователя (проблема стенда, не кода; разблокирована). НЕ проверено: пароль на живом sshd, ключ с passphrase, sudo, Bao, services с systemd, ВМ пользователя, Debian/RHEL/Alpine, CI (биллинг).

R-026, C17.02 (код, локально). sshlinux.CollectWithCredentials + Binding: задание несёт только credential_ref и адрес; пользователь, отпечаток ключа хоста и алиасы секретов берёт Binding оператора. Неизвестная ссылка или адрес вне Hosts → отказ ДО чтения секрета; секрет читается через bao.Client.Read (алиас из конфига, не путь) непосредственно перед соединением, буферы обнуляются, текст ошибки хранилища наружу не идёт; ровно один способ (пароль/ключ[+passphrase]). Проверено go test -race ./internal/remote/... (11 тестов, настоящий SSH-протокол + фейковое хранилище): границы ссылки/адреса, нет чтения при отказе, нет утечки текста ошибки, нет соединения без секрета; *bao.Client удовлетворяет интерфейсу (compile-time). Первый -race прогон завис на холодной сборке зависимостей и был прерван, повтор прошёл за 1,7 с. НЕ проверено: живой OpenBao с KV-секретом SSH (политика read на алиас, revoke/rotation), хранение Bindings в реестре источников/UI, привязка к заданию collector, CI (биллинг).

R-026, C17.03 (шаг: полный набор 12 секций, локально). linuxinventory: Identity (hostname + machine-id → uuid), OS (os-release + uname -m → amd64/arm64/386, неизвестная архитектура не выдумывается), Network (ip -o link/addr: MAC, MTU, адреса без link-local, lo пропущен). sshlinux: секции identity/os/network добавлены в Collect; Complete12 даёт ровно 12 секций (updates/protection/neighbors — unsupported, прочее — unavailable); Candidates извлекает hostname и machine_uuid (namespace linux-machine-id, как у локального агента). Проверено: go test -race ./internal/remote/..., go test linuxinventory (на настоящем SSH-протоколе с фейковыми выводами команд; `ip` на живом sshd песочницы не гонялся). Тест отмены поправлен под новый порядок секций (первая — identity). Протокол доставки в центр НЕ реализован: профиль 1.2 принимает только origin.source_kind=agent (inventory_profile12.go:31, enrollment.go:354), агентлесс-источник требует решения по контракту (см. следующую запись).

R-026, C17.03/доставка (решение пользователя «1»: отдельный вид источника). По коду: профиль 1.2 привязан к личности agent (~10 мест), полноценный remote_ssh = миграция + enum + enrollment/relay/profile12/pki — не верифицируем без hosted CI/PG17/Bao. Реализован первый безопасный шаг без изменения контрактов: команда `surveyscan-agent run-ssh12 --config agent.json --ssh-target target.json` (internal/agent/ssh_collect12.go, run_ssh12.go): виртуальная агентская личность на цель, runLoop12 с подменённой функцией сбора (SSH → Complete12 → candidates). Проверено: go build ./... , GOOS=windows build, unit-тесты LoadSSHTarget (обязательный отпечаток, ровно один секрет, неизвестные поля, непрочные права) и fail-closed без утечки секрета. Заявки vm_center на grant для linux/amd64 уже поддержаны (prepare-linux.json). НЕ проверено: сквозной прогон run-ssh12 → collector → центр (нужен стенд: docker/PG17/Bao, т.е. ВМ пользователя или CI), центр не отличает SSH-цель от агента (нужна миграция acquisition). Локально подтверждено, что интеграционные тесты БД (-tags integration) идут на PG16 в песочнице — база для следующей миграции.

R-026, C19 (пакет internal/remote/snmpnet; по просьбе пользователя «до 24 этапа» работа идёт по пакетам последовательно, статусы пакетов НЕ меняются, 57/200 не меняется). C19.02/C19.03 код: профиль SNMPv3 только authPriv (SHA/SHA256/SHA512 + AES/AES256; v1/v2c/community/noAuth/DES/MD5 отвергаются), ключи по алиасам из хранилища (обнуляются, текст ошибки хранилища не наружу), только GETBULK (запись невозможна), ограничение частоты (MinInterval), повторы ≤3, лимит строк с признаком truncated, срок всего сбора, проверка учётных данных до сбора (неверный ключ → ErrAuth, а не «пустые таблицы»). Нормализация: system, интерфейсы (IF-MIB ifTable/ifXTable, скорость, MAC, адреса из ipAddrTable), ARP, FDB (dot1d + карта портов), LLDP-соседи (lldpRemTable), VLAN (Q-BRIDGE static); статус на каждую таблицу ok/empty/unavailable/truncated. Проверено: go test (фикстуры: нормализация всех таблиц, независимость таблиц при отказе VLAN, truncation, отказ слабых профилей) и ЖИВОЙ SNMPv3 против настоящего net-snmp snmpd в песочнице (127.0.0.1:1161, SHA/AES): system, 4 интерфейса, ARP=1, if/ip таблицы ok; fdb/lldp/vlan/bridge_ports = empty (у Linux-snmpd их нет); неверный auth-ключ → ErrAuth. НЕ проверено: реальные коммутаторы/маршрутизаторы (вендорные OID, права на таблицы, большие FDB, LLDP-MIB на живом железе), SNMPv3 engine-id discovery на нескольких вендорах, маршруты (routes) и VRF/LAG — в коде отсутствуют; привязка к заданию collector и контракту доставки netdev (формат/вид источника не определён — как у C17); C19.01 матрица vendor/OID — не оформлена. CI недоступен (биллинг).

R-026, C20/C21/C22 (код, локально; статусы пакетов не меняются).
C20 internal/discovery: Scope (Include/Exclude, MaxHosts; вне scope — отказ при пробе и отбрасывание при импорте, расширения нет), ProbeTCP (лимит параллелизма/частоты, «refused» тоже доказывает хост, ICMP НЕ реализован — нужны привилегии), ParseProcARP, ParseDHCPLeases, Merge (идентичность по MAC, иначе по IP; новые/повторные/повышение IP→MAC; IP_CONFLICT у обоих MAC, MULTIHOMED; вне scope считается dropped). Тесты -race проходят, TCP-проба проверена на локальном листенере. НЕ реализовано: DNS-импорт, AD/гипервизор API, ARP/NDP-пробы по сети, привязка к заданию collector и контракту.
C21 internal/presence: Tracker по проходам; пропуск засчитывается только полным успешным проходом источника, который видел объект, и только в рамках Covers; неполный проход состояние не меняет; события appeared/missing/returned, история сохраняется. Тесты -race проходят. НЕ связано с heartbeat/freshness агента и бизнес-состоянием; хранения в БД и API нет.
C22 internal/topology: граф L2 (LLDP: confirmed при подтверждении с обеих сторон, probable с одной; FDB только на access-портах без LLDP-соседа и с ≤N MAC; self-MAC пропускается; остальное — Unattributed) и L3 (общая подсеть = weak); противоречия (несколько соседей на порту) помечены конфликтом, не стираются. Тесты -race проходят на синтетических Result. НЕ проверено на реальных коммутаторах (вендорные особенности LLDP/FDB, VLAN-aware FDB, LAG), маршруты/VRF не используются, отображения в UI нет.

R-026, C18 (код, локально). internal/remote/winrminv: Parse (JSON фиксированного read-only сценария → identity/os/network/hardware/software/services), Connect (masterzen/winrm: только HTTPS + CA + NTLM, пароль по алиасу), CollectWith/Complete12 (ровно 12 секций), сценарий Script (≤7800 символов в кодировке, read-only проверяется тестом). Тесты -race: нормализация и отбрасывание небезопасного, прохождение настоящей схемы наблюдения (секции не новее наблюдения), fail-closed без утечки, отказ при отсутствии HTTPS/CA/секрета. Агент: `run-winrm12 --config agent.json --winrm-target target.json` (виртуальная личность на Linux-хосте; общий runVirtual12 с SSH). Документ decisions/C18-winrm-profile.md. НЕ проверено: ЖИВОЙ WinRM (транспорт NTLM/HTTPS, сам сценарий PowerShell на Windows Server 2019/2022, права, вендорные особенности) — C18.04 не выполнена; users_groups/routes/resources/updates не собираются.

R-026, C23/C24 (локально). C23: internal/portable — ZIP-формат с Ed25519-подписью JCS-manifest (stdlib, без самодельных примитивов), импорт с лимитами/zip-бомбой/path traversal/дедупом/карантином (тесты -race: round-trip, повтор → дубликат, тот же ID другой digest → карантин, чужой ключ и подмена manifest → отказ, подмена наблюдения → карантин, враждебные имена, лимиты, нарушение схемы, отсутствие ключей/паролей в пакете; late-наблюдение принято). Решение decisions/C23-portable-format.md. НЕ сделано: workflow сбора, HTTPS/resume, mapping, шифрование, parity online/file. C24.01: handoffs/C24-matrix.md — честная матрица (LIVE/TEST/не проверено) и список релиз-блокеров E2; C24.02–C24.04 НЕ выполнены (нужны живые источники, soak и решения пользователя). STATUS.md обновлён кратко. Счётчик 57/200 и статусы пакетов C15–C24 не менялись.

R-026, soak центра НЕ состоялся (сообщение предыдущей сессии со слов пользователя, вывод 2026-11-10 09:31 UTC; я это не наблюдал, но причина подтверждена кодом: дефолт --timeout был 4*3600, по истечении харнесс удаляет БД ssv2machine_*). Факт со слов пользователя: ни одной ssv2machine_* нет, контейнеры surveyscan-v2-c04-* Up 12 h (healthy), процесс центра завершён (~01:55 UTC, ≈3 ч после soak-start). Данные центра за ночь потеряны, сравнение «нумерация source_sequence/assets=1» по центру невозможно (НЕ PASS и НЕ FAIL). V1–V4 в силе. Побочный факт, ещё НЕ измеренный: Windows-служба, вероятно, ~7,5 ч работала без центра (очередь spool, лимит 1 МиБ, память, RUNNING) — нужен Windows soak-end (sequences.json, WS/PM/HandleCount, w32tm, размер C:\surveyscan\vm\state\spool, STATE). Исправление: дефолт --timeout в vm_center.py теперь 7 суток, предупреждение и запуск в tmux добавлены в handoffs/C15-vm-stand-runbook.md. После перезапуска центра агентов регистрировать заново.

R-026, Windows soak-end (данные пользователя, 2026-11-10 09:30:19 UTC, переданы через сообщение предыдущей сессии; я не наблюдал, значения не перепроверял). Факты из вывода: sequences.json inventory=221, heartbeat=428 (soak-start 22:51 UTC: 26/74); служба SurveyscanAgentVm RUNNING, PID 4800 тот же, старт 1:46:43 местного (≈10 ч 43 мин без вмешательства); WS 67 497 984 (было 24 272 896), PM 62 009 344 (59 199 488), HandleCount 184 (161); w32tm Source 10.170.108.2, Last Successful Sync 12:22:33 местного (09:22 UTC) — синхронизация держалась.
РАСЧЁТ (не наблюдение, со слов предыдущей сессии): heartbeat +354 ≈ 3 ч по 30 с и inventory +195 ≈ 180 за 3 ч + ≈15 до лимита очереди 1 МиБ — согласуется с остановкой центра ≈01:55 UTC (дефолт --timeout 4 ч); т.е. счётчики росли только пока центр жил, агент без центра не копил бесконечно. Точное время остановки центра не измерено.
ОТКРЫТО: рост WS 24→67 МБ при почти стабильном PM и handles 161→184 — утечка или кэш страниц НЕ установлены (нужен повторный замер при живом центре через несколько часов); размер spool (C:\surveyscan\vm\state\spool) пользователь пришлёт отдельно. Это не планировавшийся сценарий «недоступный центр»; как приёмочный V-пункт не засчитывается.

R-026, дополнение к Windows soak-end (данные пользователя ~2026-11-10 09:35 UTC через сообщение предыдущей сессии; не перепроверено): C:\surveyscan\vm\state\spool — Count=22 файла, Sum=883 182 байта (≈0,84 МиБ) при spool_limit_bytes=1 048 576; один файл — блокировка нулевой длины, т.е. ≈21 неотправленный пакет по ≈42 КБ. РАСЧЁТ: очередь ограничена и не растёт бесконечно при недоступном центре; почему остановка не ровно на лимите (резерв/размер следующего пакета) по коду не установлено. Закрывает пункт «размер spool» из предыдущей записи; вопрос роста WS остаётся открытым.

R-026, уточнение причины остановки центра (данные пользователя ~2026-11-10 09:45 UTC: last -x / ls / ps, через сообщение предыдущей сессии; не перепроверено). Причина — штатный таймаут vm_center.py (--timeout 14400), а НЕ обрыв SSH: mtime ~/surveyscan/v2/.local = 01:54:30 UTC (чистая очистка харнесса), старт центра ≈21:54:30 + 4 ч совпадает; SSH-сеансы жили до 06:50–06:54 UTC (выключение компьютера пользователя) — позже остановки; порт 18443 не слушается, процессов .dist/surveyscan-server/collector нет, следов аварийного завершения нет. Версия «закрытие окна SSH» для этого случая отвергнута. Предупреждение в runbook о закрытии окна остаётся как общий риск (в этом случае не проявилось), дефолт --timeout уже 7 суток (f6681d4).

R-026, прямой вывод пользователя в этой сессии (2026-11-10 09:34 UTC): Windows soak-end — sequences.json inventory=221 heartbeat=428, PID 4800 (StartTime 1:46:43 местного), WS 67497984, PM 62009344, HandleCount 184, w32tm Source 10.170.108.2 / Last Successful Sync 12:22:33 местного, STATE 4 RUNNING — совпадает с ранее записанными данными. Linux: DB= (пустая) — ни одной ssv2machine_* нет, pgrep vm_center.py пуст → центр не работает, данные центра потеряны (ошибка psql `database "-At"` — следствие пустой переменной DB, не сбой проверки). Сравнение с базой по центру невозможно; пункт soak по центру — не выполнен.

R-026, шаг 2 на Linux-ВМ пользователя (прямой вывод, 2026-11-10): git pull до 21e6ebb (потребовал логин GitHub — репозиторий приватный), сборка go1.27.3 `surveyscan-agent` и `ssh-probe` успешна (версия агента печатает 0.0.0-c13, revision/source_dirty unknown — сборка без -ldflags), пользователь surveyscan-agent, установка в /opt/surveyscan/releases/c16-a, symlink current, unit + drop-in run12 скопированы, `systemd-analyze verify surveyscan-agent.service` на реальном хосте rc=0. Запуск службы и enroll ещё не выполнялись (шаг 3).

R-026, ДЕФЕКТ найден на реальной ВМ (Ubuntu 24.04, systemd 255.4): prepare под сервисным пользователем через LoadCredential упал с «private regular file required» (prepare-rc=1). Диагностика пользователя: файл в $CREDENTIALS_DIRECTORY — `-r--r-----+ root:root 0440` с ACL для сервисного пользователя, каталог `dr-xr-x---+`; privatefile.Read требовал права ≤0600. (Ранее CI на Debian 12/systemd 252 это не ловил.) Исправление: privatefile.Read на Unix принимает файл ТОЛЬКО прямо в $CREDENTIALS_DIRECTORY при владельце root:root, правах не шире 0440 и каталоге без доступа «остальным»; вне этого каталога строгость прежняя (0600). Тесты: строгий режим по умолчанию (0640/0440/0644/0604 отвергаются), credentials-каталог (0440 принят; 0444/0640 отвергнуты; вне каталога отвергнут; каталог 0755 отвергнут), GOOS=windows vet. Проверено локально от root в песочнице; на ВМ пользователя исправление ещё НЕ проверено (нужны git pull, пересборка, установка, повтор prepare).

R-026, проверка исправления privatefile на ВМ пользователя (Ubuntu 24.04, systemd 255; прямой вывод): после git pull до 0d26ba7 и пересборки `prepare` под сервисным пользователем через LoadCredential: prepare-rc=0, PRIVATE KEY в prepare-linux.json = 0. Дефект закрыт на реальной системе. Далее enroll и запуск службы (шаг 3c) — ещё не выполнены.

R-026, ДЕФЕКТ стенда найден на ВМ: vm_center.py аварийно завершился (ValueError «prepare.json: не удалось разобрать JSON») — оболочка создаёт `> prepare-linux.json` до записи содержимого, а центр опрашивает файл и читал пустой (в этом случае от первой неудачной попытки prepare-rc=1 из-за дефекта privatefile). Прямой вывод пользователя: traceback в tmux, в каталоге vm-center остался prepare-linux.json 09:46 без grant-linux.json. Исправление: пустой/недописанный/неполный prepare не роняет центр, печатается `WAIT …` и проверка повторяется. Проверено py_compile; на ВМ — ещё нет. Центр после падения не работает (БД удалена харнессом) — нужен перезапуск, агент использует прежнее состояние (prepare идемпотентен), CA новый.

R-026, ПЕРВЫЙ ЖИВОЙ ПРОГОН Linux-агента run12 как systemd-службы (прямой вывод пользователя, Ubuntu 24.04, systemd 255.4, 2026-11-10 ~09:55 UTC; центр vm_center.py в tmux на той же ВМ, collector 10.170.108.2:18443). Путь: prepare под сервисным пользователем через LoadCredential (после исправления privatefile 0d26ba7) → grant → enroll (`agent_enrolled`, rc=0; первая попытка rc=1 «collector unavailable or identity rejected» из-за конфига от прежнего центра: после перезапуска центра tenant/collector_source_id новые — конфиг надо перегенерировать, не только CA) → `systemctl enable --now surveyscan-agent`. Факты: до enroll служба завершалась кодом 2/INVALIDARGUMENT (не зарегистрирован; RestartPreventExitStatus=2 сработал — не зацикливается); после enroll `active (running)` с 09:53:05, drop-in run12.conf применён, память 14,0 МБ (пик 21,4 МБ); в журнале циклически inventory_profile_synced, heartbeat_accepted (каждые 30 с), inventory_queued (≈60 с), delivery_pending; в окне центра observations 0→1→2, assets=1, факты по секциям: hardware=11 identity=2 network=21 os=3 resources=130 routes_ports=229→250 services=833 software=3510 users_groups=403 (это число ФАКТОВ в центре, не число строк; секции updates/protection/neighbors не собираются). Вывод: Linux run12 как реальная systemd-служба проходит сквозной путь агент→collector→центр на реальной ВМ — закрывает «реальный systemd вместо systemd-analyze» из хвостов C16.03 (частично). НЕ проверено: перезагрузка ВМ (центр на той же ВМ — перезагрузка уничтожит центр; проверять отдельно), обновление бинарника с сохранением личности/очереди, длительная работа, разбор появившихся `delivery_pending` (центр данные принял, смысл события при этом не расследован), Debian/RHEL/Alpine.

R-026, обновление бинарника Linux-агента под systemd НА ВМ ПОЛЬЗОВАТЕЛЯ (прямой вывод, 2026-11-10 ~09:57 UTC): подмена бинарника через symlink /opt/surveyscan/current (0.0.0-c13 → 0.0.1-c16-upgrade, версия в выводе обрезана head -c 200 на «0.0.1-c16-upg») и `systemctl restart`, после 120 с: служба active; sha256 identity.json ДО = ПОСЛЕ (962848d1…28b4) — личность сохранена; sequences.json 3/6 → 5/10 (inventory/heartbeat продолжают счёт без сброса); в центре observations=5, assets=1 (количество наблюдений совпадает с номером последовательности inventory=5); в журнале после рестарта inventory_profile_synced/heartbeat_accepted/inventory_queued. Закрывает «обновление бинарника с сохранением личности» для Linux на реальной ВМ при ЖИВОМ центре. НЕ проверено: обновление при непустой очереди (центр был доступен), откат на предыдущий релиз, update.fence/штатный updater (подмена вручную), reboot ВМ, обновление при смене формата состояния.

R-026, C17 ЖИВОЙ SSH-сбор на ВМ пользователя (прямой вывод, Ubuntu 24.04 с systemd, цель 127.0.0.1:22, непривилегированный пользователь scanprobe, ключ ed25519, бинарник ssh-probe из 21e6ebb). collect: identity 1, os 1, network 7, hardware 3, software 702, services 231 (systemd — первый ЖИВОЙ факт по services), users_groups 109, resources 16, routes_ports 4 — все partial/REMOTE_SSH_PARTIAL, rc=0. Негатив на живом sshd: неверный отпечаток → «host key does not match», пустой → «fingerprint is required», несуществующий пользователь → «authentication failed» (rc=1). Замечание: отпечаток из FetchHostKey (SHA256:25Kw…) отличается от ed25519-ключа сервера (SHA256:Gl2c…) — sshd согласовал другой тип ключа (вероятно ECDSA/RSA); отпечаток пинится для согласованного типа, при смене порядка/типа алгоритмов сервера сбор закроется отказом (fail-closed), а не молча примет.
НАЙДЕНО по результату (код, исправлено; на ВМ ещё не пересобрано): (1) routes_ports собирал только маршруты (4 строки), без сокетов TCP/UDP — у локального агента их сотни фактов; добавлены /proc/net/tcp,tcp6,udp,udp6, источники независимы (тест). (2) ДЕФЕКТ зависания: повторные прогоны -race (count=8) ловили зависание TestCancelStopsCollection — ssh.Client.NewSession ждал подтверждения канала бесконечно, когда отмена/таймаут совпали с закрытием соединения; сбор мог игнорировать собственные сроки. Исправление: открытие сессии ограничено CommandTimeout и контекстом, при истечении соединение закрывается. После: go test -race -count=40 ./internal/remote/sshlinux — ok (30,8 с), go build ./... ok.

R-026, подготовка сквозного прогона SSH-цели (код стенда, локально): vm_center.py принимает любое число заявок prepare-linux*.json (linux/amd64) и prepare-windows*.json, prepare.json — платформа --platform; grant лежит рядом (grant-… с заменой prepare→grant); отказ в grant больше не роняет центр (печатается GRANT REFUSED). Старые prepare*/grant* удаляются при старте. Новый scripts/vm-linux-identity.sh (bash -n ok; НЕ запускался в песочнице — нужны systemd-run/центр): `agent` (локальная run12) и `ssh NAME ADDR USER KEYFILE` (личность run-ssh12 с собственным юнитом, состоянием /var/lib/NAME, CA/конфигом/target.json в /etc/NAME, ключ цели через LoadCredential, пин ключа хоста через ssh-probe fingerprint), prepare → ожидание grant → enroll → enable --now. Причина: слот prepare-linux.json одноразовый и занят первым агентом, поэтому для второй личности нужен перезапуск центра (все агенты регистрируются заново).

R-026, СКВОЗНОЙ ПРОГОН SSH-ЦЕЛИ В ЦЕНТР НА ВМ ПОЛЬЗОВАТЕЛЯ (прямой вывод, 2026-11-10 ~10:17 UTC, Ubuntu 24.04, центр vm_center.py в tmux на 10.170.108.2:18443, новый центр после перезапуска; код 21b734c). Зарегистрированы две личности в одном центре: локальный агент run12 (surveyscan-agent) и SSH-цель (surveyscan-ssh1, `run-ssh12` → 127.0.0.1:22, пользователь scanprobe, ключ ed25519, пин ключа хоста SHA256:25Kw…, ключ цели через LoadCredential, личность зарегистрирована скриптом vm-linux-identity.sh). Обе службы active, в журнале inventory_profile_synced / heartbeat_accepted / inventory_queued. Центр (БД ssv2machine_a3b1…): наблюдения по источникам 93f3ad4e…=2 (max sequence 2) и c935c7a6…=4 (max 4), В ЦЕНТРЕ assets=1; в sources.agents три записи linux/amd64 (третья ac002c4e… — осиротевшая запись от неудачной регистрации с прежней личностью, наблюдений нет). Факты по секциям: services=845, software=3510, routes_ports=297, resources=140, users_groups=411.
ВЫВОД (факт): агент и SSH-сбор одной ВМ (одинаковые machine-id/hostname) сведены центром в ОДИН актив (assets=1) без дублей — положительный случай C24.02 «один актив разными источниками». Какой из двух источников агентский, а какой SSH, в центре не различимо (вид источника на проводе agent, поле acquisition не реализовано — известный пробел); различены только по source_id.
НЕ проверено: смена IP/hostname, клон ВМ, коллизия источников (C24.02), история/ответственные при слиянии, SSH-цель на другой машине, удаление/возврат (presence).
ДЕФЕКТЫ СТЕНДА, найденные по пути и исправленные (код, не проверено на ВМ): (1) центр запоминал обработанные prepare-файлы по имени — повторная регистрация другого агента под тем же именем не получала grant: теперь по имени+source_id; (2) enroll отказывает при личности от прежнего центра («existing identity cannot be replaced») — скрипт теперь явно требует RESET=1 для удаления состояния стенда; (3) при запуске новой копии центра при работающей старой collector не стартует на занятом порту (ошибка оператора, не кода) — в инструкции остановка старого центра отдельным шагом.

R-026, Windows-агент заново зарегистрирован в новом центре и работает (прямой вывод пользователя, 2026-11-10 ~10:25 UTC): служба снята и состояние C:\surveyscan\vm удалено (личность прежнего центра заменить нельзя), prepare → файл `prepare-windows.json` на Linux (передан копированием содержимого, публичные данные) → grant (платформа windows/amd64) → enroll (`agent_enrolled`, `service_installed`, STATE RUNNING, PID 4068; тот же exe, что в V1–V4). Центр после ~2 минут: assets=2; наблюдения по источникам: Linux-агент 93f3…=8 (max 8), SSH-цель c935…=10 (max 10), Windows 90abb706…=3 (max 3), осиротевшая запись ac002c4e… без наблюдений. Факты Windows поднялись в сводке: neighbors=127, protection=24, updates=15 (этих секций нет у Linux), services=1604, software=3902.
ВЫВОД (факт): Linux-агент и SSH-цель одной ВМ → один актив, Windows-ВМ → отдельный актив; ложной склейки разных машин нет. Центр обслуживает три источника двух платформ одновременно; Windows-агент с прежним exe корректно регистрируется в перезапущенном центре. НЕ проверено: смена hostname/IP, клон, длительная работа с живым центром (soak теперь возможен: центр в tmux с 7-суточным таймаутом).

R-026, БАЗА ВТОРОГО soak (soak-start, прямой вывод пользователя, 2026-11-10 10:24:27 UTC Windows / 10:24:40 UTC Linux). Центр vm_center.py (PID 1881859) в tmux с 7-суточным таймаутом, БД ssv2machine_a3b1…, три источника, assets=2.
Windows (SurveyscanAgentVm, PID 4068, старт 13:20:51 местного = 10:20:51 UTC, exe прежний 0.0.1-upgrade-test): sequences.json inventory=4 heartbeat=7; WS 24 834 048, PM 60 084 224, HandleCount 161; w32tm Source 10.170.108.2, Last Successful Sync 13:13:45 местного; spool Count=5 Sum=3 796 байт; STATE RUNNING.
Linux: наблюдения по источникам 90abb706…(Windows)=4 (max 4), 93f3ad4e…(Linux-агент)=10 (max 10), c935c7a6…(SSH-цель)=11 (max 11); assets=2; surveyscan-agent MemoryCurrent=14 426 112, NRestarts=0; surveyscan-ssh1 MemoryCurrent=16 019 456, NRestarts=0.
Сравнить при soak-end (≥6–10 ч, центр не перезапускать, ВМ не перезагружать): нумерация без пропусков (число наблюдений = max sequence у каждого источника), assets=2, рост WS/PM/HandleCount Windows (открытый вопрос: 24→67 МБ WS в первом прогоне при мёртвом центре — теперь при живом), MemoryCurrent и NRestarts Linux-служб, w32tm, размер spool, центр жив. Расчётные ожидания: Windows inventory ≈ +60/ч, heartbeat ≈ +120/ч.

R-026, acquisition (код). Миграция 0036_acquisition (sources.agents.acquisition: 'agent'|'ssh'|'winrm', по умолчанию 'agent'; 0000–0035 не менялись; каталог теперь 37 миграций). Поле acquisition в EnrollmentGrantRequest (только source_kind=agent, неизвестное значение и не-агент отвергаются), сохраняется при grant, возвращается в Source (View/List; у collector/portable отсутствует). Схемы wire.schema.json и openapi.json (v2/contracts и docs C03, 4 файла) и web/src/generated/c03.ts обновлены (c03.ts — ВРУЧНУЮ в стиле генератора: node_modules нет, `npm run generate` не запускался). Счётчики миграций 36→37 в bootstand/guest.py, auth_smoke, machine_smoke, upgrade_smoke (+ «добавляет ровно 6», отпечаток таблиц без колонки acquisition). Тест миграции 0035 учитывает две добавленные миграции. vm_center.py передаёт acquisition по имени prepare-файла (…ssh… → ssh, …winrm… → winrm).
ПРОВЕРЕНО локально: go build ./..., go test ./... (27 пакетов ok), integration (`-tags integration`) internal/app на PostgreSQL 16 — ok (69 с), включая новые проверки в TestC07AgentCollectorCenterPGAndVerifiedReturn: по умолчанию agent; ssh сохраняется и виден в View; bogus отвергается; для collector acquisition отвергается и в View пуст; миграция: «не две добавленных» (n=2) и неизменность старого журнала. НЕ проверено: PostgreSQL 17 и hosted CI (биллинг), скрипты upgrade_smoke/auth_smoke/machine_smoke/bootstand (нужны docker/ВМ), web-проверки (npm), живой центр на ВМ (нужна пересборка .dist/surveyscan-server и collector и перезапуск центра), отображение в UI/CLI. Живой центр в soak не трогаю.

R-026, C18 ПЕРВЫЙ ЖИВОЙ ШАГ WinRM на ВМ пользователя (Windows Server 2019, контроллер домена awm.local, DomainRole=5, 10.170.108.1; прямой вывод). Подготовка цели: доменный пользователь AWM\scanwinrm (без админ-прав, только Remote Management Users), самоподписанный сертификат WIN-AREDINOV.awm.local, HTTPS-listener 5986 (отпечаток 7B895C24…), правило firewall только от 10.170.108.2. С Linux-ВМ: curl с --cacert даёт ssl_verify=0, http=405 — TLS и проверка сертификата цели работают. Личность surveyscan-winrm1 зарегистрирована (`agent_enrolled`, служба active, heartbeat_accepted).
ДЕФЕКТ найден живым прогоном (код, исправлено; на ВМ ещё не проверено): центр отвечает 422 SCHEMA_INVALID на запрос профиля (`inventory_profile_rejected`) — агент объявляет в запросе платформу по ОС ХОСТА (platform12() = linux/amd64), а личность зарегистрирована как windows/amd64; центр сверяет самозаявленную платформу с регистрацией (inventory_profile12.go: req.Platform != platform → Invalid). Для виртуальной личности (run-ssh12/run-winrm12 к цели другой ОС) платформа должна быть платформой ЦЕЛИ. Исправление: необязательное поле inventory_platform в конфиге агента (windows/amd64|linux/amd64, иное отвергается), запрос профиля берёт его, иначе платформу хоста; скрипт vm-linux-identity.sh winrm записывает windows/amd64. Тест: ReadConfig по умолчанию/явная/неподдерживаемая платформа; go build, GOOS=windows build.

R-026, C18.04 живая диагностика WinRM (прямые выводы пользователя, Windows Server 2019 DC awm.local, цель 10.170.108.1:5986, учётка AWM\scanwinrm без прав администратора). ФАКТЫ: (1) TLS по своему CA работает (curl ssl_verify=0). (2) Сервер предлагает только схемы Negotiate и Kerberos — `curl --ntlm` поэтому не годится для проверки (давал 401), наш клиент go-ntlmssp шлёт NTLM внутри Negotiate и проходит: winrm-probe — 401 → 401(challenge) → 500 SOAP на пустой запрос; 4776 Status=0x0 и 4624 type=3 NTLM с 10.170.108.2. (3) Первоначальный 401 агента — устаревший пароль в /etc/surveyscan-winrm1/pass (скрипт копирует пароль один раз; после сброса пароля копию не обновили). (4) Для подключения не-админа к WinRM в RootSDDL добавлен ACE группы Remote Management Users (S-1-5-32-580) — тестовая настройка цели. (5) Не-админ: `cmd whoami` и PowerShell 5.1 выполняются, но Get-CimInstance Win32_OperatingSystem → PermissionDenied (root\cimv2) — без прав на WMI секции ОС/сеть/службы/железо недоступны (ACCESS_DENIED), реестр Uninstall читается. (6) Полный сценарий сбора возвращал exit 0 и пустые stdout/stderr, хотя его части по отдельности работают (try/catch, ASCII-вывод, Safe с отказом WMI, ConvertTo-Json); проверка длины с наполнителем ПОСЛЕ команды не опровергает обрезание командной строки — гипотеза открыта.
КОД (по ходу, локально проверен тестами -race): платформа запроса профиля для виртуальной личности (inventory_platform), детали ошибок сбора/preflight в отладке, классификация ошибок WinRM (401/TLS/сеть/код выхода) без текста цели, сценарий только ASCII и никогда не молчит (errors по категории PowerShell, fatal), причина ACCESS_DENIED в секциях, winrm-probe (по шагам NTLM, exec-cmd/exec-ps/exec-script), доставка сценария через stdin коротким загрузчиком (без лимита длины командной строки) — на цели ещё НЕ проверена.

R-026, C18.04 продолжение (прямые выводы пользователя): загрузчик через stdin работает (`ok-stdin`); проверка с наполнителем ДО команды напечатала `ok-end` — обрезания командной строки НЕТ (гипотеза закрыта); полный сценарий через stdin — 36 с, exit 0, пустые stdout/stderr. ПРИЧИНА (по коду masterzen/winrm, вывод — гипотеза до проверки на цели): long-poll Receive держится сервером до OperationTimeout (по умолчанию PT60S), а HTTP ResponseHeaderTimeout клиента был 30 с (проба) / 15 с (агент); клиент бросает запрос, сервер отдаёт вывод в брошенный ответ — вывод потерян, следующий Receive получает только «завершено, код 0». Короткие команды не затронуты. Исправление: OperationTimeout PT20S, HTTP-таймаут 60 с, собственные параметры вместо общего DefaultParameters (тест согласованности таймаутов). Лимит сбора профиля Windows 420 с — с запасом.

R-026, C18.04 ПРИЧИНА ПОДТВЕРЖДЕНА на живой цели (прямой вывод пользователя, код f067a35): после согласования таймаутов long-poll (OperationTimeout PT20S, HTTP 60 с) тот же сценарий (36 с) вернул stdout 9577 байт JSON, exit 0. Без прав администратора: errors = os/cs/prod/bios/cpu/nics/svcs:PermissionDenied (WMI root\cimv2 закрыт для не-админа), реестр Uninstall читается (software). Замечание: при отказе WMI сценарий выдаёт по одной «пустой» записи nics/services (конвейер $null | ForEach-Object) — разборщик их отбрасывает (нет имени); в сценарии стоит отфильтровать $null. Следующий шаг — агент run-winrm12 с этой версией (ожидаемо: identity по hostname, software из реестра — partial; os/network/services/hardware — unavailable/ACCESS_DENIED).

R-026, C24.02 факт (прямой вывод пользователя): WinRM-цель (surveyscan-winrm1, не-админ) доставила наблюдения (inventory_queued, observations растут), но в центре assets=3 — WinRM-цель НЕ сведена с Windows-агентом той же машины. Причина: без прав WMI сценарий отдавал только hostname (namespace dns), а родной Windows-агент шлёт hostname.raw + machine_uuid/windows-machine-guid; только по слабому hostname центр не сливает (ложного слияния нет — правильно). Исправление (код, тесты -race ok; на цели не проверено): сценарий читает MachineGuid из HKLM\SOFTWARE\Microsoft\Cryptography (обычно доступен без прав администратора) → кандидат machine_uuid/windows-machine-guid в нижнем регистре; hostname теперь в namespace hostname.raw, как у родного агента; при отказе WMI нет пустых записей nics/services. Существующий актив WinRM-источника переносить не будем (слияние/разделение — C25); проверка — новой личностью surveyscan-winrm2.

R-026, C18.04 / C24.02 ЖИВОЙ РЕЗУЛЬТАТ (прямой вывод пользователя, 2026-11-10 ~15:28 UTC, код a2bb383): WinRM-сбор Windows Server 2019 DC без прав администратора работает сквозно до центра. winrm-probe: MachineGuid читается без админа (machine_guid 15b9bc6b-…), errors = os/cs/prod/bios/cpu/nics/svcs:PermissionDenied (WMI закрыт для не-админа). Новая личность surveyscan-winrm2 (run-winrm12): agent_enrolled, inventory_profile_synced, inventory_queued, служба active. Центр: assets осталось 3 при добавлении нового источника (observations 907) — WinRM-источник сведён с активом Windows-машины по machine_uuid/windows-machine-guid (вывод по счётчику активов; связь в БД отдельным запросом не проверялась). Старый surveyscan-winrm1 (только hostname, отдельный актив) выключен — его актив остаётся отдельным до появления слияния (C25).
Итог C18.04 (факты): HTTPS+свой CA ✓; NTLM через Negotiate ✓; не-админ требует ACE Remote Management Users в RootSDDL (настройка цели); не-админ без прав WMI получает только hostname, MachineGuid и ПО из реестра — os/network/services/hardware = unavailable/ACCESS_DENIED (честный статус); с правами WMI секции не проверялись. Найдено и исправлено 4 дефекта по ходу: платформа профиля виртуальной личности, потеря вывода из-за таймаутов long-poll, молчащий сценарий/неразличимые ошибки, пространства имён кандидатов. Изменения на цели для теста (откатить после пилота): пользователь AWM\scanwinrm, сертификат и HTTPS-listener 5986, правило firewall от 10.170.108.2, ACE S-1-5-32-580 в RootSDDL. На Linux: drop-in отладки surveyscan-winrm1/2 (debug.conf только у winrm1).

R-026, C23.02 portable-сбор (код + проверка в песочнице; трек Б по выбору пользователя). Новое: internal/portableaudit (Init/Load/Run), agent.CollectHost12 (Linux/Windows), cmd/surveyscan-portable (init/collect/verify). Тесты -race: init/load/без перезаписи/приватность ключа, экспорт проверяемого пакета с изоляцией сбоя цели, dry-run, монотонная последовательность, отмена без файла, отказ невалидного наблюдения. ЖИВОЙ прогон в песочнице: init → dry-run (12 секций хоста) → export (пакет 0600, state 0700/0600) → verify accepted=1; перезапись отвергнута; чужой ключ → «signature or key is not trusted»; подмена наблюдения → карантин DIGEST_MISMATCH; ключ подписи в пакете не найден; смешанный режим хост+SSH (настоящий OpenSSH) → 2 наблюдения, verify accepted=2; SSH-цель с неверным отпечатком → частичный пакет из 1 наблюдения и код выхода 3. Windows: сборка/vet под GOOS=windows ok, запуск на Windows НЕ проверялся. НЕ сделано: импорт пакета в центр (C23.03: эндпоинт/CLI, доверие к ключу portable-источника в реестре, staging/checkpoints/mapping), шифрование пакета, parity online/file (C23.04).

R-026, C23.03 импорт portable-пакета в центр (код + проверки локально на PostgreSQL 16; трек Б). Формат: записи пакета — SignedObservation (подпись как у агента), key_id в форме UUID; импорт проверяет подпись манифеста и каждой записи (RECORD_SIGNATURE_INVALID → карантин), origin.source_kind обязан быть portable. Центр: sources.RegisterPortable/PortableTrust (источник portable + ingest_binding, аудит), app.Registry.ImportPortable (проверка пакета ключом из реестра → общий IngestAuthorized с авторизацией «только этот portable-источник»), консоль surveyscan-server portable-register / portable-import. Проверено: unit -race (portable, portableaudit), интеграционный тест TestC23PortableRegisterAndImport (регистрация идемпотентна, конфликт поколения, применение к активу, повторный импорт без дублей, чужой ключ и неизвестный источник отвергаются без записи, аудит), архитектурные границы ok. СКВОЗНОЙ прогон настоящими бинарниками (PG16, БД e2e): server migrate (37) → bootstrap-admin → surveyscan-portable init/collect (живой хост песочницы) → portable-import до регистрации = «resource not found» → portable-register → portable-import = applied (asset создан, SOURCE_MAPPING) → повтор = duplicate; в БД 1 наблюдение, 1 актив. Попутный факт: два разных source_record с одинаковыми признаками идентичности центр помечает recorded_pending_resolution/IDENTITY_CONFLICT (правильно, не дефект). НЕ проверено: проекция current_facts (не заполнилась при консольном импорте — вероятно, её делает работающий сервер; не проверено), HTTPS-путь, PostgreSQL 17/CI, ВМ пользователя, Windows-запуск portable.

R-026, SOAK №2 ИТОГ (прямой вывод пользователя; soak-start 10:24:27 UTC → soak-end 16:57:48 UTC Windows / 16:58:00 UTC Linux, ≈6 ч 33 мин; центр vm_center.py PID 1881859 жив всё время, БД ssv2machine_a3b1… та же).
ФАКТЫ. Windows (SurveyscanAgentVm, PID 4068 тот же, RUNNING): sequences inventory 4→379, heartbeat 7→769; WS 24 834 048→27 615 232, PM 60 084 224→62 287 872, HandleCount 161→185; w32tm Source 10.170.108.2, Last Successful Sync 19:46:17 местного (16:46 UTC); spool 5 файлов/3 796 Б → 380 файлов/401 383 Б. Центр: наблюдения по источникам — Windows 90abb706… 379 (max 379), Linux-агент 93f3ad4e… 384 (max 384), SSH-цель c935c7a6… 392 (max 392), WinRM b22ee044… 56 (max 56), WinRM f10ed551… 2 (max 2); assets=3. Linux-службы: surveyscan-agent active, MemoryCurrent 14 426 112→15 446 016, NRestarts 0; surveyscan-ssh1 active, 16 019 456→18 042 880, NRestarts 0; surveyscan-winrm2 active, 16 515 072, NRestarts 0.
ВЫВОДЫ (расчёт): нумерация без пропусков у ВСЕХ источников (число наблюдений = max sequence); Windows inventory +375 за 6,56 ч ≈ 57/ч, heartbeat +762 ≈ 116/ч (≈31 с) — соответствует настройкам 60/30 с; assets=3 стабильно (Linux-агент+SSH = 1, Windows+WinRM2 = 1, отдельный актив WinRM1 только по hostname — ожидаемо); рост памяти Windows за 6,5 ч при живом центре: WS +2,8 МБ (+11 %), PM +2,2 МБ (+3,7 %), handles +24 — несопоставимо меньше первой ночи при мёртвом центре (WS 24→67 МБ); утечку не подтверждает и не исключает (нужен прогон ≥ суток). Рост spool — кэш квитанций центра (~1 КБ на доставку) для распознавания повторов: по коду diskspool.capacity вытесняет старые квитанции при нехватке места под лимит 1 МиБ, при >4096 файлах или старше 7 суток — ограничен, НЕ дефект (поведение при достижении лимита на живом стенде не наблюдалось). Время синхронизировано. Хвост V9 (замер ресурсов): частично закрыт для режима «центр жив», дочерние процессы Windows inventory-worker не измерялись.

R-026, C23.03 доп. проверка фактов: ложная тревога предыдущей записи — для профиля 1.2 факты проецируются СИНХРОННО при приёме (app/registry.go → ProjectPartial12) в inventory.record_facts12, а не в current_facts (таблица 1.0). В e2e-БД после консольного portable-импорта: record_facts12 software=4255, users_groups=624, routes_ports=208, resources=50, network=9, hardware=7, os=3, identity=2 для одного актива. Интеграционный тест дополнен: факты актива читаются API записей 1.2 (InventoryRecordFacts), у каждого факта происхождение = portable-источник. НАЙДЕН общий пробел (не portable, касается и агентов 1.2): сводка источников карточки C09 (InventoryDetail.Sources) строится только из проекции 1.0, поэтому источники данных профиля 1.2 в ней не перечислены (тест фиксирует текущее поведение логом). Полный integration-набор internal/app на PG16 — ok (72 с).

R-026, передача сессии: локальный повтор CI v2 (job c04, песочница с dockerd, код 5f3d1cb) — шаги 01–08 rc=0 (verify+контракты, race agent/collector/wire, сборка, Web UI, signed release bundle 14 проверок, unit_check systemd-analyze, dev.py up, integration на PostgreSQL 17); шаги 09–36 не завершены к моменту передачи (результат НЕ получен). Создан handoffs/C15-C24-session-handoff-2.md, STATUS.md обновлён.

R-026, локальный повтор CI v2 к моменту передачи (5f3d1cb): 01–10, 14, 15 rc=0; 11–13 (machine_smoke, agent_smoke, recovery_smoke) rc=1 — «machine/collector binary did not start» (центр не отвечает на TLS-порту за 10 с, в логе только старт). Причина НЕ установлена (песочница или регрессия после C14) — первое дело следующей сессии, подробности в handoffs/C15-C24-session-handoff-2.md.
R-026, дополнение: после передачи шаги 16 (bao_pipeline), 17 (c15_center_smoke), 18 (c15_relay_smoke) rc=0 — c15-смоуки используют ту же обвязку machine_smoke с центром на TLS, поэтому провал 11–13 вероятнее связан с песочницей/таймингом (ready ждёт 10 с), а не с регрессией кода. НЕ подтверждено — воспроизвести в новой сессии.
R-026, дополнение: локальный CI шаги 19–21 rc=0, в т.ч. 21 — vm_center.py --selftest на текущем коде (множественные prepare-файлы, acquisition по имени, устойчивость к пустому prepare) — изменения стенда центра подтверждены автоматической проверкой.
R-026, разбор провалов локального CI (факты): (1) ПРИЧИНА провалов 11–13, 25–28 (machine_smoke и сценарии на его обвязке без Bao) — окружение песочницы: Python 3.13 по умолчанию включает ssl.VERIFY_X509_STRICT, тестовый файловый CA dev-режима ему не соответствует, ssl.SSLError скрипт ready() принимает за «не запустился». Доказательство: тот же machine_smoke со снятым ТОЛЬКО флагом VERIFY_X509_STRICT — status passed, 8 проверок C07. Hosted CI (Python 3.12) этого не видит; при переходе CI на 3.13 сломается — стоит сделать тестовый CA RFC5280-строгим (отдельная задача). Регрессии кода не обнаружено. (2) Шаг 22 (run12 non-root) — РЕАЛЬНОЕ устаревшее ожидание после C16.02: CI требовал services=unsupported, а агент теперь собирает службы через systemctl (partial на хосте с systemd, unavailable без него). Проверка в .github/workflows/v2.yml обновлена; новая проверка прогнана на свежем бинарнике от nobody — проходит (services unavailable в песочнице без systemd).
R-026, локальный повтор CI v2 ЗАВЕРШЁН (34 шага, старт на 5f3d1cb): rc=0 — 01–10, 14–21, 23, 24, 29, 30, 33. Провалы и причины (факты): 11–13, 25–28 — Python 3.13 VERIFY_X509_STRICT против тестового CA (machine_smoke со снятым флагом проходит); 22 — устаревшее ожидание services (исправлено в df5ca5b); 31 (upgrade_smoke) — песочница: клон неглубокий (shallow), нет исторического коммита b22efa2 для git archive (в CI fetch-depth 0); 32 (update_smoke) — «rebuild Go components after changing source revision»: во время прогона я делал коммиты (HEAD 5f3d1cb → df5ca5b), а .dist собран на старом HEAD — артефакт прогона, не код. Регрессий кода после C14 этим прогоном не обнаружено; 31–32 и сценарии 11–13/25–28 нужно перепроверить в среде как у CI (Python 3.12, полный клон, без коммитов во время прогона) или hosted CI.
