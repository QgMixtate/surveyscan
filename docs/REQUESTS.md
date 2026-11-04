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
