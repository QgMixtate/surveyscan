# Текущее состояние surveyscan

Обновлено:2026-11-05, Москва. C01–C13 приняты в пределах E1; C14.01 done,
**53/200 подзадач**. C14.02 выполняется; C14.03/04 planned до фактического суточного результата.
Ветка `codex/v2-c13-operations`, draft [PR4](https://github.com/QgMixtate/surveyscan/pull/4).
R-020 разрешает push/PR/CI; R-021/R-022 — автоматический переход после приёмки зависимостей.
Main73ced7e не слит, production deployment и публикация настроек среды не поручены.

**Реальный24h прогон работает**: `10812e7a-8a6a-4dae-9dd5-b0583f503c83`, PID3505270.
Чистый runtime source8560f57, frozen private copies/SHA256. Начало5 ноября00:31:49UTC;
завершить можно не раньше **6 ноября03:31:49 по Москве** (00:31:49UTC), при всех успешных checks.
Run жив уже≥8h; выполнены оба networkfault и запланированные restart collector/center.
На [снимке](plans/surveyscan-v2/evidence/C14-soak-progress.json) пройдены оба настоящих разрыва
связи, UID/sequence сохранены, очереди опустели; это **не** суточный PASS.
Изv2: `python scripts/soak_status.py <run-id>`, `python scripts/soak_report.py <run-id>`
и `python scripts/soak_acceptance.py <run-id>` (exit3=pending, не24hPASS).
[Evidence guard](plans/surveyscan-v2/evidence/C14-evidence-gate.json):10 synthetic tests passed;
965 actual samples проверены, max gap32.027s, pending. Private follow-up PID843094 после
завершения runner сохранит acceptance-review.json; plan/Git/C15 автоматически не меняет.
Local state `.local/c14-soak/<run-id>/status.json`; stdout `.local/c14-actual-soak.log`.
Проверять PID/run ID и свежий sample; marker running без процесса неPASS. Не останавливать/
запечатывать общий dev PG/Bao. Runner отделён от жизни вызова/чата, но не переживает выключение машины.
[Инструкция](../v2/deploy/SOAK.md), [передача C14](plans/surveyscan-v2/handoffs/C14.md).

**Последний полностью зелёный runtime/code baseline5954f5c:3 hosted workflows SUCCESS**:
v2 run41956828439, Web41956828524 иnative boot41956828433.
[Скачанные отчёты/хеши](plans/surveyscan-v2/evidence/C14-hosted.json),
[native proof](plans/surveyscan-v2/evidence/C14-native-hosted.json).
Две fresh VM9+9 подтвердили reboot/autostart/nonroot/LoadCredential/operator unseal/UID+queues/
combined checked update/CLI/staticWeb. Readiness исправлен: unseal ждёт активную Raft health,
collector — проверенный TLS listener. Безопасные phase/call-line diagnostics сохраняют причины;
старые failed runs не переименованы вPASS. [Дефекты](plans/surveyscan-v2/evidence/C14-defects.json).

Новая проверка e7a07fe: validator workflow41999415338 SUCCESS (10 synthetic tests),
v2 41999415657 SUCCESS; native41999415334 failed после8checks на CLI-login.
[C14-D08](plans/surveyscan-v2/evidence/C14-native-cli-failure.json) остаётся на разборе.
Два local VM9+9 с timings прошли (CLI-login4.286s/4.706s); добавлены безопасные exit/category/
duration diagnostics и5 unit tests на отсутствие credential/stderr leakage. Это ещё не исправление
неизвестной причины hosted CLI сбоя; новый instrumented hosted run нужен для диагностики.

Local verification:43 top-level Go tests +3 subtests,58 C03 fixtures; исходные architecture guards
сохранены, новый SQL guard проверяет92 production Go files/7 контрпримеров.136 runtime inputs
Go/SQL/contracts/build files побайтно равны measured8560f57; после него менялись tests/docs/operator stand.
[Reconnect5](plans/surveyscan-v2/evidence/C14-reconnect.json) на3 процессах/одном хосте и
[preflight121.597s](plans/surveyscan-v2/evidence/C14-preflight.json) прошли; preflight не заменяет сутки.

[Private candidate27files](plans/surveyscan-v2/evidence/C14-candidate.json): clean8560f57 Go/Web,
те же3 daemon hashes, test sign/verify/staging и [Chromium16](plans/surveyscan-v2/evidence/C14-candidate-browser.json)
на точных artifacts passed. Private test signing key удалён, official release не опубликован/не принят.
[Draft notes](releases/surveyscan-v2-e1-candidate.md), [матрица15 E1 сценариев](plans/surveyscan-v2/evidence/C14-plan.json).

Следующий переход: после реального≥86400s PASS — C14.03 triage/регрессия, C14.04 acceptance/
поставка, затем C15 без нового routine confirmation поR-022. До этого C14/C15 не считать ready.
Нет claim о100users/SLA/production KMS/HA/geo/physical power loss. SQL0000–0032/C03/C09 не менялись.
История ниже — прежние состояния; текущий статус определяется этим блоком и живым run report.

## Контекст архитектуры и история C01–C04

Локально сохранены спецификация/архитектура 0.5, исследование аналогов, матрица 19 замечаний,
план из 50 пакетов и 200 подзадач. GitHub main при проверке 2026-11-03 — 73ced7e (документы 0.3).
Теперь документы опубликованы в C04 feature branch; main остаётся на 0.3.
Runtime candidates C01: Go 1.27.3, PG 17.x, Bao 2.7.2, bbolt 1.5.0; Web React/TS/Vite.
В C04 Go/pgx/PG/Bao/nginx проверены сборкой и локальным стендом; остальные candidates не подтверждены. ОС host agent остаётся proposed до C08; серверный dev-стенд Linux/amd64, не блокирует C02–C07.
Последнее определение R-011: local agent — постоянная служба хоста → постоянный collector;
portable — разовый аудит. Предыдущая трактовка local в R-008 заменена.
OpenBao, UID, ответственность, agentless/discovery/topology, API/CLI, outbox/FTS,
геопроектирование, отдельный UI и модульность сохранены. Первый релиз — постоянно работающий SMB,
а не только разовый импорт; расширение по эпохам, затем ЖЦ/склад и ITSM.

C01 завершён: scope E1, baseline, рабочие ADR-кандидаты и план приёмки сохранены в decisions/.
[Передача C01](plans/surveyscan-v2/handoffs/C01.md). Продуктовые проверки и 24ч soak не запускались.
C02 завершён документально: 24 логические сущности, 9 владельцев, 14 инвариантов, 4 транзакции
и 22 контрпримера. [Передача C02](plans/surveyscan-v2/handoffs/C02.md).
ID-03 уточнён: mapping использует origin source; collector-посредник — маршрут.
На выходе C02 проверялся проект; в C04 появились SQL FK/PK/guards. Projector ещё не реализован.
C03 завершён: 26 OpenAPI операций, 54 schemas, origin/center signatures, enrollment/renewal proof,
receipt vs applied/pending result, heartbeat challenge и jobs/outbox contracts.
58 fixtures (19 positive/39 negative), 12 state edges, 2 JCS vectors и 3 HTTP формы проверены.
[Передача C03](plans/surveyscan-v2/handoffs/C03.md). Реальные HTTP/mTLS/PG/lease/commit tests unrun.
Следующее действие C04 — новый Go-каркас, PG/миграции, dev-стенд и CI; исходный порядок сохранён. Читать
[индекс](plans/surveyscan-v2/TASK_INDEX.md), [C04](plans/surveyscan-v2/packages/C04.md)
и [стартовый запрос](plans/surveyscan-v2/prompts/C04.md). В каждом чате только выбранный пакет,
краткий STATUS, последние REQUESTS и необходимые разделы спеки. C01–C03: 12 задач done как проектирование/контракты, остальные 188 planned; код v2 пока не реализован.
Ранний функциональный цикл — C08, проверенный SMB-релиз — C14; не называть C08 production-ready.
Плановые 24ч soak/нагрузка/пилоты не выполнены. Внешние стенды/credentials/решения — prerequisites.
Документы исследуют Device42, GLPI/Agent, runZero и Snipe-IT по официальным GitHub-источникам;
остальные упомянутые аналоги свежими материалами не подтверждены из-за сетевых ограничений.
На этапе планирования проверялись ID/coverage/DAG/ссылки/структура WBS; затем C04/C05 добавили код v2.
При новом окружении нужен опубликованный документ или переданный архив 0.5/плана;
не заменять его старым main 0.3. Статусы/артефакты сохранять по шаблону handoff.

## Историческое состояние до R-011/R-012

Ниже сохранены предыдущие записи. Трактовка local и следующий приоритет определяются блоком выше.

## Историческая передача на 3 ноября — R-007 (уточнена R-008)
Пользователь завершает обсуждение на сегодня и просит сохранить контекст для другого устройства.
Спецификация v2 0.1 и схемы опубликованы. «Окей, сохрани» подтверждает сохранение,
но не означает согласование D-01–09 или запуск миграции. Код Go ещё не реализовывался в этом чате.
Следующий шаг: прочитать актуальные документы GitHub, проверить новые ветки/PR и кратко восстановить
контекст; затем согласовать открытые решения и объём первого этапа. Не начинать автоматически
старый фикс Python или слияние веток.

Готовый запрос для нового чата:
> Продолжаем surveyscan: https://github.com/QgMixtate/surveyscan.
> Загрузи актуальные AGENTS.md, docs/STATUS.md, docs/REQUESTS.md,
> docs/specifications/go-asset-management-v2.md и docs/architecture/go-target-architecture.md
> непосредственно из GitHub. Проверь новые ветки и PR, не полагайся на старую локальную копию.
> Восстанови точку остановки и продолжи обсуждение Go-версии с открытых решений спецификации.
> Веди журнал и актуальное состояние в GitHub.

На новом устройстве необходим доступ к приватному репозиторию. Непереданные сообщения
другого чата не считаются автоматически доступными: сохранённая документация — точка передачи.

## С чего продолжить на другом устройстве
Прочитать этот файл, [журнал запросов](REQUESTS.md), затем [правила работы](../AGENTS.md).
Сначала проверить свежие ветки и PR на GitHub, а не только локальный HEAD. Перед pull проверить git status; не затирать незакоммиченные изменения.

## Состояние кода
- main: последний проверенный коммит кода ba8f735 — расширение инвентаризации (интерфейсы, маршруты, соединения, службы, группы, диски/USB). После него публикуются документы передачи работы.
- codex/baseline-audit: c678ead16655904b53814b284cba8ac94b4fc874 от 2 ноября — восстановление импорта, отмена задач, тайм-аут nmap, маскирование ошибок, API коннектора, упаковка ресурсов. В сообщении коммита заявлено 126 passed с PostgreSQL 16.15; в этом чате прогон не повторялся. При проверке PR для ветки не найден.
- codex/asset-inventory: c333c3286d5fa1954919e30ea39ec22ce2261356 от 2 ноября — корректность парсеров Linux, состав групп Windows, независимый сбор TCP/UDP, статусы полноты, DNS и метрики маршрутов.
- [PR №1](https://github.com/QgMixtate/surveyscan/pull/1): черновик, открыт, не слит. Ветка codex/asset-inventory → main. На момент проверки комментариев и ревью нет.
- Обе ветки на момент проверки на один коммит впереди ba8f735 и ещё не объединены.

## Проверки и ограничения
PR №1 сообщает о 55 passed (19 проверок инвентаризации + 36 версий): SQLite, временная no-op подмена apply_role_guess в процессе тестов. Заглушка не включена в код. Также заявлены проверки PowerShell на подменённых командах и Chromium. Полный PostgreSQL-прогон и сбор с реальных хостов для этой ветки не выполнены.
В main ранее обнаружен импорт отсутствующей apply_role_guess. Исправление находится в отдельной ветке аудита; не считать main исправленной до объединения и проверки.
Локальная Windows-копия этого чата осталась на ba8f735 с незакоммиченными изменениями нескольких задач. Она не является актуальным источником состояния других устройств.

## Исторический приоритет R-009: Web UI отдельно, backend готов к разделению
Актуальны [спецификация 0.3](specifications/go-asset-management-v2.md) (30 разделов, 43 критерия)
и [архитектура 0.3](architecture/go-target-architecture.md).
Серверный frontend — отдельная сборка/поставка и OpenAPI-контракт; команды и релизы независимы.
Backend — модульный Go-монолит с ownership данных/контрактов; proposed combined/api/worker роли
для изоляции тяжёлой обработки. Встроенный UI остаётся лишь возможной опцией portable.
Последующее выделение модулей в сервисы требует переноса данных/контрактов/инвариантов, не обещается автоматически.
Ориентир 100 одновременно активных пользователей — предложенный нагрузочный сценарий;
не известный предел монолита и не подтверждённая ёмкость.
Сохраняются R-008: OpenBao; portable local/network; agentless discovery/topology; asset_uid и
ответственность; CLI/API; outbox без внешней шины; Tantivy/Bluge (не выбран); георезерв.
Волна 2 — процессы ЖЦ/склад/запчасти/движения; волна 3 — ITSM.
Следующий шаг — ER-модель и D-01–18, особенно frontend/границы модулей/нагрузочный паспорт.
Код/миграция не начаты. Ветки Python отдельно, не объединены этой работой.

## Предыдущая точка остановки
Пользователь сообщил, что на другом устройстве закончились токены и остались последние запросы. Точный текст этих запросов недоступен в истории этого чата. Не выдавать предполагаемый следующий шаг за запрос пользователя.

Поручение вести документацию и журнал в GitHub сохраняется. На момент исторической записи последним был R-009; актуальный следующий шаг указан выше по R-012. Документы публикуются в main; код не объединяется.

## Ранее предложенный шаг для Python-версии (приоритет пересматривается)
После восстановления незавершённого запроса: совместить аудит ядра и инвентаризацию, проверить объединённую версию с PostgreSQL и запуск Docker, затем рассмотреть слияние в main. Это предложение, а не уже выполненная работа или разрешение на слияние.

## Навигация
- [Спецификация Go Asset Management v2](specifications/go-asset-management-v2.md)
- [Журнал запросов](REQUESTS.md)
- [Карта проекта и команды](../CLAUDE.md)
- [Установка](../INSTALL.md)
- [Описание проекта](../README.md)

C11 в работе локально: 01/02 done,03/04 in_progress (42/200 done). Scoped OpenBao KV/Transit,
non-exportable CA/receipt keys, private token/policy, declarative masked audit, no private-key fallback.
4 live scoped checks +15 compiled pipeline checks passed: actual seal/unseal, readonly sealed restart,
staging retained→automatic ACK/no duplicates. make verify/build и43PG passed.
Renewal/rotation/clone matrix ещё не готова; продолжать C11.03, не переходить к C12.
Передача plans/surveyscan-v2/handoffs/C11.md; production HTTPS/custody/restore rehearsal unrun.
Без push/merge/deploy/повторной публикации среды.

C12.02 готов локально: managed versioned profiles, signed origin/center delivery/ACK, CLIupdate,
agent runtime/cache и collectorheartbeat.36unit/49PG/58fixtures/10livechecks passed.32migrations/44tables,
46/200done. C12.03diagnostics вработе,04operator pending. No push/merge/deploy/env publication.

C13 начат локально: codex/v2-c13-operations отC12d55a23d.01in_progress (48/200done).
Stagedsystemdunits/installer(privatecredentials/data paths) и5stagingchecks,real system-mode
systemd-analyze staticverifyexit0вnetworklesscontainer. Actualboot/reboot/services не проверены:
managedhostPID1tail/UID1000. No host service install/start. handoffs/C13.md содержитточнуюграницу.
C13.02–04release/backup/restore ещёplanned; no push/merge/deploy/env publication.

## Дополнительная подготовка C14

[Внутренний кандидат](plans/surveyscan-v2/evidence/C14-candidate.json) содержит27 public files,
чистые Go/Web8560f57 и те же3 daemon binaries, что actualsoak. Test-signed/verified/staged локально;
private test signing key удалён, production trust/release не утверждались. Его точные артефакты
прошли [Chromium16](plans/surveyscan-v2/evidence/C14-candidate-browser.json).
[Предварительные release notes](releases/surveyscan-v2-e1-candidate.md); C14.04 остаётсяplanned.
`soak_report.py <run-id>` сводит только завершённые samples; running/preflight/failed неPASS.

C14 native continuation: e3fe449 failed hosted boot at second_unseal_replay after4checks; safe
phase/line retained, old until-helper line did not identify the exact replay condition. Local e3
also reproduced first_bao_init/sys/mounts/transit failure immediately after unseal. Operator now
waits HTTPS health200 initialized=true/sealed=false/standby=false before provisioning, without
write retries/storage reset/custody regeneration. Two fresh local VM9+9 passed with this gate.
5954f5c published the gate and granular readiness/inventory/queue phases plus numeric guest call
lines/Bao HTTP status; no raw journals/custody upload. Hosted repeat pending. Actualsoak8560f57
passed both real two-minute cuts;124+ observations/oneUID/no duplicates/both queues drained,
max sampled inventoryage184.44s<300. Stillrunning/not24hPASS;53done and C15 waits.

Latest native acceptance:5954f5c hosted boot41956828433 SUCCESS, two fresh VM9+9,
[proof](plans/surveyscan-v2/evidence/C14-native-hosted.json). Active-Raft/readiness fixes verified;
latestfullv2 regression41956828439 stillpending, Web41956828524 check separately.
Actual24h8560f57 remains running; both real network faults recovered, no24hPASS claim.
