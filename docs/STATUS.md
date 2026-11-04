# Текущее состояние surveyscan

R-020, 2026-11-05: пользователь поручил продолжить и опубликовать всё сделанное в GitHub.
Публикация текущей ветки/PR/Actions подготавливается; прежние no-push ограничения ниже исторические.
Main не сливать, production deployment и перепубликация среды не поручены.
Новые проверки C13: общий stopped-writer PG/Bao/files checkpoint10 и actual C11schema31→33 upgrade13 passed.
Restore на других FS paths, original host/issuer fenced, pending replay exactly once/UID/sequence3,
оба spool drained, прежняя session и новый leaf certificate через restored Transit CA.
После upgrade все previous domain rows и31 applied hashes сохранены; migrate2→0, login/card/write/profile1 работают.
Перед публикацией make verify39unit/58C03 и50 realPG integration passed. Workflow дополнен Node/Web build,
release/static units/PG/Bao/common checkpoint/previous-version upgrade; hosted run ещё не подтверждён.
48/200 done: C13.01–03 in_progress до systemd/live-update/two-clean-OS gates; C14 не начат.

Обновлено: 2026-11-05 (Москва). GitHub refs повторно проверены fetch/ls-remote; main73ced7e, PR refs1–3 без изменений. Новые этапы локальны.

C13.01–03 в работе: staged systemd units и подписанный Ed25519 directory bundle,
SHA256/size/mode manifest, SPDX2.3 dependency inventory, verified atomic filesystem staging.
14 release checks, make verify (39 unit/58 fixtures) и separate Web build passed.
Все пять компонентов показывают version/revision/dirty; keys/configs не включаются в поставку.
Actual systemd boot/reboot и live checked update/backup/restore остаются открытыми:
host PID1 tail, нет QEMU/KVM/nspawn, Docker cgroup driver none. 48/200 done без изменения.
Продолжение: [handoff C13](plans/surveyscan-v2/handoffs/C13.md), [release procedure](../v2/deploy/RELEASE.md).
PG component backup/restore:18 actual pipeline+restore checks passed,46 table fingerprints identical,
33 migrations verified without reapply, прежний admin login и UID/card доступны на восстановленном
реальном TLS server; authorized PATCH создаёт ровно один audit/outbox и сохраняет UID. Full checkpoint/filesystem/previous-schema upgrade ещё не проверены;
PG-only component не обновляет общий backup marker. [Runbook](../v2/deploy/BACKUP.md).
Отдельный Bao Raft restore:9 checks passed на initially empty disposable node; cluster ID,
KV/scoped policy сохранены, оба non-exportable Transit ключа подписывают проверяемые challenges,
после actual Docker restart/unseal подпись работает. Source volume не восстанавливался/reset.
Это component dev rehearsal, не единый PG/Bao/filesystem restore, production HTTPS/KMS или boot.


Актуальная задача R-019 — выполнять этапы последовательно до лимита.
C01–C12 завершены локально в ограниченном E1 scope:48/200 done.
[C12 передача](plans/surveyscan-v2/handoffs/C12.md): CLI JSON/table, versioned central profiles,
signed delivery/application ACK, sourceHB vsinventoryfreshness,tenant diagnostics/metrics/alerts,
private offline snapshots и read-only Web profile panel. CLI/APIadmin меняет интервалы.
39unit/50realPG/58fixtures,13operator/17CLI/16browser,8SIGKILLrecovery и10agent/10collector renewal passed.
Реальный120→60с cadence проверен безfakeclock; collector TLSrace отдельно сtest scheduler clock.
33migrations/45tables, prior SQL/C03/C09 bytes неизменны. Backup ageunknown безactualmarker,
production/systemd/24h/DR/hardwareclone/100users не проверены. C11 identity limitations сохранены.
Далее C13 установка/services/release artifacts/backup/restore; сначала проверить доступностьsystemd/cleanboot.
C04/C05 hosted success, C06–C12 локальны; no push/merge/deploy/env publication.

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
