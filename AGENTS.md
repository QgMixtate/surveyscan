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

[План](docs/plans/surveyscan-v2/README.md): 50 пакетов/чатов, 200 подзадач; C01–C03 завершены как проектирование/контракты, C04 — Go-каркас/dev-стенд, C05 — auth/tenant scope, C06 — реестр/проекция/outbox; C07 — collector/upload; C08 — live Linux agent/heartbeat; C09 — Web UI/detail API; C10 recovery done; C11 done (bounded E1), C12/C13 done bounded E1; C14.01 done, C14.02 actual24h running; по R-023 независимая C15.01 preparation в codex/v2-c15-windows, C15.02–C50 planned.
Для текущей работы читать TASK_INDEX.md и packages/Cxx.md, затем только нужные spec sections.
Не читать весь WBS в каждом чате. Handoff — по HANDOFF_TEMPLATE.md; evidence и статусы — в plan.json,
краткая передача в STATUS и REQUESTS. При продолжении сохранять уже заполненные evidence/статусы.
C04/0.5/план опубликованы в codex/v2-c04-foundation (7407da6); C05 — ветка codex/v2-c05-auth. Main не слит. Точные publication refs — в STATUS/evidence; не выдавать local tests за hosted CI.
Планирование не означает разрешение сразу реализовать все пакеты или выполнить production deployment.
Текущий acceptance пакет — C14; независимая подготовка C15.01 разрешена R-023 без объявления C14 done. Ранний сквозной цикл после C08, эксплуатационная приёмка первого SMB после C14.
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

C09 завершён локально: handoffs/C09.md. Отдельные React/TS/Vite UI и C09/1.0 API детализации,
IP/MAC/provenance/section attempt-success/friendly responsibility/source generation/contact. Source inventory
summary обновляется через source-owned port (29 migrations/39 tables), heartbeat его не меняет.
18 unit/37 PG/58 C03 fixtures/14 browser checks passed; C03 unchanged. 36/200 done.
C06–C09 не опубликованы. Следующий C10 по R-019; не сливать main/не менять настройки среды.

C10 done локально: handoffs/C10.md. Leased/fenced import processing, bounded admission, payload GC
после signed durable result, retry/deadletter и cached-ACK/revoke recovery. SQL30/40tables;
22 unit/42 PG/58 fixtures/8 real process-recovery/1 real ENOSPC/14 browser checks passed.
40/200 done. Jobs runtime/API C12; C10 import/outbox foundation. Следующий C11 OpenBao/PKI.
C06–C10 не опубликованы; no merge/deploy/env publication.

C11 в работе локально: 01/02 done,03/04 in_progress (42/200 done). Scoped OpenBao KV/Transit,
non-exportable CA/receipt keys, private token/policy, declarative masked audit, no private-key fallback.
4 live scoped checks +15 compiled pipeline checks passed: actual seal/unseal, readonly sealed restart,
staging retained→automatic ACK/no duplicates. make verify/build и43PG passed.
Renewal/rotation/clone matrix ещё не готова; продолжать C11.03, не переходить к C12.
Передача plans/surveyscan-v2/handoffs/C11.md; production HTTPS/custody/restore rehearsal unrun.
Без push/merge/deploy/повторной публикации среды.

C11 checkpoint10a3f93: scoped OpenBao + no local private fallback. Продолжение: cert_renew
challenge/ledger, server/collector relay и Linux agent atomic TLS key rotation реализованы;
24unit/46PG/58fixtures +8live rotation/ACK-loss +8recovery/14browser regression passed.
31migrations/42tables (0030 appended),42/200 done. C11.03/04 ещё in_progress: collector self-renew,
expiry/clone matrix и final acceptance. Читать handoffs/C11.md. Не объявлять весь C11 done/C12 ready.

C11 принят локально (bounded E1): handoffs/C11.md + evidence/C11-lifecycle-matrix.json.
Shared machinecred renewal, collector TLS hot reload/locks, agent host-binding/explicit legacy bind-host;
30unit/46PG/58fixtures,10agent/10collector race+clock/17Bao/8recovery/14browser passed.
44/200done;31migrations/42tables. Далее C12 CLI/config/metrics. Старые in_progress записи выше исторические.
Не обещать hardware clone detection, automatic expired reissue/24h/production/DR; matrix содержит пределы.

C12.01 готов локально: cmd/surveyscanctl +internal/usercli (только HTTP, existing session/CSRF API),
private context0600,JSON output,stable exitcodes; login/logout/assets/sources/status,2tenant isolation.
33unit/58fixtures и16live checks passed;45/200done. C12.02–04 planned, handoffs/C12.md.
C11 finalb22efa2, новая веткаcodex/v2-c12-cli. Session auth, не объявлять bearer/OS keychain/table output готовыми.

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

C13 продолжение2026-11-05:01–03 in_progress,04planned;48/200done. Release checkpointcc242c5,
PG checkpointb874302. Signed Ed25519 bundle/SHA256-size-mode/SPDX/verified staging14checks,
PG17dump→newemptyDB18checks(46table fingerprints+actualTLSlogin/card/write),отдельныйBaoRaftrestore9checks
(scopedKV/двеnonexportableTransit signatures/restart-unseal) passed. makeverify39unit/58fixtures.
HostPID1tail/QEMU-KVM-nspawn absent/cgroupdriver none: boot unrun. FullPG-Bao-filesystemcheckpoint,
liveupdate/previousschema upgrade/twoOS ещёunrun. Читатьhandoffs/C13.md; не закрыватьC13/не начинатьC14.
No push/merge/deploy/envpublication; privatebackup/custody неstageвgit. PG-only неsystembackupmarker.

R-020(2026-11-05) разрешает push накопленной работы текущей ветки, PR и hostedCI; prior no-push исторический.
Main merge/production deploy/env publication не поручены. Common PG/Bao/files checkpoint10 и actual
C11schema31→33 upgrade13 passed;39unit/58fixtures/50PG passed. C13.01–03IP/04planned,48/200done:
systemd boot/livecheckedupdate/two clean OS остаются gates. Handoff C13 содержит публикацию/точныеrefs.
Не загружать privatebackup/custody вgit илиActions artifacts (только явный sanitizedreport allowlist).

R-020 опубликован: draftPR4/codex/v2-c13-operations, hosted v2+Web SUCCESS на215f10c.
Точный evidence plans/surveyscan-v2/evidence/C13-hosted.json; финальный docs-only [skip ci] не меняет source.
C13boot/liveupdate/twoOS pending,48/200done; C14не начинать доC13acceptance. Mainне слит/deployне выполнялся.

C13 DONE boundedE1(2026-11-05): evidence/C13-runtime.json, handoffC13. TwofreshnativeDebian12/systemdVM9+9
actualkernelreboot/nonroot/LoadCredential/PGnotify/scopedBao/manualoperatorunseal/queues+UID/combinedupdate/CLI.
Updater19(compiledprivateDDL34/checkpoint/rollback/SIGKILL),40unit/50PG/58C03/release14. SQLunchanged.
52/200done. C14.01IP,24hsoaknotstarted; C14prompt explicitly nonblocking24h/persistentrecording, nofakepass.
R021 asksautonextpackagesuntilquota; source fixes uncommittedpendingpush, R020 stillauthorizesGitHubPR/CI.
07adce1hostedv2/Websuccess; latestnativeVM source notyetpublished. Main/deploy/envpublication notauthorized.

C14 checkpoint: .01 done53/200, reviewed15E1scenario matrix; .02runner/preflight ready, actual24h notstarted.
Finalpreflight121.597s≠24h; reconnect5actual3processes/onehost+quota+simultaneousreconnect passed.
41unit/58fixtures. C13 published8568927 allv2/Web/nativebootCI SUCCESS (SHA-specific evidence).
Readhandoffs/C14.md/deploy/SOAK.md. Start actualsoak detached aftercleanbuild; do notstopshareddevPG/Bao.
Only86400realelapsed+allgates cancloseC14; noC15/releaseacceptance based onshortpreflight.

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
