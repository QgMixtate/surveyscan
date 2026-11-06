# surveyscan — правила продолжения работы

## Начало чата

1. Прочитать актуальные GitHub AGENTS.md, docs/STATUS.md и последние docs/REQUESTS.md.
2. Прочитать CLAUDE.md как карту legacy-кода; сведения об окружении сверять с машиной.
3. Проверить remote/ветку/HEAD/dirty state, активные ветки/PR; origin/main без fetch
   может быть устаревшим. В main ещё нет всей работы активных draft PR.
4. Для v2 читать TASK_INDEX.md, текущий packages/Cxx.md и нужные spec sections,
   затем актуальный handoff/evidence. Не перечитывать весь WBS/архив каждый чат.
   Недоступную историю другого устройства не восстанавливать по догадкам.

## Журнал, доказательства, публикация

- Записывать существенные запросы и результаты в docs/REQUESTS.md: дата/ID/суть/
  статус/branch/SHA/PR/проверки/следующий шаг. STATUS.md держать кратким и актуальным.
- После значимого результата и перед передачей обновлять handoff, plan.json evidence,
  STATUS/REQUESTS. В долгой работе сохранять промежуточные checkpoints до лимита.
- Различать фактический прогон, чужое сообщение, mock/synthetic, план и unrun.
  Failed/pending/running не превращать в PASS; привязывать hosted runs к точному SHA.
- Не считать опубликованным до успешной записи в GitHub. Branch publication, main
  merge и production deployment — разные действия. Сохранять исторические failures.
- При чужих/параллельных изменениях перечитать файлы перед записью, сохранить чужие
  записи/заполненные evidence; не stage незавершённую работу другой задачи.
- Не публиковать credentials/private keys/raw inventory/backup/custody/VM serial/disks.
  Actions artifacts — только явный sanitized report allowlist.
- R020/022/023 и текущие поручения разрешают последовательную реализацию, push/PR/CI
  и автоматическое продолжение после проверок. Main merge, официальный release,
  production deploy и повторная публикация cloud settings не поручены. Старые no-push
  checkpoints исторические; обычные разрешённые шаги не требуют повторного вопроса.

## Архитектура v2

[Спецификация](docs/specifications/go-asset-management-v2.md), проект0.5,
не полностью утверждённое ТЗ. R011 приоритетнееR008: local/host agent — постоянная
минимальная служба→постоянный site collector; portable — разовый аудит без службы.
Безагентный SSH/WinRM/SNMP/network discovery выполняет collector, не каждый agent.

Реестр обновляется постоянно. Source health/heartbeat/freshness/presence/бизнес-состояние
различаются. OpenBao выбран. asset_uid неизменен, agent_id/collector_id — другие IDs;
relay не меняет origin. Observations immutable, assignments temporal, факты и ручные
business fields разделены. Outbox/событийность без внешней шины. Отдельный Web UI,
Go backend с ownership модулей и combined/api/worker ролями. FTS Tantivy/Bluge ещё
выбирается;100 activeusers — тестовый сценарий, не доказанный SLA. Первый SMB — E1;
enterprise HA/geo/shards не блокируют его, основы не терять. Волна2 ЖЦ/склад/запчасти/
движения, волна3 ITSM. Матрица замечаний — requirements-traceability-v0.5.md;
аналоги — docs/research/inventory-platform-analogues.md.

## Текущий этап и ограничения стенда

[План](docs/plans/surveyscan-v2/README.md):50пакетов/200подзадач. C01–C14 приняты
в bounded Linux E1; C15.01 design done, C15.02 in_progress;57/200done. Не увеличивать
счётчик без acceptance. C15.03/04 и C16+ ещё не приняты. Точный новый code/CI статус —
STATUS и [C15 handoff](docs/plans/surveyscan-v2/handoffs/C15.md), не архив checkpoints.

C15 worktree /workspace/surveyscan-c15, branch codex/v2-c15-windows, draftPR5 на базеE1
PR4. SQL catalog35/48ownedtables; applied0000–0034 immutable. New migration толькоappend;
обновлять schema/table/backup/boot expectations и сдвигать private update fixture.
Default inventory12_enabled false. C03/C09/C12 frozen; C15 partial12/schema/typed facts/
capabilities/relay не означают complete/deletion или готовую Windows-службу. Native
Windows2022/elevated ≠ ordinaryrights/Windows11/SCM/reboot. Следующие gates — Windows
profile1.2/state security/DACL/reparse/atomic files/locks/host continuity/service/coverage.

E1 worktree /workspace/surveyscan и его frozen24h/candidate/evidence не заменять новыми
C15 binaries. Actual24h закончен; running markers в архиве не означают текущий прогон
или новый временной запрет продолжения. Нового24h результата у C15 нет.

C15 и E1 могут разделять dev PostgreSQL55432/OpenBao58200/Composeproject, но local
password files могут различаться. Не запускать C15 dev up/down/reset/init/integration
вслепую. Локальные проверки используют существующий E1dev module дляcredentials,
C15 binaries, свои DB/ports/scopedmounts/processes и C15 report_directory. Не копировать
private keys/не перезаписывать E1 reports/не останавливать shared services без причины.

## Legacy v1

Правила snapshot/dashboard относятся к Python v1, не v2. UI/документы по-русски;
SPA — локальныеUMD безCDN. После app.jsx пересобирать app.js Babel runtime classic.
Карточки сохраняются в dashboardJSON, рабочая БД задачи удаляется после выполнения.
Секреты УЗ не попадают в логи/результаты/отчёты. Legacy v1/connector сохранять.

Полная прежняя история checkpoints перенесена без потерь в
[AGENTS_HISTORY.md](docs/plans/surveyscan-v2/AGENTS_HISTORY.md); читать только при
расследовании соответствующего старого этапа. HandoffTemplate — в plan directory.
