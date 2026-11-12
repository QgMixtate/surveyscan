# surveyscan — правила продолжения работы

## Начало чата

1. Прочитать актуальные GitHub AGENTS.md, docs/STATUS.md и последние docs/REQUESTS.md.
2. Прочитать CLAUDE.md как карту кода v2; сведения об окружении сверять с машиной.
3. Проверить remote/ветку/HEAD/dirty state. С 2026-11-11 ветки: `develop` — рабочая (все коммиты),
   `main` — проверенное состояние, обновляется только fast-forward с develop после проверок;
   `archive/*` — замороженные ветки прежних сессий. Старые codex-ветки и их PR закрыты.
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

## Текущий этап

[План](docs/plans/surveyscan-v2/README.md): 50 пакетов / 200 подзадач. Принято 57/200 (C01–C14, C15.01);
счётчик и статусы пакетов меняет только пользователь при приёмке. Код C15–C23 и C25.01 написан, не принят.
Актуальное состояние — [docs/STATUS.md](docs/STATUS.md), передача — актуальный handoff в docs/plans/surveyscan-v2/handoffs/.

Инварианты: миграции 0000+ неизменяемы, новая — только следующим номером (сдвигать приватную фикстуру update_smoke);
C03/C09/C12 контракты заморожены; inventory12_enabled по умолчанию false; живые проверки стенда (ВМ пользователя)
различать с песочницей и CI; стенд — vm_center.py (--persistent), см. runbook C15-vm-stand-runbook.md.
Прежние ограничения worktree /workspace/surveyscan(-c15) эпохи Codex — в AGENTS_HISTORY.md.

## Legacy v1

С 2026-11-11 (решение пользователя) v1 (Python) удалён из основной линии; код — в истории git (bd26e78),
ветка `legacy/v1` удалена 2026-11-12. Не восстанавливать v1 без поручения; перенос его данных не нужен (C32 — not_required). UI/документы по-русски.

Полная прежняя история checkpoints перенесена без потерь в
[AGENTS_HISTORY.md](docs/plans/surveyscan-v2/AGENTS_HISTORY.md); читать только при
расследовании соответствующего старого этапа. HandoffTemplate — в plan directory.
