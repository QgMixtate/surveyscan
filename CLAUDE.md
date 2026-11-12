# surveyscan — память проекта для Claude Code

Читается автоматически при старте сессии. Держать кратким: карта и указатели, не дамп кода.
Правила продолжения работы, журнал и границы — в [AGENTS.md](AGENTS.md); состояние — docs/STATUS.md, docs/REQUESTS.md.

## Что это
SurveyScan v2 — постоянная инвентаризация и реестр ИТ-активов на Go (`v2/`). Legacy v1 (Python) выведен из основной линии;
код — в истории git (bd26e78), ветка legacy/v1 удалена, перенос данных не нужен (C32 — not_required).

## Карта `v2/`
- `cmd/` — бинарники: surveyscan-server (центр, консоль migrate/bootstrap-admin/portable-*), surveyscan-collector,
  surveyscan-agent (Linux systemd / Windows SCM; run12, run-ssh12, run-winrm12), surveyscan-portable, surveyscanctl, ssh-probe, winrm-probe.
- `internal/app` — композиция: HTTP API, приём наблюдений (registry.go), карточка, факты 1.2, схема сети (topology_http.go), portable.
- `internal/modules/{access,sources,assets,inventory,responsibility,scope,audit,imports}` — модули со своими схемами БД
  (`schema/NNNN_*.sql`, только дописывать); границы проверяет `internal/architecture`.
- `internal/platform/*` — wire-контракты, PKI, outbox, миграции, diskspool, winstate; `internal/remote/*` — SSH/WinRM/SNMP;
  `internal/topology`, `discovery`, `presence`, `portable`, `portableaudit`, `agent`, `collector`, `usercli`.
- `contracts/` — JSON Schema/OpenAPI (C03 wire, C09, C12, C15, C22); `web/` — отдельный SPA (React+TS, без CDN; генерация `npm run generate`).
- `scripts/` — dev-стенд (`dev.py up`), smoke-сценарии CI, `vm_center.py` (центр стенда, `--persistent`), `demo_stand.py`.

## Команды
- Сборка: `cd v2 && make build`; проверки контрактов: `make verify CONTRACT_PYTHON=.contract-tools/bin/python`.
- Unit: `go test ./...`; integration: `SURVEYSCAN_TEST_DATABASE_URL=postgres://… go test -tags integration ./internal/app`
  (или `make integration` на dev-стенде).
- Web: `cd v2/web && npm ci && npm run generate && npm run build` — после правки контрактов обязательно `generate`.
- Полный CI — шаги `.github/workflows/v2.yml`.

## Готчи
- Секреты (grant, токены, пароли, ключи) не попадают в git, логи, отчёты и чат.
- Миграции 0000+ неизменяемы: новая — только следующим номером; сдвигать приватную фикстуру update_smoke.
- Контракт C03 заморожен: новые типы событий/поля — только через решение пользователя.
- В облачной песочнице docker и PostgreSQL могут пропасть после перезапуска окружения: `dockerd &`, `python3 scripts/dev.py up`.
- Ответы API проверяются в браузере по валидаторам из контрактов: после изменения схем — `npm run generate` (проверяется CI).
