# SurveyScan v2 — постоянная инвентаризация E1

Go host agent периодически собирает сведения своего Linux-хоста и отправляет их площадочному
collector. Collector сохраняет пакеты и доставляет их combined server; постоянный реестр,
история, ответственность и outbox находятся в PostgreSQL. Секретные операции выполняет OpenBao.
Отдельный статический Web UI и `surveyscanctl` работают через API.

C01–C14 приняты (первый рабочий SMB-контур на Linux, эпоха E1). Написаны и проверены, но ещё не приняты: агенты Windows/Linux
с профилем инвентаризации 1.2, SSH/WinRM/SNMPv3, discovery/presence, схема сети L3, portable-аудит с HTTPS-загрузкой,
сведение источников по сильным идентификаторам (C15–C25.01). Актуальный статус — [STATUS](../docs/STATUS.md),
журнал — [REQUESTS](../docs/REQUESTS.md), передача — [handoff-3](../docs/plans/surveyscan-v2/handoffs/C15-C24-session-handoff-3.md).

## Сборка и локальный dev-стенд

Проверенный build target — Linux/amd64, Go1.27.3, Node24/npm11, Python3.12+ и Docker/Compose v2.
В compose закреплены PostgreSQL17.11, OpenBao2.7.2 и nginx1.30 с digest.
Go dependencies закреплены go.mod/go.sum; Web — package-lock.json. Runtime Go/static Web
не требует Go compiler или Node. Python3/OpenSSL3 нужны для operator release/update/backup tools.
В managed cloud сохранять настроенные proxy/CA и Docker credentials; использовать локальный daemon.

Команды для **отдельного** dev-стенда, без уже идущей приёмки:

```sh
cd v2
python3 -m venv .contract-tools
.contract-tools/bin/pip install -r ../docs/plans/surveyscan-v2/contracts/C03/checks/requirements.txt
export GOTOOLCHAIN=local
make verify CONTRACT_PYTHON=.contract-tools/bin/python
(cd web && npm ci --ignore-scripts --no-audit --no-fund && npm run build)
make build
python3 scripts/dev.py up
make integration
```

Для отдельной установки Go передать `make GO=/path/to/go` и соответствующий GOROOT/PATH.
Import guards используют текущий `runtime.GOROOT`. Dev role имеет CREATEDB для временных тестовых
БД; разделение production migrator/app privileges не проверено как production hardening.
`dev.py status` показывает контейнеры. `dev.py down` сохраняет named volumes, но прерывает работающий
стенд/прогон. Не применять `down --volumes`, не сбрасывать state и Bao ради устранения ошибки.

| Компонент | Локальный адрес |
|---|---|
| backend HTTP health/API | 127.0.0.1:58080 |
| отдельный Web/API edge | http://127.0.0.1:58081 |
| PostgreSQL | 127.0.0.1:55432, surveyscan_v2 |
| OpenBao | 127.0.0.1:58200 |

Порты привязаны к loopback; это development HTTP, не production TLS. `dev.py up` создаёт
private `.local/pg_password` и инициализирует single-node Bao Raft. Bootstrap/unseal material
остаётся в `.local/bao-init.json` (0600, parent0700), backend его не получает. После cold Bao restart
нужно операторское unseal; dev-команда `dev.py unseal` использует только локальный test custody.
При существующем томе и утраченных ключах восстанавливать собственную защищённую копию,
не создавать новое хранилище. `.local`, identities, contexts, spools и backups не включать в Git/artifacts.

## Пользователи, агент и CLI

Заводского пароля нет. Первого администратора создаёт локальная операторская консоль с доступом
к нужной БД. Пароль передаётся отдельным private file0600 (16–1024bytes), не значением argv/env.
Ниже UUID/path — значения вашей установки, DATABASE_URL содержит только параметры подключения:

```sh
.dist/surveyscan-server migrate
.dist/surveyscan-server bootstrap-admin --tenant YOUR-TENANT-UUID --tenant-name 'Организация' --username admin --password-file /secure/admin-password
.dist/surveyscan-server create-user --tenant YOUR-TENANT-UUID --username viewer --role viewer --password-file /secure/viewer-password
```

Server получает `SURVEYSCAN_V2_DATABASE_URL`, `SURVEYSCAN_V2_DATABASE_PASSWORD_FILE`,
`SURVEYSCAN_V2_PUBLIC_ORIGIN`; machine listener — явный `SURVEYSCAN_V2_MACHINE_CONFIG`.
Для HTTPS установки без dev opt-in нужен доверенный TLS edge и правильный public origin.
[Auth policy](../docs/plans/surveyscan-v2/decisions/C05-auth-policy.md): роли/tenant/CSRF/Origin,
PG-backed sessions и read-only scoped tokens; backend проверяет права при каждом write commit.

Host agent: `surveyscan-agent prepare/enroll/run --config PRIVATE_FILE`.
Он собирает hostname/OS/IP/MAC read-only, подписывает observations; machine/source IDs не заменяют
asset UID. [Agent config/enrollment](internal/agent/README.md). Collector:
`surveyscan-collector run --config PRIVATE_FILE`. Site/scope/fallback team и source binding
оператор готовит до enrollment; production provisioning wizard пока не поставляется.
`machine_smoke.py` и native boot stand показывают полное синтетическое provisioning для теста.
CA/pins и назначенный collector проверяются, TLS private keys и state не входят в golden image.

[Human CLI](internal/usercli/README.md) поддерживает login/context/logout, assets/sources/status,
profiles get/set, diagnostics/local-status, JSON/таблицы и стабильные exit codes. Context0600
содержит session cookie/CSRF; это private file. CLI не подключается к PostgreSQL или Bao.
[Web UI](web/README.md) поставляется отдельно, проверяет C03/C09/C12 compatibility hashes,
показывает inventory/provenance/section attempt-success/ответственность и source health отдельно.
Фильтр текущей страницы не называется full-text search; CDN/Node в Web runtime не нужны.

## Надёжность, данные и эксплуатация

Agent/collector хранят durable spool и независимые counters. Transport receipt не разрешает
удаление пакета; для этого проверяется подписанный результат центрального commit.
Retry/backoff/jitter и квоты ограничены, pending не вытесняется ради нового сбора.
[Spool policy](../docs/plans/surveyscan-v2/decisions/C10-spool.md),
[runbook](../docs/plans/surveyscan-v2/decisions/C10-operations.md),
[profiles](../docs/plans/surveyscan-v2/decisions/C12-profiles.md),
[diagnostics](../docs/plans/surveyscan-v2/decisions/C12-diagnostics.md).
Bao использует scoped policies и неэкспортируемые Transit keys; root/unseal material не принадлежит app.
Machine leaf renewal проверяется вместе с bounded clone/revoke/expiry сценариями; одинаковые
machine-id+private keys не позволяют аппаратную аттестацию. Expired identity fails closed;
automatic expired reissue/admin recovery не поставляются как готовая функция.

33 forward-only SQL migrations встроены в owner modules;45 domain/access tables плюс ledger.
Apply проверяет advisory lock, owner/SHA256/prefix; pending batch транзакционен, repeat даёт0.
Применённые SQL и C03 bytes не менять. SQL guards удерживают history/audit/outbox/assignment;
Ed25519/JCS/source trust дополнительно проверяются на ingest, не одной SQL checksum.
История observations неизменяема; ручные business fields не затираются inventory.
Outbox работает в PG без внешней шины; heartbeat/contact не выдаются за успешный inventory.
Architecture tests сохраняют import/contract guards и проверяют ownership SQL/client boundaries.

[Systemd install path](deploy/systemd/README.md), [release](deploy/RELEASE.md),
[checked update/recovery](deploy/UPDATE.md), [backup/restore](deploy/BACKUP.md),
[native boot stand](deploy/bootstand/README.md), [суточный прогон](deploy/SOAK.md).
Operator supplies PG/Bao/TLS/custody/static edge. Проверенный native target — Debian12/amd64/systemd252;
два fresh VM прошли реальный reboot/autostart/nonroot/LoadCredential/manual unseal/combined update.
Staging не устанавливает службы на managed host. Rollback после несовместимой SQL миграции запрещён;
нужны verified checkpoint, совместимая схема и явный recovery. Backup одной PG не равен общему checkpoint.

## Проверки и границы E1

`make verify`: formatting/vet/обычные Go tests/C03 fixtures. `make integration`: реальные временные PG DB,
изолированные тесты auth/registry/leases/profiles; отсутствие test DSN — ошибка, не скрытый skip.
`agent_smoke.py`, `recovery_smoke.py`, `reconnect_smoke.py`, Bao/renewal/CLI/profile scripts проверяют
конкретные live/process сценарии. `web_smoke.py` использует Chromium: auth/assets/profiles реальны,
partial/stale/unknown display matrix содержит явно mocked API responses. Host facts/keys не публикуются.
`smoke.py` и Bao outage tests могут останавливать общие dev services: не выполнять их параллельно soak.

Hosted workflows: `.github/workflows/v2.yml`, `web.yml`, `boot.yml`.
Точные SHA/run IDs/results находятся в [evidence](../docs/plans/surveyscan-v2/evidence/),
а не выводятся из одного факта push. [План](../docs/plans/surveyscan-v2/README.md):50 пакетов/200 задач.
C14 требует ≥24 реальных часов, фактических отказов/recovery и всех применимых E1 критериев.

Пока не приняты C14/SMB release; не доказаны100 users/SLA/production KMS/HA/geo/physical power loss.
Windows/agentless/discovery/topology/portable — E2; merge/split/full-text Tantivy/Bluge/100users — E3;
независимые production API/worker/шарды/geo — E5. Волна2 — ЖЦ/склад/запчасти, волна3 — ITSM.
Combined E1 и подготовленные module ports не означают принятую multi-process эквивалентность.
