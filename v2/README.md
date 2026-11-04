# SurveyScan v2 — C06

Новый Go-каркас рядом с Python v1. Linux/amd64, Go **1.27.3**, Docker Engine + Compose v2,
Python 3.12+. PostgreSQL **17.11**, OpenBao **2.7.2**, nginx **1.30** закреплены digest в deploy/compose.yaml.
Зависимости Go закреплены go.mod/go.sum; автоматическое обновление toolchain не требуется.
Go дистрибутив проверен по SHA256 официального go.dev (linux-amd64:
`65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40`).
В облачной среде сохранять настроенные proxy/CA; в scratch-образ копируется только статический бинарник,
сетевых загрузок при Docker build нет. Docker CLI использует локальный socket; DOCKER_CONFIG сохраняется.

```bash
cd v2
python3 -m venv .contract-tools
.contract-tools/bin/pip install -r ../docs/plans/surveyscan-v2/contracts/C03/checks/requirements.txt
export GOTOOLCHAIN=local
make CONTRACT_PYTHON=.contract-tools/bin/python verify
make build
python3 scripts/dev.py up
make integration
python3 scripts/smoke.py
python3 scripts/dev.py status
python3 scripts/dev.py down
```

Если Go установлен отдельно, передать `make GO=/path/to/go` и соответствующий GOROOT/PATH.
При сохранённом старом GOROOT его надо заменить или убрать. Проверки импортов сами используют
текущий runtime.GOROOT. Integration без явного test DSN завершается ошибкой, не пропускает проверки.
Тесты создают случайные `ssv2test_*` БД в отдельном dev-кластере и удаляют только созданные ими БД.
У dev-роли есть CREATEDB для этих тестов; production-права/разделение migrator и app — дальнейшая работа.

Локальные адреса:

| Компонент | Адрес |
|---|---|
| backend | 127.0.0.1:58080, /health/live и /health/ready |
| отдельный proxy/UI origin | 127.0.0.1:58081; /contracts/openapi.json |
| PostgreSQL | 127.0.0.1:55432, БД и пользователь surveyscan_v2 |
| OpenBao | 127.0.0.1:58200 |

Все опубликованные порты привязаны к loopback. Это локальный HTTP-стенд, не production-конфигурация.
Proxy раздаёт JSON-контракты отдельно от Go; Web UI появится в C09. Продуктовые `/api/...`
требуют auth; auth и assets реализованы; прочие будущие handlers после проверки прав отвечают 501. `/` возвращает 404. OpenAPI описывает auth и будущие domain handlers. Agent/collector поддерживают только `version`;
попытка запуска сбора завершается кодом 2. Сервер поддерживает `serve`, `migrate`, `version`, `healthcheck`.
Combined composition root собирает модули; worker/API роли появятся вместе с реальными обработчиками.

`dev.py up` генерирует `.local/pg_password` и инициализирует обычный single-node OpenBao Raft.
Bootstrap/unseal материал остаётся в `.local/bao-init.json` (0600, каталог 0700); backend его не получает.
Это локальная схема с одним unseal share. Не использовать её для production, не коммитить/архивировать
`.local/`, не публиковать compose config/env или bootstrap responses. Backend проверяет только health Bao.
После перезапуска Bao выполнить `python3 scripts/dev.py unseal`; обычный `up` делает это автоматически.
Если том существует, а ключи потеряны, скрипт отказывается сбрасывать storage. Восстановить ключи из
собственной защищённой копии. `down` сохраняет pgdata/baodata. Не выполнять `down -v` для рабочих данных.
Если изменился пароль в файле, он не меняет автоматически пароль существующей PostgreSQL-роли.

25 forward-only миграций встроены в модули. Apply берёт PG advisory transaction lock, проверяет SHA256,
owner, известность и непрерывный prefix истории; весь pending batch выполняется одной транзакцией.
Повтор даёт 0; изменённую историю нужно расследовать, а не перезаписывать checksum. Rollback и
zero-downtime upgrades не заявлены. 32 domain/access tables + platform.schema_migrations.
SQL FK/guards читают несколько owner schemas ради C02 транзакционной целостности; записи будущих
handlers должны идти через владельцев/ports. Ограничения импортов проверяются тестом.

Наблюдение сохраняет canonical_payload, digest, origin key ID и 64 bytes signature по C03.
SQL проверяет digest и соответствие JSON, но **не** Ed25519, JCS canonicality и доверие ключу:
это выполняет Registry.Ingest C06. Нулевые synthetic signature в SQL integration tests не являются
проверкой подписи. Реализованы C05 auth и C06 registry/projector; нет RLS, публичного machine enrollment/transport, spool, collector runtime,
production TLS/PKI, backup/HA или готовности к 100 пользователям. C07 — следующий пакет.

CI: `.github/workflows/v2.yml`. Та же последовательность команд выполнена локально; C04 опубликован,
push-триггер отправлен, состояние GitHub Actions пока не подтверждено из-за запрета GitHub API. Smoke временно останавливает **только этот** dev Bao/PG,
проверяет live=200, ready=503, восстановление после старта/unseal и перезапуска backend.

## C05: пользователи и доступ

[Политика](../docs/plans/surveyscan-v2/decisions/C05-auth-policy.md),
[threat cases](../docs/plans/surveyscan-v2/decisions/C05-threat-cases.md).
Внутри compose уже задан origin `http://127.0.0.1:58081` и явный local HTTP opt-in.
Для обычной установки задать `SURVEYSCAN_V2_PUBLIC_ORIGIN=https://inventory.example`, без dev opt-in;
TLS завершается доверенным reverse proxy. Нельзя считать локальный HTTP production TLS.

Первого администратора создаёт **локальная консоль**; это требует привилегированного OS/DB доступа.
Подготовить свой password file 0600 (16–1024 bytes), не помещать пароль в argv или env.
Ниже путь `/secure/admin-password` — ваш существующий private file, UUID — ваш tenant ID:

```bash
# В shell задать DATABASE_URL и DATABASE_PASSWORD_FILE для нужной БД, как в deploy/compose.yaml.
.dist/surveyscan-server migrate
.dist/surveyscan-server bootstrap-admin --tenant YOUR-TENANT-UUID --tenant-name 'Организация' --username admin --password-file /secure/admin-password
.dist/surveyscan-server create-user --tenant YOUR-TENANT-UUID --username viewer --role viewer --password-file /secure/viewer-password
.dist/surveyscan-server set-user-state --tenant YOUR-TENANT-UUID --username viewer --role viewer --enabled=false
.dist/surveyscan-server reset-password --tenant YOUR-TENANT-UUID --username admin --password-file /secure/new-password
```

В текущем cloud dev shell для доступа к отдельному кластеру:

```bash
export SURVEYSCAN_V2_DATABASE_URL='postgres://surveyscan_v2@127.0.0.1:55432/surveyscan_v2?sslmode=disable'
export SURVEYSCAN_V2_DATABASE_PASSWORD_FILE="$PWD/.local/pg_password"
```

POST `/api/v1/auth/sessions` принимает C03 LoginRequest и точный Origin; возвращает Session и cookie.
DELETE `/api/v1/auth/session` требует cookie/Origin/X-CSRF-Token и отзывает session.
POST `/api/v1/auth/tokens` выдаёт read-only scoped token по cookie/CSRF;
DELETE `/api/v1/auth/tokens/{token_id}` отзывает свой token. Bearer token не заменяет cookie при выдаче.
Username уникален глобально; один user принадлежит одному tenant. Правила ролей/expiry/reset — в policy.
Production cookie Secure/HttpOnly/SameSite=Strict. Все session/token secrets в БД хешированы;
raw token и CSRF из ответов надо защищать на клиенте, не копировать в отчёты/логи.

```bash
# После make build и dev.py up: новая временная БД, настоящий CLI/HTTP и restart процесса.
python3 scripts/auth_smoke.py
```

Скрипт не создаёт постоянного пользователя в рабочей dev-БД; временный пароль и собственную test DB
удаляет после прогона. `integration` дополнительно использует HTTPS test server и проверяет
expiry, revocation, roles, tenant context, concurrent bootstrap/sessions/tokens и commit fencing.
Hosted CI остаётся неподтверждённым до доступа к GitHub API; публикация ветки не равна CI success.

## C06: реестр и outbox

GET/list/PATCH `/api/v1/assets` реализованы по C03; остальные future handlers остаются fail-closed.
[Политика](../docs/plans/surveyscan-v2/decisions/C06-registry.md), [передача](../docs/plans/surveyscan-v2/handoffs/C06.md).
Внутренний Registry.Ingest проверяет source binding и настоящую C03 Ed25519 подпись; публичный machine
transport/enrollment — C07. IP/MAC сохраняются в current_facts; C03 Asset публично отдаёт hostname/OS/statuses.
Combined server обрабатывает PG outbox consumer registry-version каждые 2s без внешней шины.
Новые guards отклоняют asset/fact/business mutation без history/outbox/audit в той же transaction.
C04/C05 SQL не редактировать, данные не сбрасывать. Default dev compose project name сохранён ради volumes.

## C07: collector и machine transport

27 forward-only migrations, 36 domain/access tables. [Передача](../docs/plans/surveyscan-v2/handoffs/C07.md),
[политика TLS/ACK](../docs/plans/surveyscan-v2/decisions/C07-collector.md).
`surveyscan-collector run --config /secure/collector.json` запускает HTTPS relay и durable spool.
Центр включает machine TLS только через `SURVEYSCAN_V2_MACHINE_CONFIG=/secure/machine.json` (dev loopback).
Формат private configs и полный воспроизводимый запуск — `scripts/machine_smoke.py`:
запускать Python из contract venv после make build/dev.py up. Скрипт создаёт временную БД/PKI и удаляет их.
Заранее доверенный CA проверяется всегда; ключ подписания ACK аттестован CA в identity certificate.
Частные ключи/конфиги 0600, spool0700; не включать в Git или CI artifacts. Production Bao issuer — C11.
Heartbeat, live host agent и automatic enrollment client — C08; production recovery/quota hardening — C10.

## C08: постоянный Linux host agent

28 migrations/38 domain/access tables. `surveyscan-agent prepare/enroll/run --config PRIVATE_FILE`.
[Регистрация и конфиг](internal/agent/README.md), [передача](../docs/plans/surveyscan-v2/handoffs/C08.md).
Настоящие hostname/OS/IP/MAC, origin signature, mTLS к назначенному collector; отдельный fresh-challenge
heartbeat. Pending spool удаляется только после проверки center ACK, counters переживают restart.
Для приёмки: contract Python `scripts/agent_smoke.py` (три автоматических60s цикла + restart,
три compiled binaries, настоящий хост и временный PG). Отчёт не содержит host facts или keys.
Systemd template deploy/surveyscan-agent.service подготовлен; установка/24h/production ещё не проверены.

## C09: отдельный Web UI

[Сборка](web/README.md), [передача](../docs/plans/surveyscan-v2/handoffs/C09.md).
`cd web && npm ci --ignore-scripts --no-audit --no-fund && npm run generate && npm run build`.
Dev edge58081 отдаёт независимый production bundle со strict CSP; Node/CDN в runtime не нужны.
Новый GET /api/v1/assets/{asset_uid}/inventory (C09/1.0) читает card/IP/MAC/provenance/ответственность/
section times/source summary в одном RR snapshot. UI проверяет C03+C09 contract hashes; C03 неизменён.
29 migrations/39 domain/access tables.14 Chromium/37 PG integration checks passed локально;
hosted CI unrun. Следующий C10 — durability/quota/recovery hardening.
