# SurveyScan v2 — C04

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
Proxy раздаёт JSON-контракты отдельно от Go; Web UI появится в C09. `/` и продуктовые `/api/...` пока
возвращают 404. OpenAPI описывает будущие handlers. Agent/collector поддерживают только `version`;
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

18 forward-only миграций встроены в модули. Apply берёт PG advisory transaction lock, проверяет SHA256,
owner, известность и непрерывный prefix истории; весь pending batch выполняется одной транзакцией.
Повтор даёт 0; изменённую историю нужно расследовать, а не перезаписывать checksum. Rollback и
zero-downtime upgrades не заявлены. 24 доменные таблицы C02 + platform.schema_migrations.
SQL FK/guards читают несколько owner schemas ради C02 транзакционной целостности; записи будущих
handlers должны идти через владельцев/ports. Ограничения импортов проверяются тестом.

Наблюдение сохраняет canonical_payload, digest, origin key ID и 64 bytes signature по C03.
SQL проверяет digest и соответствие JSON, но **не** Ed25519, JCS canonicality и доверие ключу:
это обязанности будущего ingestion. Нулевые synthetic signature в SQL integration tests не являются
проверкой подписи. Нет RLS/auth/enrollment, inventory handlers, projector, spool, collector runtime,
production TLS/PKI, backup/HA или готовности к 100 пользователям. C05 — следующий пакет.

CI: `.github/workflows/v2.yml`. Та же последовательность команд выполнена локально; GitHub Actions
появится после публикации и пока не запускался. Smoke временно останавливает **только этот** dev Bao/PG,
проверяет live=200, ready=503, восстановление после старта/unseal и перезапуска backend.
