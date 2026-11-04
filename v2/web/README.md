# Отдельный Web UI (C09)

React19.3.1, TypeScript5.9.3, Vite8.3.5; Node24.22.1 нужен только для сборки.
TypeScript7 из C01 был кандидатом; openapi-typescript7.13.0 требует peer TypeScript5.x,
поэтому выбран поддерживаемый5.9.3, без force/legacy-peer-deps. Версии и integrity закреплены lockfile.

```sh
cd v2/web
npm ci --ignore-scripts --no-audit --no-fund
npm run generate
npm run build
```

Результат dist/ — независимый статический артефакт. Production Node/CDN не нужны.
Серверный Go-бинарник UI не содержит. Отдельный workflow .github/workflows/web.yml.
Типы генерируются из неизменённого C03 OpenAPI и отдельного C09/1.0; standalone validators из wire.schema на build step.
AJV не компилирует схемы в браузере, CSP не требует unsafe-eval. CSS/JS/font resources локальные.

Same-origin hosting: `/` и `/version.json` — web/dist, `/api/` — Go, `/contracts/` — server build contracts.
Dev compose теперь монтирует web/dist; перед dev.py up выполнить frontend build. HTTP dev только loopback,
production HTTPS/cookies/proxy настройки проходят C14. index/version не кешируются; hashes в bundle filenames.
Version manifest содержит frontend version, wire1.0 и SHA256 backend OpenAPI. UI проверяет размещённый
server contract до login и блокирует работу при несовместимости. Деплоить backend contracts вместе с API.

Готовы первый UI: login/logout, API response validation, tenant-bound assets/source lists, cursor pagination,
поиск/свежесть на текущей странице (это явно подписано), базовая карточка, responsible subject ID,
section statuses и отдельный источник/contact. Нет произвольного выбора tenant в frontend.
Credentials/csrf только в памяти и HttpOnly session cookie; localStorage/sessionStorage не используются.
При reload нужна повторная авторизация (C03 не имеет GET session); CSRF в браузерном storage не сохраняется.
Backend по-прежнему проверяет RBAC/tenant, UI не заменяет эту проверку. Backend errors не показываются raw.

C09 завершён локально: карточка читает базовые поля/IP/MAC/provenance/ответственность и времена
из одного RR snapshot нового C09/1.0 API. C03 сохранён. Source inventory summary обновляется через
sources-owned port, generation и heartbeat contact видны отдельно. Исторического backfill нет.
14 Chromium checks прошли с реальными auth/assets/detail/PG и strict CSP на800/1440;
partial/stale/unknown matrix отдельно mocked. CI build и live-api jobs созданы, hosted unrun.
Старый backend без C09 extension отклоняется до login; manifest проверяет оба OpenAPI hashes.
[Приёмка и пределы](../../docs/plans/surveyscan-v2/handoffs/C09.md).
