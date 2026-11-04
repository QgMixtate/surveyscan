# Отдельный Web UI (C09 в работе)

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
Типы генерируются из неизменённого C03 OpenAPI; standalone validators из wire.schema на build step.
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

Ещё не завершено C09.03/04: versioned IP/MAC/provenance API, человекочитаемая ответственная команда,
source inventory summary, окончательная browser/live API приёмка нового shape.
Текущие13 Chromium checks прошли с real auth/assets/PG,800/1440,keyboard/version mismatch;
partial/stale/unknown matrix проверена отдельно на явно подменённых fixtures. Не объявлять C09 done.
Новый schema/API shape должен быть отдельным расширением; C03 corpus не редактировать задним числом.
Текущий read-only UI не выдаёт registration state за online; heartbeat не подтверждает свежесть inventory.
