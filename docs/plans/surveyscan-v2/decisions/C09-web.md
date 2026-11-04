# C09 — независимый Web UI и inventory detail API

2026-11-04. React19.3.1/TS5.9.3/Vite8.3.5, Node24.22.1 только build.
TS7 кандидат C01 заменён из-за peer requirement openapi-typescript7.13.0; force не используется.
Версии/integrity в lockfile, UI отдельный dist и pipeline, Go не содержит SPA. Статика same-origin,
строгий CSP без unsafe-eval/CDN, JSON validators компилируются заранее, session secrets в памяти/cookie.
После истечения/смены сессии очищаются selected card/tenant cache; logout реально отзывает session.

Контракт C03 сохранён byte-for-byte. Новое GET /api/v1/assets/{asset_uid}/inventory описано
в отдельных c09.openapi.json/c09.schema.json (C09/1.0). Базовая карточка, ответственность,
current facts и per-section attempt/success читаются в одном RepeatableRead snapshot с повторным
assets:read/tenant authorization. Чужой/неизвестный asset404. Subject name отдаёт responsibility owner;
contact/email subject не выдаются. Inventory owner возвращает facts/evidence; sources owner — summaries.
Source metadata доступна только для origin этого asset в рамках assets:read, никаких keys/certificates.

Каждый fact содержит observation/source/generation/exact sequence/section collected_at/clock_quality.
Normalized network facts дают interface/IP/MAC; failed/partial сбор не подменяет происхождение сохранённых
фактов. Attempt/success раздельны. Payload подписанного observation и origin/center keys не выдаются.
Detail ограничен2048 facts и2054 sources; wire payload≤1MiB. Большую enterprise card надо пагинировать
в отдельном API revision, не отдавать обрезанный результат. C35 throughput/scale ещё не проверялся.

Sources.inventory_progress — отдельная source-owned таблица (migration0028, всего29/39 domain tables).
Registry вызывает source port внутри той же write transaction. Только trusted/full/complete requested
sections, без future>5min; not_requested не считается failure. Success marker=максимум collected_at
section, не delivery time; точный replay не обновляет marker, старое наблюдение не продвигает время.
Source summary generation-scoped; heartbeat не меняет inventory_progress. Данные до migration не
backfill-ятся автоматически; до следующего полного inventory источник может показывать unknown.

Contact policy1: recently_seen — подтверждённый server heartbeat≤180s, stale — более старый,
unknown — контакт не подтверждён. Registered/revoked state показывается отдельно. Это freshness
источника, не asset presence и не полнота inventory. Portable без heartbeat обычно contact unknown.

UI build manifest проверяет SHA256 base OpenAPI и отдельного C09 OpenAPI до login. Поддерживаемая
пара: этот UI с API C03+C09/1.0; старый API без extension отклоняется явно. Same matching contracts
позволяют независимо обновлять UI/backend. Это узкая проверенная матрица, не обещание N-1 API support.

Реестр использует server cursor pagination; поиск/фильтр свежести явно ограничен текущей страницей.
Полнотекстовый поиск/глобальные query filters реализуются последующими пакетами. Card read-only;
editing/assignment workflows не подменяются декоративными кнопками. Reload требует login: C03 не имеет
GET session, credentials/CSRF не сохраняются в localStorage ради восстановления.

Приёмка: real compiled source→collector→PG и Chromium с реальным auth/list/detail/logout,
strict CSP, responsive800/1440, keyboard/focus, session revocation/cache cleanup, version mismatch.
Partial/stale/unknown matrix проверяется отдельно явно mocked fixtures; это не live source evidence.
Separate web.yml build artifact + live-api job; hosted runs unrun до publication.
