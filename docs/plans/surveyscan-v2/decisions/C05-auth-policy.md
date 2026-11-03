# C05 — политика локальной аутентификации E1

Основание: C01 D-09, C03 wire 1.0 и R-017. Локальная реализация C05; OIDC/MFA и machine PKI сюда не входят.

## Bootstrap и администрирование

Первый admin создаётся отдельной локальной командой `bootstrap-admin`. Общих заводских паролей нет.
Пароль читается из regular file 0600, 16–1024 bytes UTF-8; в argv/environment/plaintext DB его нет.
Одноразовый bootstrap защищён общей PG advisory transaction lock и singleton state.
Пользователь/tenant/credential metadata и security events принадлежат access. OpenBao остаётся
обязательным для секретов целевых устройств; PostgreSQL хранит только пользовательские хеши,
метаданные и хеши случайных session/API credentials.

`create-user`, `set-user-state`, `reset-password` — доверенная локальная administrative console,
требующая доступа ОС к конфигурации БД. Это не удалённый публичный API и не обход пользовательских
прав через API. Запуски требуют явных tenant/username, пароль — из private file. Console может
восстановить доступ после отключения последнего admin. Отдельный network user-management UI позже.

C03 LoginRequest не содержит tenant, поэтому E1 username уникален глобально, ASCII lowercase,
1–128 `[a-z0-9_.@-]`. У пользователя один tenant и одна из ролей admin/operator/viewer.
Множественное членство и federation требуют отдельного контракта. Tenant из body/header не выбирается.

## Пароли и сессии

Argon2id v19: memory 65536 KiB, iterations 3, parallelism 1, salt 16 bytes, result 32 bytes.
Параметры закреплены version tag в БД; хеширование выполняет golang.org/x/crypto v0.58.0.
Локально проверены настоящий login/reset, случайные соли, concurrency и длительность; это не
нагрузочный SLO для 100 пользователей. Одновременно максимум 2 вычисления Argon2id на процесс.

Неверный пароль, неизвестный username, disabled user/tenant дают одинаковую безопасную 401.
Для неизвестного допустимого username выполняется dummy Argon2id. Shared PG rate limit:
120 login attempts/min globally, 10/min на SHA256 нормализованного username; fixed minute windows.
Два процесса используют общие счётчики. X-Forwarded-For не доверяется. Неактивные bucket удаляются;
сообщение 429 не раскрывает наличие пользователя. Redis/broker не требуется.

Session secret и CSRF nonce — независимые 32 bytes CSPRNG, в PG только SHA256. Cookie
`surveyscan_session`: HttpOnly, Secure, SameSite=Strict, Path=/, без Domain, absolute expiry 8h.
Не более 5 активных sessions/user/revision. Повторный login создаёт новый ID, не принимает client ID.
Logout отзывает только текущую session, не независимые CLI tokens. Role/enable/password changes
увеличивают user revision: все старые sessions и CLI tokens немедленно перестают проходить проверку.
Password reset — через доверенную console, без общего reset token и без автоматического password age.

## HTTP и CLI tokens

`PUBLIC_ORIGIN` обязателен: точный origin для login и cookie mutations. Default требует HTTPS.
`INSECURE_LOCAL_HTTP=1` разрешает только localhost/127.0.0.1/::1 origin для loopback dev-стенда.
Proxy TLS termination допустим; клиентские identity/forwarded headers не становятся principal.
Нет wildcard CORS. Изменяющий cookie request требует точного Origin и session-bound X-CSRF-Token;
пустые/чужие/дублированные headers отвергаются. Все ответы API содержат no-store.

JSON body ограничен 8 KiB, unknown fields/trailing values отвергаются. Auth requests имеют 5s deadline,
DB connections — 3s timeout, pool — 8 connections. Ошибки содержат безопасные code/message/request_id/details,
без DSN/SQL/password/credential. Полученный session/CSRF/token — секрет для клиента; не логировать response.

CLI token выдаётся только действующей cookie session + CSRF. В PG только SHA256; raw token возвращается
один раз. Expiry 60–86400s, максимум 10 active tokens/user/revision. Scopes строго `assets:read`
и/или `sources:read`; даже admin token не получает write/admin rights. Имя и secret не помещаются в URL.
Отозвать можно только собственный token в том же tenant; чужой/несуществующий ID даёт одинаковую 404.
Cookie и Authorization одновременно, повторные cookie/Authorization и session secret как bearer отвергаются.

## Авторизация и транзакции

Viewer читает; operator также меняет asset business fields и jobs; admin также выполняет source admin.
Все human C03 routes имеют явную policy в composition root; неизвестный operation без policy блокирует
сборку HTTP router. Machine endpoints пока fail-closed 401 до mTLS implementation, не принимают user session.
Future domain handler после успешной human auth возвращает 501, не фальшивые данные/успех.

`access/port.Authorizer` — общий контракт API/workers/artifacts. При записи надо повторно вызвать
Authorize внутри **той же PG transaction** с серверной credential reference и tenant, затем сделать
доменную запись и commit. Общий порядок блокировок — user → credential, после ожидания identity проверяется снова.
FOR SHARE locks credential/user/tenant удерживаются до конца transaction;
отзыв/смена роли не могут незаметно пересечь проверенную транзакцию. Credential ID сам по себе не
публичный bearer credential. Его provenance в будущем job context должна происходить от проверенного
principal, а не произвольного пользовательского body. При долгом выполнении проверять снова перед commit.

В C05 нет jobs/artifact runtime и реестра; их wiring/data-query scopes проверять в C06/C07/C10.
Нет RLS, production split app/migrator roles или публичного создания пользователей. Security events
фиксируют успешные выдачи/отзывы/reset/change без secrets; failed login отражён rate counters,
полная observability/retention и аудит доменных операций — последующие пакеты.
