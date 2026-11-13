# C01: решения первого релиза и границы ADR

Дата: 2026-11-03. Вход: [baseline](C01-baseline.json), [E1 scope](C01-smb-scope.md), D-01–18 спеки 0.5.

## Статусы и полномочия

`user-confirmed` — прямо задано пользователем. `proposed` — конкретный инженерный default,
подготовленный для следующих пакетов, а не приписанное пользователю согласование.
`blocked` — для указанной функции нет необходимого решения/доступа.
Предложенные ниже варианты можно использовать для дальнейшего проектирования C02/C03;
до реализации в соответствующем пакете проверяются совместимость, безопасность и ограничения.
Общее «по плану» разрешает поэтапную работу, а не означает одобрение каждой версии/ADR или production deploy.

## Выбранное направление

| ID | Статус | Решение / аргумент | Где закрывается остаток |
|---|---|---|---|
| D-01 | proposed | E1 — технический реестр активов; CI/service/финансовый учёт не блокируют цикл | Полная трактовка CMDB и ER — C25/C26 |
| D-03 | user-confirmed + proposed detail | Server/collector/agent — Go, без Python runtime. E1 native read-only host APIs; shell и remote scripts в минимальном агенте не нужны | Правила remote scripts/Nmap — C17–C20 |
| D-06 | proposed | Server/dev Linux/amd64 Debian 13; agent OS остаётся предложением до C08 | Runtime pinning/чистые сборки C04, подтверждённая platform matrix C13–C24 |
| D-07 | user-confirmed | Постоянный host agent → постоянный collector; portable — разовый аудит | Первый agent OS до C08; язык/упаковка portable — C23 |
| D-09 | user-confirmed + proposed detail | OpenBao обязателен; user login E1 — локальная учётная запись и серверная session; machine access — mTLS | Auth/threat/PKI wire details C03/C05/C11 |
| D-11 | user-confirmed + proposed detail | Canonical UUID asset_uid, отдельно source/agent/collector IDs; локальные source IDs отображаются на asset | ER/namespace и минимальные правила C02; merge/split C25 |
| D-14 | user-confirmed + proposed detail | С первого asset есть ответственная команда разбора tenant/site; нельзя оставить бесхозный asset | Таблицы/guards C02/C06; person/team workflows C27 |
| D-16 | user-confirmed + proposed detail | UI отдельным артефактом через OpenAPI; React + TypeScript + Vite, без обязательного CDN | Конкретный frontend lockfile и UI/API matrix C09 |
| D-17 | user-confirmed + proposed detail | Ownership модулей; combined в E1, api/worker совместимы по контрактам; новое дерево v2/ | ER/ownership C02, Go module/layout C04, production split C35 |

## Runtime и зависимости: конкретные кандидаты

| Компонент | Инженерный default | Доказательство / предел проверки |
|---|---|---|
| Go | 1.27.3, GOTOOLCHAIN=local в воспроизводимой сборке | Официальный go.dev/dl metadata: stable и SHA256; архив не скачан/не исполнен. C04 проверяет checksum и сборку |
| PostgreSQL | 17.x; 17.11 имеется в текущем dev-окружении | Это выбор семейства и наблюдаемая установка v1, не проверка нового Go driver; C04 фиксирует актуальный patch/image digest |
| OpenBao | 2.7.2 как версия-кандидат | Официальный stable tag v2.7.2 существует; подпись/совместимость/артефакт ещё не проверены. C04/C11 pin и проверка |
| Agent/collector spool | bbolt, кандидат 1.5.0; транзакционная pure-Go очередь, один writer на файл | Stable tag v1.5.0; crash/durability/resource tests C10. Shared network DB file запрещён |
| Server jobs/outbox | PostgreSQL, ограниченный claim/lease/checkpoint | Без Redis/Kafka как prerequisites E1; точные таблицы/claim query C02/C03 |
| PG driver | native Go pgx family, без sqlite-compatibility слоя v1 | Версию/SQL/migration compatibility фиксирует C04, не этот документ |
| Web | React 19.x + TypeScript + Vite 8.x, Node 24.x только build | Registry read: React 19.3.1, TS 7.0.2, Vite 8.3.5; текущий Node 24.22.1 подходит engines metadata. Совместная сборка ещё не проверена |
| Edge | простой reverse proxy со static assets и /api; Nginx — default-кандидат | Версию, TLS trust и отсутствие credential header spoofing проверяет C04/C05; это не выбор SQL pool |

Номера из registry/tag metadata не доказывают безопасность, готовность артефактов или совместимость.
Перед первым lockfile нужны реальные сборка/проверки, без отключения TLS/checksum/signatures.
Наследуемый connector/go.mod и установленный Go 1.24.4 относятся к v1; они не выбирают toolchain нового сервера.

## Auth, trust, enrollment и очереди

- Пользователи: отдельный bootstrap администратора, без общего заводского пароля; пароль хешируется
  Argon2id с проверенным набором параметров на стенде C05. Session ID непрозрачный, серверное состояние в PG,
  cookie HttpOnly/Secure/SameSite и CSRF-защита изменяющих запросов. Logout/revoke проверяет сервер.
- CLI: отдельный ограниченный API credential с expiry/revoke и защищённым хранением; токен не обязателен в argv.
- Machine identity: mTLS, ключ создаётся локально на agent/collector; trust anchor поставляется проверяемым способом.
  Scoped одноразовое enrollment-разрешение привязано к tenant/site/collector, default TTL 15 минут.
  Конкретная цепочка issuer/OpenBao PKI/edge identity и CSR API уточняется C03/C11; CSR не даёт произвольный tenant.
- Agent может дозвониться только до collector. Enrollment/renewal и финальный ACK должны поддерживать этот путь;
  нельзя незаметно добавить обязательный прямой доступ agent→center/Bao.
- Collector receipt — отдельное долговечное состояние. Agent и collector удерживают неподтверждённые данные
  до центрального результата; body/hash/source identity и tenant проверяются повторно на центре.
- Нельзя верить клиентскому заголовку с машинной идентичностью. Если mTLS терминируется на edge,
  backend принимает атрибуты лишь от доверенного edge по защищённому внутреннему каналу; детали — C03.
- Spool: личный каталог процесса 0700 и data file 0600 как Linux-default; bounds/backpressure и crash replay C10.
  bbolt — очередь; не новая авторитетная база активов. Нельзя использовать один файл несколькими экземплярами.

## Что не блокирует серверный старт

| Решение | Статус | Когда необходимо |
|---|---|---|
| Первая ОС host agent | proposed / не выбрана пользователем | До C08; текущие C02–C07 проектируют независимый контракт |
| D-02 SQL pool | proposed, отложено | C36; E1 native PG pool driver |
| D-04 Nmap и remote scripts | proposed, отложено | До соответствующего адаптера C17–C20 |
| D-05 физический shard key | proposed tenant candidate | Основной scope tenant в C02; реальные кластеры C37 |
| D-08 production retention/SLO | proposed | Defaults стенда сейчас, реальные budgets C10/C14; расширение C30/C38 |
| D-10 Tantivy/Bluge | proposed, отложено | PoC C28; E1 exact/filter PG search |
| D-12 geo/residency/RPO/RTO | proposed, отложено | ADR/ресурсы C37–C39; до этого geo SLA не заявляется |
| D-13 multi-source presence | **принято пользователем 2026-11-13** — decisions/D13-discovery-policy.md | C20/C21; E1 health/freshness без массового missing |
| D-15 процессы ЖЦ/склада/ITSM | proposed, отложено | C41 и C46 до реализации соответствующей волны |
| D-18 100 active workload | proposed, отложено | C30; E1 ресурсные тесты не доказывают 100 пользователей |

В C01 отсутствуют внешние blockers для C02. Реальный reboot/systemd/Windows service и 24ч soak
в текущем managed shell не подтверждены. Доступный полноценный host/VM и разрешённые targets —
prerequisites C08/C13/C14; отсутствие такого стенда блокирует claims приёмки, а не проектирование сервера.

## Источники

- https://go.dev/dl/?mode=json
- https://registry.npmjs.org/react/latest
- https://registry.npmjs.org/vite/latest
- https://registry.npmjs.org/typescript/latest
- https://github.com/openbao/openbao/tree/v2.7.2
- https://github.com/etcd-io/bbolt/tree/v1.5.0

Точные наблюдения и hash source snapshot — в C01-baseline.json. Никакие credentials не запрашивались/не читались.
