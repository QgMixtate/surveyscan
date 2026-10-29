# surveyscan — память проекта для Claude Code

Читается автоматически при старте сессии. Держать кратким: карта + указатели, не дамп кода.
Не перечитывать весь проект — идти сразу в нужный файл по карте ниже; код смотреть через Grep/Glob точечно.

## Что это
Сканер **инвентаризации сети с автопостроением схемы сети**: nmap-обнаружение → (опц.)
аутентифицированный сбор по SSH/WinRM/SNMP → схема L3 (+L2 по SNMP) → веб-UI с графом и экспортом PNG/SVG.
Наследие (скрыто в UI, доступно через API): уязвимости по БДУ ФСТЭК, проверки конфигураций.
Инструмент обследования, НЕ сертифицированное СЗИ.

## Стек
Ядро на Python (библиотека) + FastAPI-бэкенд + React SPA (UMD, вшит локально — закрытый контур) +
коннектор на Go. Хранилище — PostgreSQL. Очередь задач — ThreadPoolExecutor (интерфейс под Celery).

## Карта (пакет `surveyscan/`)
- `cli.py` — CLI; тут `ROOT` (= корень репо) и `DATA`.
- `pgcompat.py` — адаптер SQLite-диалект → PostgreSQL (open_db/connect/drop_db). DSN из `SURVEYSCAN_PG_DSN`.
- `db.py` — схема обследования, `find_or_create_asset` (матч по hostname/любому IP, иначе дубль).
- `ingest.py` — загрузка в БД: nmap-XML, linux `.surv`, windows `.json`, netdev, openvas, trivy.
- `collect.py` — аутентифицированный сбор: подбор УЗ под актив, SSH(linux_collect.sh)/WinRM(windows_collect.ps1)/SNMP; склейка с nmap-активом (`_merge_into`); отмена через `should_cancel`.
- `topology.py` — схема сети: `build` (L3), `to_svg`, `merge_l2` (LLDP из SNMP).
- `matcher.py`/`bdu.py`/`msrc.py`/`advisories.py`/`normalize.py` — уязвимости (наследие).
- `report.py`/`reporttpl.py` — HTML-отчёт и `dashboard_json`.
- `configcheck.py` — проверки конфигураций по профилям (наследие).
- `api/app.py` — FastAPI: /tasks, /tasks/{id}(+/topology,/topology.svg,/report,/cancel), /credentials, /connectors.
- `api/runner.py` — исполнитель: `nmap_scan` (Popen, отменяемый), `run_pipeline`, реестр секретов `_VAULT`, отмена `_PROCS/_CANCELLED`, журнал через `_log`→`store.append_progress`.
- `api/store.py` — прикладная БД (task, credential). `SURVEYSCAN_APP_DIR`.
- `api/secretbox.py` — шифрование секретов УЗ (Fernet). Ключ из `SURVEYSCAN_SECRET_KEY`, не в БД.
- `api/static/` — SPA: правится `app.jsx`, компилируется в `app.js` (см. Сборка SPA). `index.html` — стили. `vendor/` — react/cytoscape/шрифты локально.

## Данные и коллекторы (относительно ROOT, НЕ внутри пакета)
`collectors/` (linux_collect.sh, windows_collect.ps1), `samples/`, `rules/`, `catalog/`, `reports/`,
`checks/`, `profiles/`. ВАЖНО: все они должны копироваться в Docker-образ (см. Dockerfile COPY) —
иначе сбор/рендер падают с FileNotFoundError.

## Команды
- Тесты: `python -m pytest -q` (ожидается 111 passed). Нужен поднятый PostgreSQL.
- Запуск: `python -m uvicorn surveyscan.api.app:app --host 127.0.0.1 --port 8099` или `docker compose up --build`.
- Сборка SPA после правки `api/static/app.jsx` (путь к babel — своей песочницы/машины; ВАЖНО:
  нужен `runtime: classic` в пресете, иначе новые версии `@babel/preset-react` эмитят
  `import {jsxDEV} from "react/jsx-dev-runtime"`, а проект без бандлера — упадёт
  `SyntaxError: Cannot use import statement outside a module`):
  1) `babel.config.json` рядом (один раз): `{"presets": [["@babel/preset-react", {"runtime": "classic"}]]}`
  2) `cd surveyscan/api/static && <path>/node_modules/.bin/babel app.jsx --config-file <path-to-babel.config.json> -o app.js`
- Скриншоты UI: Playwright+Chromium уже в контейнере (require('playwright'), chromium.launch()).

## Готчи (на них уже наступали)
- PostgreSQL в песочнице периодически падает при рестарте окружения. Поднять:
  `su postgres -c "$PGBIN/pg_ctl -D /tmp/pgdata -o '-p 5433 -k /tmp/pgrun -c listen_addresses=127.0.0.1' start"`,
  где `PGBIN=/usr/lib/postgresql/16/bin`. Роль/БД — `surveyscan`.
- `pgcompat._Cursor` не имеет `rowcount` — для «удалил/нет» использовать `DELETE … RETURNING`.
- Секреты УЗ: только в памяти задачи (`_VAULT`) + зашифрованы в БД; в params/result/логи/отчёт НЕ писать.
- nmap `-O` требует root/caps NET_RAW,NET_ADMIN; без них — авто-откат к сбору без ОС. В compose caps заданы.
- Фронтенд закрытый контур: только вшитые vendor-ресурсы, без CDN. После правки app.jsx — обязательно перекомпилировать в app.js.
- Перезапуск uvicorn: убивать по PID (`pkill -f uvicorn` в песочнице даёт exit 144 и рвёт шелл).

## Соглашения
- UI и тексты — по-русски. Комментарии в коде — по-русски, по делу.
- Параллельная сессия иногда правит backend — при конфликте смотреть свежий файл перед правкой.
