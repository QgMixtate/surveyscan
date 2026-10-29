# surveyscan — установка, использование, проверка

Сканер **инвентаризации сети с автопостроением схемы сети**: сетевое обнаружение активов (nmap —
хосты, открытые сервисы, ОС) и автоматическая интерактивная **схема сети** (ядро → устройства →
подсети → хосты) с экспортом PNG/SVG. Ядро на Python (PostgreSQL), веб-бэкенд FastAPI + React-интерфейс,
коннектор на Go. Это инструмент обследования, **не** сертифицированное средство анализа защищённости.

---

## Вариант A — Docker (быстрее всего)

Поднимает PostgreSQL и бэкенд с веб-интерфейсом одной командой.

```bash
unzip surveyscan.zip && cd surveyscan
docker compose up --build
```
Открыть **http://localhost:8000** → **«+ Новое сканирование»** → указать подсети/хосты
(`10.0.0.0/24`, `10.0.1.5`) → **«Запустить скан»** → раздел **«Схема сети»**.
Остановить: `docker compose down` (данные сохраняются в томах; `down -v` — удалить вместе с данными).

---

## Вариант B — вручную

### 1. Требования
- Python 3.10+
- PostgreSQL 14+ (запущен; сервисная роль должна иметь право **CREATEDB** — приложение само
  создаёт рабочую БД под каждый прогон)
- **nmap** — для реального сетевого сканирования целей (`apt install nmap`)
- Go 1.22+ — только для сборки коннектора

### 2. Установка
```bash
unzip surveyscan.zip && cd surveyscan
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
```

PostgreSQL (один раз):
```bash
sudo -u postgres psql -c "CREATE ROLE surveyscan LOGIN PASSWORD 'surveyscan' CREATEDB;"
sudo -u postgres createdb -O surveyscan surveyscan
export SURVEYSCAN_PG_DSN="host=127.0.0.1 port=5432 user=surveyscan password=surveyscan"
```
По умолчанию DSN = `host=127.0.0.1 port=5433 user=surveyscan`. Наборы данных лежат схемами одной
БД прогона (`public`, `bdu`, `ms`, `adv`); обслуживающая БД `surveyscan` нужна для их создания.
Прикладная БД задач веб-бэкенда — по каталогу `SURVEYSCAN_APP_DIR` (по умолчанию `/tmp/surveyscan_app`).

### 3. Запуск
```bash
python -m surveyscan.api          # веб: http://localhost:8000
```

---

## Проверка работоспособности

```bash
python -m pytest -q               # ожидается: 100 passed
python -m surveyscan demo         # -> demo-output/report.html (прогон ядра без сети)
curl -s localhost:8000/health     # -> {"status":"ok"}
```
В браузере: «+ Новое сканирование» → указать цели → «Запустить скан» → через несколько секунд
Дашборд показывает KPI инвентаризации, раздел «Схема сети» — интерактивный граф.

---

## Использование

### Реальное сканирование (ввод целей)
Сначала (один раз) заведите **учётные записи** во вкладке «Учётные записи» сайдбара: имя, тип
(SSH/WinRM/SNMP), логин, пароль/ключ/community. Затем «+ Новое сканирование» → укажите
подсети/хосты (`10.0.0.0/24`, `10.0.1.5`) → отметьте нужные УЗ галочками → «Запустить скан».

1. **Сетевое обнаружение (nmap):** живые хосты, открытые порты, версии сервисов, ОС.
2. **Аутентифицированный сбор (если заданы УЗ):** к каждому активу подбирается подходящая по типу
   УЗ (перебор до первой успешной) и собирается полный инвентарь — по **SSH** (Linux: пакеты, учётки,
   параметры ОС, конфиги), по **WinRM** (Windows: ПО, роли, патчи), по **SNMP** (оборудование: соседи
   для схемы L2). Собранные данные склеиваются с активом, обнаруженным по сети.
3. **Схема сети** строится автоматически из результата.

Учётные записи хранятся в БД **в зашифрованном виде** (Fernet). Мастер-ключ берётся из переменной
окружения `SURVEYSCAN_SECRET_KEY` и в базе не лежит — дамп БД сам по себе секреты не раскроет.
Задайте ключ перед запуском (иначе он сгенерируется в томе данных и потеряется вместе с ним):
```bash
export SURVEYSCAN_SECRET_KEY="$(python3 -c 'from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())')"
docker compose up --build        # ключ пробросится в контейнер (см. docker-compose.yml)
```
При скане секреты расшифровываются только в память задачи; в БД задачи, логи и отчёт не попадают,
в сводке фиксируется лишь логин подошедшей УЗ. Требуются `nmap` и клиент `snmp` (snmpwalk) — в Docker
уже в образе; `pywinrm`/`cryptography` ставятся из `requirements.txt`. Для определения ОС nmap (`-O`)
нужны права root / capabilities NET_RAW,NET_ADMIN (в Docker заданы; иначе — откат к обнаружению
сервисов без ОС).

> Проверено вживую: SSH-сбор (прогон `linux_collect.sh` под УЗ → 1000+ пакетов, слияние с nmap-активом)
> и SNMP-опрос. WinRM реализован по той же схеме (`windows_collect.ps1` через pywinrm); валидация —
> на вашем Windows-хосте, в песочнице сборки его не было.

### Веб-интерфейс
Разделы: Дашборд (KPI инвентаризации) / Сканирования / Активы / **Схема сети** / Коннекторы;
отчёт — кнопкой «открыть ↗» в разделе Обследования. Коннекторы регистрируются в одноимённом разделе.

### Консоль (рабочий процесс обследования)
```bash
# базы знаний (перед обследованием)
python -m surveyscan bdu-import vulxml.zip        # https://bdu.fstec.ru/files/documents/vulxml.zip
python -m surveyscan adv-import --ubuntu-oval com.ubuntu.jammy.pkg.oval.xml.bz2 \
    --debian-json debian-data.json --file astra-1.7.jsonl

# сбор на месте: collectors/linux_collect.sh, collectors/windows_collect.ps1, nmap, Greenbone/Trivy

# загрузка, анализ, отчёт (work/acme — метка каталога -> имя БД прогона)
python -m surveyscan --survey work/acme ingest raw/* nmap.xml openvas.xml configs/*.cfg
python -m surveyscan --survey work/acme analyze --profile profiles/base.yaml
python -m surveyscan --survey work/acme report --out acme.html --csv acme-csv/ \
    --name 'ГИС «Пример»' --customer 'ООО «Пример»'
```

### Коннектор (сбор у заказчика)
```bash
cd connector && CGO_ENABLED=0 go build -o surveyscan-connector .
# pull-режим (только исходящие соединения):
./surveyscan-connector -mode serve -center https://center -token <ТОКЕН> -raw /var/collected -interval 30s
# офлайн-курьер: courier-run (офлайн) + courier-import (онлайн) — см. connector/README.md
```
API протокола: `POST /connectors` (регистрация → токен), `POST /connector/jobs` (задание),
`GET /connector/jobs/next`, `POST /connector/jobs/{id}/result`, `GET /connector/jobs/{id}/bundle`.

---

## Если что-то не так
- **`connection refused` / `psycopg.OperationalError`** — PostgreSQL не запущен или не тот порт; проверьте `SURVEYSCAN_PG_DSN`.
- **`permission denied to create database`** — у роли нет CREATEDB: `ALTER ROLE surveyscan CREATEDB;`
- **`database "surveyscan" does not exist`** — не создана обслуживающая БД.
- **В вебе не грузятся шрифты/иконки** — запускайте `python -m surveyscan.api` (не голый uvicorn без рабочего каталога); статика отдаётся с `/static/`.

Полная шпаргалка по API — `README.md`, по коннектору — `connector/README.md`.
