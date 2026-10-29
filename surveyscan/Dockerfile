# Образ бэкенда surveyscan (FastAPI + ядро). PostgreSQL — отдельным сервисом (см. docker-compose.yml).
FROM python:3.12-slim

WORKDIR /app

# nmap — сетевое обнаружение; snmp — клиент net-snmp (snmpwalk) для сбора с оборудования;
# psycopg[binary] тянет libpq сам
RUN apt-get update && apt-get install -y --no-install-recommends nmap snmp \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY surveyscan ./surveyscan
# данные и коллекторы, которые ядро читает относительно корня проекта (ROOT):
# коллекторы для сбора по SSH/WinRM, базы-образцы, правила, шаблоны отчётов, профили проверок
COPY collectors ./collectors
COPY samples ./samples
COPY rules ./rules
COPY catalog ./catalog
COPY reports ./reports
COPY checks ./checks
COPY profiles ./profiles
COPY README.md INSTALL.md ./

EXPOSE 8000
ENV SURVEYSCAN_HOST=0.0.0.0 SURVEYSCAN_PORT=8000 SURVEYSCAN_APP_DIR=/data/app
VOLUME ["/data"]

CMD ["python", "-m", "surveyscan.api"]
