# Передача сессии: C15 (Windows) и C16 (Linux) — состояние на 2026-11-10

Ветка `claude/peaceful-goodall-a8u9sk` (единственная рабочая), HEAD на момент записи — см. `git log -1`.
Счётчик плана 57/200 НЕ менялся; C15.02 in_progress, C15.03 частично, C15.04 planned, C16.01 draft, C16.02/03 частично.
Журнал: docs/REQUESTS.md (R-024, R-025). Таблица возвратов: handoffs/C15-04-verification.md (V1–V10).

## Что проверено на реальной ВМ (Windows Server 2019 build 17763, Ubuntu 24.04 центр) — факты в R-025
V1 служба LocalSystem→Open; V2 сквозной enroll→данные в центр (11 секций); режим службы (source_sequence подряд, assets=1);
V3 перезагрузка (служба сама стартует через ~3,5 мин, личность/нумерация сохранены); V4 подмена бинарника (0.0.0-c13→0.0.1-upgrade-test);
V9 первая оценка (родительский процесс ~24 МБ WS, ~60 МБ PM, CPU ~1 с за несколько циклов; дочерние inventory-worker не измерялись).

## Найденные на ВМ условия/дефекты (все в журнале)
1) часы агента и центра: окно ±30 с вперёд/−2 мин назад для запроса профиля 1.2 (без NTP — 422 SCHEMA_INVALID); 2) machine_uuid без дефисов
отвергал весь пакет (исправлено acef4a0); 3) очередь агента копит отвергнутые пакеты (чистить state\spool); 4) на Linux-ВМ 72 дня висел `apt-get update`.

## Открытые проверки (нужны ресурсы) — что НЕ сделано
V5 обычные права; V6 Windows 10/11; V7 клон ВМ (одинаковый MachineGuid); откат на .prev и обновление при непустой очереди;
жёсткое выключение; длительный прогон и замер с дочерними процессами; users_groups на не-DC (на ВМ unsupported, вероятно из-за DC — не подтверждено).

## Стенд (тестовый, НЕ production; одноразовая dev-CA)
Linux-ВМ (Ubuntu 24.04, root, Docker, Go 1.27.3 в /usr/local/go, репозиторий ~/surveyscan, ветка выше, .contract-tools venv, chrony как NTP):
`cd ~/surveyscan/v2 && .contract-tools/bin/python scripts/vm_center.py --public-host <IP> --collector-port 18443` (поднимает PG/OpenBao сам;
держать открытым; файлы агента в v2/.local/vm-center/). После перезапуска центра БД новая (имя ssv2machine_<hex>: найти через
`docker exec surveyscan-v2-c04-db-1 psql -U surveyscan_v2 -d surveyscan_v2 -Atc "select datname from pg_database where datname like 'ssv2machine_%' order by 1 desc limit 1"`)
и агент надо регистрировать заново (новый grant). Windows-ВМ: C:\surveyscan\ (exe, windows-vm-enroll.ps1, windows-vm-check.ps1), служба SurveyscanAgentVm.
Передача файлов: python3 -m http.server 8000 --directory /root/transfer на Linux, Invoke-WebRequest на Windows. Сборка exe: GOOS=windows go build на Linux-ВМ.
Секреты (grant, токены) в чат/репозиторий не класть.

## Следующие шаги (рекомендация пользователю согласована)
1. Фон: длительный прогон службы и центра (утром: нумерация, assets=1, память, время).
2. Linux-агент `run12` как systemd-служба на Linux-ВМ (закрыть хвосты C16.03: реальный systemd, reboot, обновление). unit: deploy/systemd/surveyscan-agent.service + .d/run12.conf.
3. Затем решение пользователя: принять C15.02 по V1–V4/V9 с явным списком исключений (V5–V7, откат), счётчик меняет только он.
4. Дальше по плану: C16.02 (rpm/apk, systemd-службы, DMI), C16.04; C17 (SSH-сбор Linux).
Диагностика: SURVEYSCAN_AGENT_DEBUG=1 печатает тексты ошибок цикла; scripts/validate_pending.py, scripts/verify_pending_signature.py,
`PENDING=… go test -tags=diag -run TestDiagPending ./internal/modules/inventory` разбирают отвергнутые наблюдения.
