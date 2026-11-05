# C14 — непрерывная проверка первого SMB

`scripts/soak.py` запускает настоящий Linux host agent → collector → combined center →
собственную PG17 БД со scoped OpenBao Transit/KV. Все state/config/keys и журналы приватны
в игнорируемом `.local/c14-soak/<run-id>/`; никакие runtime credentials не публикуются.
Нужен уже работающий dev-стенд (`scripts/dev.py up`), собранные Go binaries в `.dist`,
Python requirements из contract checker, OpenSSL и доступ к локальному Docker/socket/loopback.
Другие тесты не должны останавливать/запечатывать общие dev PG/Bao в течение окна.

Сначала выполнить короткую проверку сценария:

```sh
python scripts/soak.py --preflight-seconds 150 --run-id <new-uuid>
```

Она возвращает только `preflight_passed`: это не суточная приёмка. Настоящий запуск:

```sh
python scripts/soak.py --hours 24 --run-id <new-uuid>
python scripts/soak_status.py <run-uuid>
python scripts/soak_report.py <run-uuid>
```

Runner следует запускать отдельным supervisor/session с закрытым stdin и приватным stdout,
чтобы завершение инструментального вызова или чата не посылало ему SIGHUP. Сохранить PID/run ID.
Общий dev-стенд и машина должны продолжать работать не менее 24 часов. Остановка/пересоздание
облачной машины прерывает тест: сохранённый marker `running` не означает работающий процесс.
`soak_status.py` сопоставляет PID с run ID и проверяет возраст sample; при stale/interrupted
возвращает exit2. Он не меняет фактический результат и не возобновляет прерванное окно.

Измеренное окно начинается после первого committed живого наблюдения. Бинарники копируются
в приватный каталог с SHA256; последующие сборки в workspace не меняют выполняемый комплект.
Записываются source revision/dirty, версии, runner hash, реальные timestamps и elapsed time.
Начальные интервалы: inventory60s, heartbeat30s, jitter0; квоты source4MiB/collector1MiB.
TLS server leaf120h — явный dev bootstrap, обычный default24h не изменён. Machine leaf24h
должен реально обновиться по текущему времени на обеих ролях; clock injection отсутствует.

Два loopback TCP relay прозрачно передают шифрованный TLS. Faults закрывают собственные
соединения и временно отклоняют новые, без изменения пакетов/firewall/общих сервисов:

| Elapsed | Действие |
|---|---|
| 1h | Разрыв agent→collector; restart agent после разрыва для реального offline сбора |
| 1h2m | Восстановление первой связи |
| 2h | Разрыв collector→center; restart agent после разрыва |
| 2h2m | Восстановление второй связи |
| 3h | Restart collector |
| 4h | Restart center |

Каждые30s сохраняются observation count/max sequence/UID, свежесть inventory, section counts,
обе очереди и их bytes, per-process RSS/CPU, outbox unapplied, readiness/renewal receipts.
Одинаковый UID/уникальные sequence/живые процессы проверяются постоянно; свежесть не должна
превысить300 реальных секунд даже при запланированных коротких отказах. RAM/CPU измеряются;
данные не объявляются SLA или доказательством поддержки100 пользователей.

После ≥86400s periodic producer переводится на явный интервал86400s с перезапуском агента:
один дополнительный настоящий inventory входит в конечный drain. Тест даёт до180s на
production backoff/ACK. Проверяются пустые обе очереди, count observations=results=max sequence,
сохранность UID и реальные renewal artifacts обоих источников. Только затем статус `passed`.
При сигнале/failure статус interrupted/failed; неполные сутки никогда не засчитываются.

`status.json` атомарен/fsync, `events.jsonl` и `samples.jsonl` append/fsync с mode0600.
После успеха тестовые DB/scoped mounts/tokens/private working files удаляются; отчёты остаются.
Не загружать каталог целиком в Git/CI artifacts. Публиковать только проверенный sanitized report.

Отдельно `scripts/reconnect_smoke.py` проверяет три independently enrolled real agent процесса
на одном хосте, явный quota filler380000bytes в private spool512KiB, bounded retries и
одновременный reconnect. Это не три физические машины; настоящий ENOSPC имеет отдельный
`scripts/diskfault.py` в disposable tmpfs. Все границы сохранены в E1 matrix.

`soak_report.py` сводит только завершённые JSONL записи: freshness, RAM, очереди/outbox,
наблюдения и события. Проверяет живой PID через status helper, не раскрывает host facts/configs/keys.
Preflight, failed и stale marker не дают accepted_24h; source/binary hashes сохраняются.
Для старых preflight, где некоторых метрик ещё не было, соответствующее значение остаётся null.
Сводка не меняет plan status и не запускает следующий пакет до приёмки зависимостей.
