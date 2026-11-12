# C32.01 — что реально хранит v1 и как это ложится на v2

Статус: составлено по коду ветки `legacy/v1` (R-027, 2026-11-12). **Решение пользователя 2026-11-12: перенос не делается** (в v1 только стендовые машины, их уже собирают агенты v2); документ — справка. Реальных баз v1 в песочнице нет — только
образцы `samples/hosts` (2 Linux `.surv`, 1 Windows `.json`, nmap, OpenVAS, конфиг коммутатора). Где лежат
боевые базы v1 и нужны ли они — **вопрос пользователю** (см. «Открытые вопросы»).

## Как v1 хранит данные (факт по коду)
- **Обследование** = одна БД: SQLite-файл (прототип) или БД PostgreSQL (`pgcompat`: имя БД выводится из каталога
  прогона), схема `public`. Таблицы: `survey` (1 строка: name, customer, created_at, bdu_version), `asset`,
  `software`, `service`, `hotfix`, `scanner_finding`, `vuln_finding`, `manual_review`, `check_result`,
  `raw_artifact`. Наборы БДУ/MSRC/фидов — схемы `bdu`, `ms`, `adv` (справочники, не данные заказчика).
- **asset**: kind (host | image | netdev), hostname, fqdn, ips (JSON-массив **без префиксов**), os_family, os_id,
  os_version, os_pretty, os_build, kernel, platform (linux | windows | container | huawei_vrp…), role, exposure,
  source, collected_at (строка от сборщика), facts (сырой JSON разделов сборщика).
- Сведение в v1 — по имени хоста **или любому IP** (`find_or_create_asset`); ID актива — целое внутри одной БД.
  Повторный ingest **перезаписывает** ПО (DELETE + INSERT) — истории версий в v1 нет.
- **Прикладная БД** (`SURVEYSCAN_APP_DIR`): `task` (журнал заданий), `credential` (ssh/winrm/snmp; секрет
  `secret_enc` — Fernet, ключ из `SURVEYSCAN_SECRET_KEY` или файла `secret.key` рядом с БД, в БД его нет).
- **Известный дефект:** `ingest.py` импортирует `apply_role_guess` из `db.py`, а функции там нет (с ba8f735) —
  загрузка в v1 сейчас падает. Поэтому переносится **уже сохранённое в БД v1**, ingest v1 не запускается и не
  чинится (исправление v1 — отдельный объём). `asset.role` в старых базах — эвристическая догадка, не факт.

## Соответствие (перенос — подписанным portable-пакетом через обычный приём центра)
Каждый актив v1 → одно наблюдение 1.2 отдельного portable-источника «миграция v1» (тенант/площадка/зона задаёт
оператор). `source_record`: `v1:<имя обследования>:<asset.id>`; `collected_at` — из v1, `clock=estimated`;
ID наблюдения детерминирован (UUIDv5 от обследования, актива и времени) — повторный перенос идемпотентен.
| v1 | v2 (раздел 1.2) | Правило / разрыв |
|---|---|---|
| hostname, fqdn | identity (hostname, fqdn); кандидат `hostname` | нет имени (актив только из сканера) → identity `unavailable` V1_NO_HOSTNAME, кандидаты — IP |
| ips | network: одна строка `v1-addresses`, кандидаты `ipv4`/`ipv6` | префикса в v1 нет → `/32`·`/128` и раздел `partial` V1_PREFIX_UNKNOWN (подсеть не выдумывается) |
| os_pretty/os_id, os_version, os_build, platform | os (name, version, build, architecture) | архитектура обязательна; в v1 её нет у Windows и часто у Linux (только у пакетов) → берётся из arch пакетов ядра/большинства, иначе раздел `unavailable` V1_ARCH_UNKNOWN |
| software (deb/rpm) | software (source dpkg/rpm, scope machine) | `ecosystem=kernel` — не пакет, в software не идёт (ядро — в os) |
| software (win) | — | в v2 обязательны `registry_key`/`registry_view`, в v1 их нет → раздел `unavailable` V1_REGISTRY_KEY_MISSING; список остаётся в архиве переноса |
| hotfix | updates (id=KB…, source qfe) | `partial` QFE_SUBSET (как у агента) |
| service (collector) | — | в v1 сервисы/порты — из сканеров (nmap) и с удалённого взгляда, не локальные слушатели → не переносятся как факты хоста |
| scanner_finding, vuln_finding, manual_review, check_result | — | модуля уязвимостей/проверок в v2 нет (E4+): архив переноса (JSON) |
| role, exposure | — | догадки v1 → в факты не идут; по желанию — тегом через CSV C31 после переноса |
| survey.customer | тенант/площадка | выбирает оператор |
| task, raw_artifact | — | журнал и пути файлов v1 — в архив (sha256 сохраняются) |
| credential | — | секреты не переносятся автоматически (C32.03) |

## Открытые вопросы (к пользователю)
1. Есть ли боевые базы v1 (сколько обследований, где: SQLite-файлы или PostgreSQL) и нужен ли их перенос, или
   v2 стартует с чистого сбора агентами (тогда C32 — только процедура и проверка на образцах)?
2. ПО Windows из v1 без ключа реестра: оставить только в архиве переноса (предложено) или нужен иной путь?
