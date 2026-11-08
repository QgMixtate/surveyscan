# C15.02: сквозная проверка Windows-агента на ВМ (runbook)

Статус: **не выполнялась**. Код Windows-агента проверен в CI по частям (см. ниже); первый запуск `RunWindows` с настоящим
collector/center/PG делается здесь, на Windows-ВМ с правами администратора. До фактического прогона C15.02 не принимается, счётчик 57/200 не меняется.

## Что уже проверено в CI (Windows Server 2022, администратор), а что нет
| Проверено нативно | Не проверено |
|---|---|
| приватный каталог состояния, блокировка писателя, атомарная замена, Remove, восстановление `.tmp-*` | `enroll`, `bind-host`, `renew` |
| `prepare` скомпилированным агентом из каталога/файла, защищённых `icacls` (шаг c15, run 42534540858) | `RunWindows` целиком: цикл, сбор 12 секций, отправка |
| чтение `MachineGuid`; запись/чтение подписанного кэша профиля через приватные адаптеры | Windows 11, обычные права, служба SCM, перезагрузка |
| 12 провайдеров в отдельных процессах (ранее, C15.02) | поведение при клоне ВМ (MachineGuid совпадает) |

## Предпосылки
- Linux-хост с центром, collector, PostgreSQL, OpenBao (`make dev-up` по `v2/README.md`) и оба флага включения 1.2:
  `inventory12_enabled: true` в конфигурации центра (`machine_config`) и collector (collector также требует `credential_state`). По умолчанию флаги выключены.
- Windows Server 2022 / Windows 10 1709+ (нужен `FileRenameInformationEx`), NTFS, запуск от администратора, Go 1.27.3 для сборки или готовый `surveyscan-agent.exe`.
- Сеть: ВМ видит HTTPS-адрес collector; CA collector положить на ВМ.

## Шаги на ВМ (PowerShell 7)
Все файлы, которые читает агент (конфигурация, CA, grant), должны лежать в каталоге с защищённым DACL и сами иметь явный
защищённый DACL без унаследованных записей; обычный `Set-Content` не подходит. Эта процедура проверена в CI для `prepare`.
```powershell
$root='C:\ProgramData\SurveyScan\agent'; $cfg="$root\cfg"; $state="$root\state"; $u=$env:USERNAME
New-Item -ItemType Directory -Force -Path $cfg | Out-Null
icacls $cfg /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' "${u}:(OI)(CI)F"
function Protect($f){ icacls $f /inheritance:r /grant:r 'SYSTEM:F' 'BUILTIN\Administrators:F' "${u}:F" }
# 1) положите ca.pem в $cfg и защитите:  Protect "$cfg\ca.pem"
# 2) agent.json (UTF-8 без BOM): tenant_id, site_id, network_scope_id, collector_source_id, collector_url (https), ca_certificate_file, state_directory=$state
#    Set-Content "$cfg\agent.json" $json -Encoding utf8NoBOM ; Protect "$cfg\agent.json"
.\surveyscan-agent.exe prepare --config "$cfg\agent.json"     # печатает source_id, csr_pem, csr_sha256, signing_public_key
```
Каталог состояния агент создаёт сам как приватный корень; готовить его вручную не нужно (обычный каталог с унаследованным ACL будет отвергнут).

## Шаги на стороне центра (не проверены с Windows-агентом)
1. Выпустить grant: `POST /api/v1/enrollments` с вошедшей сессией (cookie + CSRF), тело: `tenant_id, source_id (из prepare), source_kind:"agent", site_id, collector_id, ttl_seconds, csr_sha256, signing_public_key`.
   Готового CLI-вызова нет; образец запроса — `v2/scripts/profiles_smoke.py`. Ответ сохранить в `$cfg\grant.json` и защитить `Protect`.
2. На ВМ: `.\surveyscan-agent.exe enroll --config "$cfg\agent.json" --grant-file "$cfg\grant.json"`, затем `run --config ...`.

## Что зафиксировать (в `docs/REQUESTS.md` и evidence)
- Успех `enroll`/`bind-host`; повторный `enroll` идемпотентен; `renew` продлевает сертификат.
- В `run`: события `inventory_profile_synced` → `inventory_queued` → доставка; в API/UI одна карточка с 12 секциями со статусом `partial`, без дублей после перезапуска агента.
- Поведение офлайн: обрыв сети — сбор идёт по последнему принятому профилю, очередь не теряется; отказ по протоколу (выключить флаг на collector) — новые сборы прекращаются, heartbeat продолжается.
- Потребление CPU/памяти за 1–2 цикла сбора; время полного сбора против бюджета профиля (420 с).
- Все отклонения и сбои записывать как есть, ничего не переименовывать в PASS.

## Известные ограничения (записаны, не скрыты)
- Клон ВМ с тем же `MachineGuid` привязкой хоста не отличается от оригинала; политика клонов — C15.04.
- Кандидаты идентичности Windows (`hostname.raw`, `windows-machine-guid`) требуют подтверждения сопоставления в центре.
- Установщик (C15.03) должен автоматизировать создание защищённых каталога/файлов; сейчас это ручной `icacls`.
