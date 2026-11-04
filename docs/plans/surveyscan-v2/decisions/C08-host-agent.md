# C08 — первый постоянный host agent

2026-11-04. Первая фактически проверенная платформа Linux/amd64. Windows C15.
Агент — отдельный процесс без inbound listener/PG/target credentials; collector постоянный relay.
Prepare генерирует source UUID, отдельные Ed25519 TLS и observation keys, CSR/hash/public key.
Администратор выдаёт prebound C07 grant; enroll проверяет заранее установленный CA, CSR key matching,
tenant/source/generation и CA-attested center key. Collector TLS сверяется с expected source и assignment.
Секрет grant передаётся private file, не argv; private state0700/files0600. Identity не заменяется prepare.

Read-only adapter не исполняет shell. Hostname/Linux machine-id, os-release, локальные интерфейсы/IP/MAC;
лимиты файлов/rows/addresses и section status. Нет root-only привилегий, scan/remote запросов или
объявления недоступных полей успешными. Machine-id — candidate, UID назначается сервером.

Daemon сразу собирает inventory, затем по60–86400s; heartbeat отдельно30–3600s; bounded jitter0–25%,
HTTPS timeout12s, SIGINT/SIGTERM graceful stop. Linux flock защищает один state writer.
Inventory/heartbeat counters независимы и fsync до использования; gaps допустимы, reset запрещён.
Sender spool atomic+fsync до отправки. Transport retain не даёт удалить данные; source проверяет
center key/signature и точные batch/record bindings самостоятельно. Offline/untrusted ACK сохраняет packet.
Pending quota ограничена; receipt GC/full backoff/disk-fault/recovery tests — C10.

Heartbeat использует server nonce120s и отдельный domain SURVEYSCAN-HEARTBEAT-V1. Центр проверяет
current registered source/generation/assignment/signing key, origin signature, TTL, monotonic sequence;
consume/result/contact атомарны. Один active challenge/source/generation. Точный replay, даже после
нового challenge, возвращает исходное server accepted_at и не обновляет contact. Revoked peer не может
обновить source. Source.last_contact_at в API учитывает heartbeat state, не меняя asset section freshness.
Source.last_successful_inventory_at baseline пока null: source-owned summary port нужен в C09/C10;
asset.last_inventory_at и текущая проекция реализованы. Не подменять это поле временем heartbeat.

Системный service unit подготовлен как шаблон, не установлен. Production issuer/renewal/rotation с
OpenBao — C11; systemd/non-root/soak/installation acceptance — C14. C08 доказывает реальный ранний
вертикальный срез, не production SLA, backup или24h устойчивость.
