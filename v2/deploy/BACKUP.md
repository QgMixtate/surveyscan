# C13 — backup/restore по компонентам (в работе)

Проверены **PostgreSQL component round-trip и отдельный OpenBao Raft restore**. Полная согласованная копия PostgreSQL,
OpenBao и файлового состояния проверена отдельным bounded development rehearsal ниже;
её production/systemd-приёмка остаётся открытой. `pg_backup.py` не обновляет
общий backup-age marker и явно возвращает `complete_system_backup=false`.
Нет утверждённых RPO/RTO, geo DR или доказанного reboot recovery.

## PostgreSQL17

Нужны `psql`, `pg_dump`, `pg_restore` major17. Подключение задаётся стандартными libpq
переменными, пароль — через защищённый pgpass или настроенный provider. Не помещать пароль
в command line, DSN отчёта или shell history. Для удалённого production PG оператор
настраивает TLS и проверку CA; development fixture использует локальный контейнер.

Пример из `v2/`; пользователь БД и авторизация настраиваются отдельно:

```sh
PGHOST=/run/postgresql PGUSER=surveyscan PGPASSFILE=/secure/pgpass \
  python3 scripts/pg_backup.py backup --database surveyscan --directory /private/new-backup
PGHOST=/run/postgresql PGUSER=surveyscan PGPASSFILE=/secure/pgpass \
  python3 scripts/pg_backup.py restore --database surveyscan_restore --directory /private/new-backup
```

Backup создаёт новый directory0700, custom archive0600 и manifest0600 с фактическим
completed_at, bytes/SHA256. Existing backup не заменяется. Частичный dump не публикуется
как завершённый backup. `pg_restore --list` проверяет читаемость archive перед публикацией.
Содержимое включает чувствительные auth/session/credential records; backup предназначен
для защищённого хранилища. Защита transport/storage и custody остаётся у оператора.

Restore требует **другую, заранее созданную пустую БД**, PG17 и необходимые роли/права.
Системные БД, URL/connection-string вместо простого имени, symlink и небезопасные permissions
отвергаются. Проверяются checksum/size private copied archive и отсутствие user schemas,
relations/functions/types в target. Restore выполняется `--single-transaction --exit-on-error`,
без `--clean`/DROP и без переноса cluster-level owners/ACL. Роли PostgreSQL, расширения,
tablespaces, CA и настройки сервера — отдельные prerequisites. App-level tenant/RBAC данные
восстанавливаются как обычные таблицы.

Backup manifest защищает от случайной порчи, но сам не подписан. Входной archive должен
происходить из доверенного protected backup custody: SQL restore исполняет его содержимое.
Перед восстановлением target изолируют от traffic и всех других writers; не использовать
свежую проверку пустоты как блокировку от параллельного подключения.

## Фактический прогон

`/workspace/.surveyscan-contract-tools/bin/python scripts/backup_smoke.py` использует
существующий local dev PG17 только для двух собственных временных БД.
Сначала реальные server/collector, TLS и synthetic signed inventory создают реестр;
затем эти процессы останавливаются. Отдельно вставляется явно обозначенный SQL retry
checkpoint fixture. Restore идёт в новую БД, рабочая dev БД/volume не заменяется.

18 checks passed (8 pipeline + 10 backup/restore): fingerprints всех46 таблиц совпали,
включая 45 domain/access tables и migration ledger. Сохранены UID, пользователи/права,
история, observations/receipts, outbox/retry. Текущий binary подтвердил все33 миграции,
`applied_migrations=0`; это не тест перехода со старой версии схемы.
После restore реальный server принял прежние admin credentials и вернул ту же карточку
через TLS API. Реальный PATCH с Origin/CSRF/If-Match сохранил UID и создал ровно один новый audit/outbox. Порча archive и nonempty target отвергнуты, sentinel table сохранена.
Временные БД, private archive и fixtures удаляются. Reports не содержат table contents/passwords.

## Единый остановленный checkpoint

`scripts/checkpoint.py` объединяет заранее снятые PG custom archive, Bao Raft snapshot и
именованные директории state/configs. Оператор предварительно останавливает/изолирует все
application writers и сохраняет их остановленными до завершения копирования. Флаг
`--writers-quiesced` — подтверждение этого предусловия, не автоматическая остановка служб.

```sh
python3 scripts/checkpoint.py pack --output /private/new-checkpoint \
  --postgres /private/pg-component --bao-snapshot /private/raft.snapshot \
  --state host=/private/stopped-host-state --state issuer=/private/server-tls \
  --writers-quiesced
python3 scripts/checkpoint.py verify --checkpoint /private/new-checkpoint
python3 scripts/checkpoint.py extract --checkpoint /private/new-checkpoint --target /private/new-restore
```

Нужен полный состав конкретной установки: operator configs, TLS/CA public trust, source
identity/origin key, generation/counters/profile cache, collector credentials и обе очереди,
PG/artifacts и Bao. Recovery/unseal/root custody хранится отдельно, не у приложения.
Tool проверяет SHA256/size/set, отказывает symlinks/special files и existing destination,
повторно проверяет private copied snapshot перед atomic extraction. Все backup dirs0700/files0600.
Ограничения:20k files/2GiB payload; protected input/custody обязательны, manifest не подписан.
Tool не запускает writers, не overwrite DB/Bao, не утверждает полноту выбранных директорий
и не обновляет monitoring marker автоматически.

`scripts/checkpoint_smoke.py`:10 real checks passed. Реальный agent с Bao-issued сертификатом
передал первый inventory; второй остался durable у agent и collector при недоступном центре.
Все application processes stopped, затем PG/Bao/files сняты в один checkpoint. Restore идёт
в другую пустую БД, отдельный initially empty Bao и другие filesystem paths. Старые host/issuer
каталоги переименованы и недоступны восстановленным процессам. Меняются только operator config
paths/endpoints; signed identities/payloads/queues остаются исходными bytes.
Прежняя session работает, second observation применяется один раз к прежнему UID, original pending
replay не создаёт дубль, агент продолжает sequence3 и обе очереди очищаются по signed ACK.
Затем настоящий leaf renewal выдаёт другой сертификат с прежними source/generation через restored
Transit CA. Исходная БД остаётся на одном observation. Custody/snapshot/private files удаляются.
Это общий development checkpoint, не две чистые ОС/systemd reboot или production DR.

`scripts/upgrade_smoke.py`:13 checks проверяют настоящий переход из C11 `b22efa2`.
Previous application binaries собираются из git archive; test callback расширен только для
управления процессами/SQL helper. Старый server/collector создают данные на31 миграции,
затем current binary применяет ровно2 новые. Все previous domain rows/31 migration hashes
сохраняются; повторный migrate0, прежние login/UID и новая business write работают.
Existing source получает unmanaged profile revision1. Это не schema downgrade/live service rollback.

## Отдельный OpenBao restore и оставшаяся системная приёмка

`scripts/bao_restore_smoke.py` проверяет настоящий Raft snapshot OpenBao2.7.2 на отдельном
изначально пустом узле с private temporary state. Исходный узел не восстанавливается,
не seal/reset и не теряет volume/keys. Dev fixture получает собственные Transit/KV/policy/token;
bootstrap custody используется только для snapshot и восстановления временного узла.
HTTP допустим здесь только на literal loopback development endpoints; production HTTPS не проверен.

9 checks passed: snapshot, separate initialization, force restore в **собственный clean target**,
unseal source custody, сохранённые cluster ID/KV/scoped policy, отказ чужому initial root token
и forbidden signing, оба non-exportable Transit CA/receipt keys реально подписывают проверяемые
Ed25519 challenges. После настоящего Docker restart узел sealed; source custody возвращает
готовность, подпись снова работает. Это не systemd reboot или auto-unseal.
Исходный узел остался active, audit не содержит raw test secrets. Target container останавливается
до удаления private bind-state; temporary snapshot/custody/keys и own source fixtures удаляются.

Snapshot содержит реальное development secret state и не сохраняется как публичный evidence.
В evidence только статусы/проверки. Этот rehearsal не предоставляет CLI для overwrite
произвольного Bao и не заменяет production restore runbook. Общий application restore с
CA leaf renewal/receipt replay проверен выше в bounded development stand.

Для полной копии требуется согласованный checkpoint после остановки writers:
agent/collector state с origin keys/identity/counters/profile cache/очередями, server configs
и TLS/CA trust, PG, OpenBao Raft snapshot и audit, отдельное custody recovery/unseal материала,
точный signed release manifest и сведения о версиях. Снятый snapshot без recovery материала
не доказывает работоспособность Transit CA/receipt signing после потери узла.
Нельзя хранить root/unseal материал у application UID или в service unit/image.

Для выбранной systemd установки и двух чистых ОС предстоит повторить общий checkpoint,
возврат тех же source/asset IDs, replay pending/receipts без дублей и безопасную миграцию
со старого release. До переключения writers нужны проверки tenant/access/history/outbox,
подтверждённый единственный writer и проверенный путь возврата к целой копии.
Автоматического overwrite production storage, unsafe schema downgrade и удаления identities нет.
Лишь после полного restore rehearsal можно обновлять общий backup-age marker.
