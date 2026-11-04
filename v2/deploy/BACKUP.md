# C13 — backup/restore по компонентам (в работе)

Проверен **PostgreSQL component round-trip**. Полная согласованная копия PostgreSQL,
OpenBao и файлового состояния пока не реализована/не принята. `pg_backup.py` не обновляет
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

17 checks passed (8 pipeline + 9 backup/restore): fingerprints всех46 таблиц совпали,
включая 45 domain/access tables и migration ledger. Сохранены UID, пользователи/права,
история, observations/receipts, outbox/retry. Текущий binary подтвердил все33 миграции,
`applied_migrations=0`; это не тест перехода со старой версии схемы.
После restore реальный server принял прежние admin credentials и вернул ту же карточку
через TLS API. Порча archive и nonempty target отвергнуты, sentinel table сохранена.
Временные БД, private archive и fixtures удаляются. Reports не содержат table contents/passwords.

## Оставшийся системный recovery

Для полной копии требуется согласованный checkpoint после остановки writers:
agent/collector state с origin keys/identity/counters/profile cache/очередями, server configs
и TLS/CA trust, PG, OpenBao Raft snapshot и audit, отдельное custody recovery/unseal материала,
точный signed release manifest и сведения о версиях. Снятый snapshot без recovery материала
не доказывает работоспособность Transit CA/receipt signing после потери узла.
Нельзя хранить root/unseal материал у application UID или в service unit/image.

На изолированном clean stand предстоит проверить Bao restore и scoped key operations,
возврат тех же source/asset IDs, replay pending/receipts без дублей и безопасную миграцию
со старого release. До переключения writers нужны проверки tenant/access/history/outbox,
подтверждённый единственный writer и проверенный путь возврата к целой копии.
Автоматического overwrite production storage, unsafe schema downgrade и удаления identities нет.
Лишь после полного restore rehearsal можно обновлять общий backup-age marker.
