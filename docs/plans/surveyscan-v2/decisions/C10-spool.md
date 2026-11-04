# C10 — локальная очередь и первые fault checks

2026-11-04. Решение для текущего SMB среза: сохранить существующий file-per-delivery формат,
общий Atomic(write/fsync/rename/dirsync) и один writer на локальную POSIX FS. bbolt1.5.0 из C01
был кандидатом, не подтверждённым runtime; новая зависимость/миграция формата здесь не вводятся.
Это не shared/NFS очередь. Linux lock освобождается ядром после SIGKILL; Windows C15 отдельно.

Agent state держит прежний process flock, collector.Run добавляет отдельный process flock на spool.
Два collector на разных listen ports не могут писать один каталог. Pump сериализован в процессе,
admission/receipt cache/GC защищены writer mutex. Source counters fsync до создания signed observation;
crash допускает пропуски sequence, не повторное использование. Некоммитнутые temp файлы удаляются
только после эксклюзивного захвата process lock, pending/receipt этим cleanup не затрагиваются.

Квота считает все файлы, включая receipt; data budget оставляет64KiB и два inode слота для ACK/recovery.
Max4096 files, byte bounds из private config. GC удаляет только committed receipt без pending того жеID:
после7d либо чтобы освободить место. Pending и rejected/quarantine никогда не вытесняются.
При нехватке места admission явно отказывает; старые данные сохраняются. Заполненный/quarantined
spool требует устранения причины/операторского разбора; автоматического удаления unack нет.
Физическое ENOSPC Atomic сохраняет прежнее committed содержимое, incomplete temp удаляется.

После crash между durable ACK и unlink оба sender/collector проверяют cached signed receipt и
bindings по исходному batch. Verified remove завершает unlink даже offline; rejected retain сохраняется
без повторной отправки неизменного payload. Неизвестный/недостоверный ACK права удаления не даёт.
Переключение generation/key/expiry и очередь старого signer относятся к C11; не сбрасывать counter.

Исходящие transient retries используют process-local exponential backoff1–60s base с±25% jitter
(0.75–75s фактически). Collector — отдельно на delivery; source — delivery pump. После restart retry
расписание начинается заново, durable данные/counters сохраняются. Persisted lease/fencing/admission
центра — C10.03, не считать реализованными из-за этого локального backoff.

Проверки: SIGKILL обоих реальных daemon при offline центре, сохранение байтов обеих очередей,
restart и reconnect→две observations/один UID/no duplicates/verified ACK drain. PG/TLS сохранённое
состояние crash-window ACK-write/unlink — отдельная fault injection, не физический power loss.
Real ENOSPC проверяется отдельным Go test binary в disposable64KiB Docker tmpfs, без сети/caps,
rootfs read-only, существующие dev volumes не трогаются. Quota/temp/retention/inode-reserve unit tests.

C10 целиком ещё не завершён: central processing claim/lease/fencing, staged payload accounting/retention,
reconnect burst/timeout/full fault matrix — оставшиеся03/04. Outbox C06 имеет atomic retry/dead-letter,
но это не доказательство готовности jobs scheduler (C12) или import worker claims.
