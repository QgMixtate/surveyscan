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

## Центральная обработка C10.03/04

Processing claims в imports — persisted row lease120s, random owner UUID, refresh перед Apply,
проверка owner/expiry и row lock в transaction checkpoint/final receipt. Старый owner после reclaim
не пишет checkpoint/receipt. Apply идемпотентен по immutable observation; если он успел commit до
потери lease, новый worker восстанавливает сохранённый result. Connection pool не удерживается
ожиданием session advisory lock. Конкурентный вызывающий ждёт короткими bounded context polls.

Failures без checkpoint progress: persisted exponential retry250ms–4s base±25%, после5 failures
state dead_letter. Progress сбрасывает failures; attempts всего сохраняется. Dead-letter не даёт
remove/подписанного успеха, HTTP503 DELIVERY_DEAD_LETTER. Failure code фиксированный, raw error не хранится.
Операторский повтор — privileged server DB/runbook до административного CLI C13: при разборе причины
сбросить state=pending,owner/lease_until/retry_at=NULL,failures=0 конкретного tenant/delivery. Не редактировать
payload/digest/result и не сбрасывать source sequence. Scheduler/jobs execution/API реализует C12;
C10 предоставляет проверенный import/outbox recovery foundation, не объявляет jobs handlers готовыми.

Admission сериализуется в tenant: defaults64MiB/256 active deliveries на collector,256MiB/1024 на tenant.
Учитывается только payload IS NOT NULL; partial index исключает scan всей исторической metadata.
Exact existing delivery того же active courier/source generation/digest может повторяться и при quota.
New origin должен оставаться active/authorized. Overload отвечает429 STAGING_FULL/Retry-After30.

Raw staging batch очищается в одной transaction с сохранением signed receipt только после всех
checkpoints; valid observations/sections/conflicts и result ledger остаются durable. Rejected material
остаётся в sender/quarantine; центр хранит его bounded reason/digest ledger, не выдаёт за observation.
SQL guard запрещает NULL payload без receipt. Cached receipt читается без повторного parse payload;
canonical JSON equivalence сохраняется после PostgreSQL JSONB serialization, байтовый порядок JSON не обещается.
Старые уже completed payload также освобождаются migration0029. Receipt/digest/owner ledger остаётся
для exact replay/409 conflict. Новый C10 SQL30,40 domain/access tables; applied0000–0028 не изменены.

Revoke-after-commit: active courier может дочитать exact previously staged/committed delivery.
Recorded path проверяет tenant/site/assignment/current source generation, original digest/key/signature,
игнорирует только origin active state для чтения immutable evidence. Новые observations после revoke
по-прежнему запрещены. Такой replay не обновляет facts/source freshness. Revoked courier сам недопущен.
При изменении generation/assignment не обещается обход текущего scope; renewal/reset policy C11.

Приёмка:24 concurrent direct service calls на real PG проверяют admission и processing burst,
lease takeover/stale owner, deadletter, GC/replay, revoked-origin recovery/forged signature.
Реальный TLS timeout и drop socket после commit до ACK сохраняют pending; retry получает прежний result.
Отдельный compiled binary smoke проверяет SIGKILL agent/collector/center, затем cached receipt после GC.
Это bounded reconnect profile, не production100users/большой шторм/physical power loss.
