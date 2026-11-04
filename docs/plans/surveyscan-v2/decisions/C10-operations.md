# C10 — разбор dead-letter и заполненной очереди

Нужны права администратора своей установки; application identity не используется для произвольного SQL.
Сначала проверить tenant/delivery, failure_code/state/failures, существующий result/receipt и причину отказа.
Не удалять pending/quarantine ради освобождения места; допустимы увеличение лимита в разрешённых bounds,
восстановление подключения и разбор rejected записи. Expired process lease восстанавливается автоматически.
Raw ошибки/секреты не копировать в журналы; log only IDs/status/counts.

При исправленной transient причине и dead_letter допускается privileged retry только конкретного delivery:

```sql
BEGIN;
SELECT state,failures,failure_code
FROM imports.processing_claims
WHERE tenant_id = :'tenant_id' AND delivery_id = :'delivery_id'
FOR UPDATE;
UPDATE imports.processing_claims
SET state='pending',failures=0,retry_at=NULL,owner=NULL,lease_until=NULL
WHERE tenant_id = :'tenant_id' AND delivery_id = :'delivery_id' AND state='dead_letter';
COMMIT;
```

Использовать psql variables из проверенного собственного ID, не подставлять команды из payload.
После этого повторный запрос active owning collector возобновит checkpoint pipeline; уже committed
observations не применятся второй раз. При existing signed receipt reset обычно не нужен.
Операторский HTTP/CLI flow C13. Нельзя переписывать digest/canonical observations/checkpoints или
переименовывать чужой источник для обхода revoked/current generation/tenant checks.
Source/collector renewal и expired identity требуют C11 policy, не отмены TLS проверки.
