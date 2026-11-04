# C07 — enrollment, relay и подтверждение центра

2026-11-04, локальная реализация C03 wire1.0. Origin source не меняется при relay.

Enrollment grant выдаётся администратором своего tenant, привязан к source/site/назначенному collector,
SHA256 CSR DER и отдельному Ed25519 public key observations. Token одноразовый, hash в PG, TTL/rate limits.
CSR доказывает владение TLS key; subject/SAN из CSR не копируются. Issuer назначает source/generation/
collector/signing-key claims. Точный concurrent retry возвращает тот же публичный результат.
Ревокация блокирует machine identity и ingest binding; активность повторно проверяется в write transaction.
Чужие source/collector/tenant не дают права relay. Collector id отличается от origin source id.

В dev используется явно заданный file-backed x509 CA и center signing key, только loopback listener.
Ничего не генерируется автоматически при старте server, private files0600. Production issuer/rotation/
renewal через OpenBao — C11. Bootstrap TLS проверяет заранее установленный CA; доверять CA из ответа нельзя.
Center receipt public key и ID включены в CA-подписанный identity certificate; клиент проверяет их
совпадение с enrollment result. Relay не может заменить этот ключ на собственный через response.

Collector принимает agent batches по mTLS. Проверяет source/generation/assignment, схему, digest,
исходную Ed25519 подпись по CA-attested key. До transport202 сохраняет packet атомарно с fsync файла/
каталога. Transport retain не разрешает удалять исходные данные. Локальный pending spool ограничен.
Центр валидирует batch до применения, durable staging/checkpoints принадлежат imports; реестр сохраняет
observation/result/history/audit/outbox транзакционно. Commit реестра до checkpoint переживает retry
через идемпотентность observation. SignedCenterResult сохраняется с финальным состоянием delivery;
конкурентные финализаторы возвращают один cached receipt. Статус доступен только владельцу доставки.

Collector проверяет известный CA-attested center key, JCS digest/Ed25519 domain и все bindings:
tenant/delivery/batch digest, source/observation ID/digest, ровно один result на record.
Receipt сохраняется durable до удаления pending. Удаление допустимо только при remove всех records.
Pending resolution может удаляться из sender spool после durable evidence в центре; rejected сохраняется.
Недоступность центра, transport ACK, неверная подпись/key/bindings не удаляют packet.

Предел C07 — первый bounded JSON путь и синтетический источник. Heartbeat/live agent — C08.
C10: полноценные admission/storage quotas (включая receipts), leases, disk fault/recovery/backoff matrix,
GC и длительные outages. При гонке revoke/parallel processing возможен консервативный rejected/retain
вместо прежнего applied; данные сохраняются, дальнейшее уточнение входит в C10. Нет заявления SLA100
пользователей/24h/production-ready. Agentless/network discovery и portable — последующие пакеты.
