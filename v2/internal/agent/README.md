# Минимальный Linux host agent (C08)

Сбор read-only, без shell и входящего listener. Только identity/ОС/локальные IP/MAC;
никаких PostgreSQL credentials, remote target secrets или ключа CA на хосте.
Linux machine-id — candidate, не asset_uid. UID назначает реестр по зарегистрированному origin.
Windows и расширенные поля — последующие пакеты. Неполный сбор помечается явно.

Private agent.json (0600, примеры UUID заменить своим tenant/site/scope/collector source):

```json
{
  "tenant_id": "11111111-1111-4111-8111-111111111111",
  "site_id": "22222222-2222-4222-8222-222222222222",
  "network_scope_id": "33333333-3333-4333-8333-333333333333",
  "collector_url": "https://collector.example.org:8443",
  "collector_source_id": "44444444-4444-4444-8444-444444444444",
  "ca_certificate_file": "/etc/surveyscan-agent/trusted-ca.pem",
  "state_directory": "/var/lib/surveyscan-agent",
  "inventory_seconds": 900,
  "heartbeat_seconds": 60,
  "jitter_percent": 10,
  "spool_limit_bytes": 67108864
}
```

Trust CA доставляется заранее доверенным способом. TLS проверяет CA, source DNS/SNI из
collector_source_id, tenant и назначенный logical collector. HTTP/redirects/insecure fallback запрещены.
Collector URL задаёт адрес соединения; идентичность peer проверяется по CA-attested source certificate.

```sh
surveyscan-agent prepare --config /etc/surveyscan-agent/agent.json > /secure/preparation.json
# Администратор использует source_id/csr_sha256/signing_public_key из preparation
# в POST /api/v1/enrollments (source_kind=agent, site_id, collector_id, ttl_seconds).
# Ответ EnrollmentGrant с token сохранить в grant.json 0600; не передавать token в аргументах.
surveyscan-agent enroll --config /etc/surveyscan-agent/agent.json --grant-file /secure/grant.json
surveyscan-agent run --config /etc/surveyscan-agent/agent.json
```

Prepare не заменяет существующую identity. TLS key и Ed25519 observation key различаются.
Enrolled identity проверяется по root CA и matching CSR key; center ACK key сверяется с CA claims.
Config/state/keys должны принадлежать пользователю службы. State0700, private files0600.
Шаблон systemd: deploy/surveyscan-agent.service; установка/enable не выполняются C08 smoke.
Production CA issuer/renewal/rotation OpenBao — C11; systemd acceptance — C14.

Inventory и heartbeat имеют отдельные durable uint64 counters. Перед использованием sequence fsync;
пропуски после crash допустимы, повтор sequence не создаётся. Flock запрещает два writer-процесса
на одном state directory. Начальный inventory сразу, следующие по интервалу60–86400s+jitter;
heartbeat30–3600s+jitter, отдельный свежий challenge120s центра и origin signature.

Pending batch сохраняется до отправки атомарно с fsync; transport receipt означает retain.
Agent сам проверяет center signature/key/tenant/batch/каждый record перед удалением.
Offline, неизвестный ACK и rejected сохраняют packet. Предел pending spool вызывает backpressure;
он не удаляет старые данные. Полная quota/receipt GC/backoff/disk-fault матрица — C10.
Если state/sequence потеряны, не копировать чужие keys и не обнулять sequence: generation reset C11.

Для live проверки: contract Python scripts/agent_smoke.py после make build и dev.py up.
Три автоматических реальных цикла по60s, heartbeat30s, три бинарника, TLS/mTLS и isolated PG.
Facts/keys не включаются в итоговый отчёт. Скрипт удаляет только свои private files/DB.

C10.01/02: квота теперь включает receipt и оставляет ACK reserve; GC удаляет только receipt без pending,
через7d/при capacity pressure. Pending/rejected не вытесняются. Cached signed ACK после crash позволяет
закончить удаление offline; rejected receipt исключает повторную отправку. Retry1–60s base±25% jitter,
после restart schedule начинается заново, counters/data сохраняются. Политика docs/decisions/C10-spool.md.
Central leases/admission и bounded overload/timeout matrix C10.03/04 завершены локально;
large production storm/24h остаются эксплуатационной проверкой.

C11: обычный TLS renewal сохраняет source/generation, observation signing key и counters.
`surveyscan-agent renew --config ...` выполняет немедленное продление под daemon lock;
Run пытается продлить сертификат за1h до expiry, pending retry раз в минуту.
Новый TLS key+CSR+proof сохраняются до отправки, затем matching cert/key одним tls-identity.json0600.
При потере ACK повторяется тот же pending request. Начальные tls.key/identity.json не удалять:
rotated bundle имеет приоритет; повреждённый bundle не вызывает fallback.

Prepare привязывает новый state к Linux /etc/machine-id через локальный HMAC, raw machine-id
в host-binding.json не хранится. Copy state при отличающемся machine-id запрещает startup/renewal/
inventory/heartbeat; source/generation/sequence не сбрасываются. Для pre-C11 state без binding оператор
сначала проверяет исходный хост/source/UID, затем останавливает daemon и выполняет один раз
`surveyscan-agent bind-host --config ...`. Команда не перезаписывает несовпадающий существующий binding.
Это защита от случайного копирования, не hardware attestation: одинаковые machine-id+keys неотличимы.
Не включать state/keys/machine-id в golden image; новый хост генерирует machine-id и новый prepare/grant.
Если machine-id недоступен/сменился, не удалять binding для обхода: сохранить state и разбирать continuity.

После TLS expiry network renewal не обходит mTLS. Сначала проверить часы/путь к Bao/сети;
если действующий rotated bundle отсутствует, остановить службу и сохранить обе очереди для оператора.
Автоматического expired-identity reissue в E1 пока нет; новый source/grant требует административного
решения о continuity и старых pending. Нельзя переименовать старый batch под новый source или сбросить counters.
