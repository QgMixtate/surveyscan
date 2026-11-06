# C15 — отдельное чтение record facts 1.2

GET /api/v1/assets/{asset_uid}/inventory/facts/{section}
и OpenAPI GET /api/v1/contracts/c15. C03/C09 schemas и старый /inventory не изменены.
Это read API, не включение observation1.2 upload/relay/scheduler. Реальные Windows
provider rows ещё не прошли signed agent→collector→center→API. APIfixture синтетический.

Response schema_version1.2: tenant/asset/section, projection_revision, section_state,
items[{record_key,field,value,evidence}], next_cursor. value сохраняет JSON type;
схема проверяет допустимое имя/тип поля в зависимости от секции изC15draft.
У каждого поля собственное evidence; last_attempt показывает и неудачный сбор отдельно.
При отсутствии1.2попытки revision="0", section_state=null, items=[] — не пустой успешный сбор.
Это пагинация полей: одна provider record может продолжаться на следующей странице.
record_key — provider locator, не глобальный component UID/asset_uid.

Auth session/CLI + assets:read; composition root повторно проверяет credential и tenant-bound
asset в repeatable-read transaction до чтения evidence. User/credential locks сохраняются
как в существующем Authorizer (не PG READ ONLY, который запрещает FOR SHARE).
Другой tenant получает404 даже с действительным чужим cursor. Отзыв пользователя даёт401.
Query allowlist limit/cursor, один непустой value наkey, malformed escapes/semicolon rejected.
limit1–100(default50); JSON max2MiB включая metadata, SQL LIMIT limit+1 и keyset tuple.
JSON application/json+nosniff/no-store; HTML escaping disabled только для JSON encoding,
никакой интерполяции вHTML. Закрытый schema checker проверяет ответ до передачи клиенту.

Cursor — base64url JSON [tenant,asset,section,revision,record_key,field], max2048.
Он не credential/подпись и не даёт доступ: scope сверяется с authenticated tenant/asset.
Порядок tuple record_key/field фиксирован COLLATE C; полный PK остаётся tenant/asset/section.
Запросы одной страницы читают state+fields в одном snapshot. При изменении секции между
страницами старый cursor возвращает409 PROJECTION_CHANGED: начать чтение безcursor.
Это не durable historical snapshot export и не обещание доступности страниц без изменений.
Нельзя смешивать pages разных revisions; cursor на основе source sequence не используется.

Проверки: real TLS/auth/PG с committed signed synthetic fixtures и штатными deferred guards,
history/audit/outbox; прямой internal projection setup, без machine admission/collector.
1-field pages исчерпывают поля без дублей; per-field provenance/state, revision conflict,
empty/uncollected, invalid queries, foreigntenant404, viewer200/revoked401. Unit schema/type/
count/byte/ordering/duplicate/cursor scope и compiled OpenAPI component parity.
Оставшиеся C15gates: complete provider coverage/deletion, negotiated signed envelopes/limits,
independent collection/heartbeat, Web rendering, Windows DACL/locks/SCM/rights/reboot.
