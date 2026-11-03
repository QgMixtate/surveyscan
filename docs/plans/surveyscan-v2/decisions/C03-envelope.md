# C03.01 — наблюдение v1.0 и неизменяемое происхождение

Дата: 2026-11-03. Статус: инженерный контракт для реализации C04–C11, не выполненный сервер.
[JSON Schema 2020-12](../contracts/C03/schemas/wire.schema.json), [совместимость](../contracts/C03/compatibility.json),
[fixtures](../contracts/C03/fixtures/manifest.json). Модель C02 остаётся основой.

## 1. Payload и конверт

`SignedObservation` содержит `payload`, `digest`, `key_id`, `signature`.
Payload: schema_version `{major:1,minor:0}`, observation_id, tenant_id, origin source/kind/generation,
source_record namespace/local_id, site/network scope, source_sequence, collected_at, clock_quality,
identity_candidates и sections. Опциональны asserted_asset_uid, job reference и namespaced extensions.
Центр сам устанавливает received_at; origin его не задаёт. Collector не изменяет подписанный payload.

UUID передаются в стандартной текстовой форме; authority/tenant определяется регистрацией и
аутентификацией. UUID из payload — claim, не полномочие. Источник не может прислать произвольную
generation или scope. Origin source_id не меняется при смене транспортного collector.

Sequence/version — **десятичная строка uint64 от 1 до 18446744073709551615**, без ведущих нулей,
а не JSON number: браузер/канонизация не должны терять целые после 2^53. Sequence назначается
при сборе и сохраняется в spool. После потери state нужна новая авторизованная generation,
а не повторное использование старой с seq=1. У heartbeat свой независимый sequence.

## 2. Namespace и значения

Namespace source_record — lowercase ASCII `[a-z][a-z0-9._:-]{0,63}`; E1 значение `host`.
source_local_id — стабильный непрозрачный UTF-8 ID длиной 1–256 символов: сравнение точное,
без trim/casefold/NFC. Его нельзя вычислять только из текущего IP/hostname.

Candidate values сохраняются в исходном виде. Нормализация — по явно версионированному kind/namespace:
UUID canonical form, MAC lowercase colon, IP через стандартный parser; serial без универсального
casefold разных вендоров. Unicode hostname — weak evidence и отображаемое значение, не универсальный key.
Изменение правил нормализации не меняет старый подписанный payload или canonical asset_uid.

## 3. E1 секции и ограничения

Секции `identity`, `os`, `network`; имена в observation уникальны. Каждая имеет своё collected_at,
status, collection_complete, reason_code, record_count и records. `record_count == len(records)`.
identity: hostname, доступные machine/BIOS UUID; os: name/version/architecture;
network: interface name, optional MAC, IPv4/IPv6 addresses/prefix.

`ok` может быть пустым; `partial` не объявляет полную коллекцию. unavailable/unsupported/not_requested
не содержат выдуманные записи. `unknown` — только явно разрешённый legacy adapter, не native agent.
Нельзя стереть старые записи по отсутствию данных partial: правила C02 сохраняются.
Время UTC RFC3339 с `Z`, до 9 знаков долей секунды. Время секции не позже observation.
Разные точности timestamp сравниваются как время, а не лексикографические строки.
clock_quality источника — заявленное качество; доверенность определяет policy сервера.

Bounds v1: batch ≤1 MiB исходного UTF-8 тела, ≤100 records, observation canonical payload ≤64 KiB,
Глубина JSON ≤32, ≤3 секции и ≤512 network records. Schemas ограничивают длины строк/массивов; общий raw-size,
record_count, IPv4 prefix≤32/IPv6≤128 и uint64 проверяются также семантически.
Повышение limits требует capability/версии и resource проверки, не бесконтрольного обхода parser limits.

## 4. Canonical bytes, digest и подпись

1. Строгий JSON UTF-8: дубли ключей, NaN/Infinity, невалидный Unicode и сверхлимитное тело отклоняются.
2. Payload канонизируется по **RFC 8785 JCS**. Порядок properties/whitespace не меняет hash;
   порядок элементов arrays и Unicode code points сохраняется, NFC не применяется автоматически.
3. `digest = lowercase_hex(SHA256(JCS(payload)))`.
4. Ed25519 подписывает `ASCII("SURVEYSCAN-OBSERVATION-V1\n") || JCS(payload)`.
   В доменном префиксе `\n` — один байт LF (0x0a), не два печатных символа.
   Signature — unpadded base64url 64-byte подписи; key_id — зарегистрированный origin signing key.
5. Digest/signature находятся вне payload. Самоссылки hash нет. Batch digest — SHA256 JCS всего
   Batch, включая delivery_id и неизменённые подписанные records; receipt отдельно от batch.

Используются стандартные примитивы/библиотеки, не собственная криптография.
Источники стандартов: https://www.rfc-editor.org/rfc/rfc8785 и https://www.rfc-editor.org/rfc/rfc8032 .
Observation-signing key может отличаться от mTLS key. Нельзя автоматически доверять ключу,
переданному рядом с payload: binding source/tenant/key создаётся enrollment и проверяется центром.
Проверка криптоподписи подтверждает происхождение, а не истинность inventory хоста.

Пакет `.survpack` E2 с архивом/шифрованием на получателя здесь **не** реализуется: C23 определит
полный порядок упаковки/подписи/шифрования. E1 transport защищён TLS, signing сохраняет origin через relay.
Secrets/пароли/private keys не включаются в records. Строгая schema не доказывает, что секрет
не спрятан в строковом hostname: actual adapters и log sanitization проверяются отдельно.

## 5. Версии и допуски

Поддерживается ровно 1.0. Неизвестная major или не объявленная minor → 422 UNSUPPORTED_SCHEMA_VERSION.
Вне `extensions` неизвестные поля запрещены. Extensions — ограниченные namespaced x-* scalars,
а не способ передать remote command/секрет или без объявления изменить семантику projection.
Появление minor не означает автоматическую совместимость. Native unknown status и portable capability
явно gated; наличие формы source_kind=portable в общей schema не объявляет готовность portable E1.

Одинаковый observation key/digest — идемпотентный предыдущий результат; тот же ID/sequence key
с иными байтами — 409 конфликт. Duplicate observation_id внутри одного batch — 422;
повтор целого batch с тем же tenant/delivery_id/digest — прежний/current durable результат.
