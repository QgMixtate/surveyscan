# C03 contracts v1.0

Это контрактный комплект E1: 26 операций OpenAPI и 54 schema definitions.
Он не означает, что сервер/collector/agent уже предоставляют эти endpoints.

- [OpenAPI 3.1](openapi.json) — self-contained components, security и HTTP формы.
- [JSON Schema](schemas/wire.schema.json) — self-contained `$defs`, выбранная схема указывается по имени.
- [Совместимость и limits](compatibility.json).
- [State machines](state-machines.json) — guards описаны отдельно от допустимых рёбер.
- [58 fixtures](fixtures/manifest.json), [HTTP формы](fixtures/http-examples.json), [JCS golden vectors](fixtures/canonical-vectors.json).
- [Validator](checks/validate_contracts.py), [reference checks](checks/reference_checks.py), [tool dependencies](checks/requirements.txt).

Нормативные инженерные пояснения: [envelope](../../decisions/C03-envelope.md),
[protocol](../../decisions/C03-protocol.md), [jobs/events](../../decisions/C03-jobs-events.md),
[область проверки](../../decisions/C03-fixtures.md).
Всё подготовлено как вход C04 и последующих пакетов реализации; публикация в GitHub не выполнялась.
