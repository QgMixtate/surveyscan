# C03.04 — исполнимые примеры и проверка контрактов

Дата: 2026-11-03. Статус: схемы и эталонные примеры проверены, сервис ещё не реализован.
Основные файлы: [manifest](../contracts/C03/fixtures/manifest.json),
[OpenAPI](../contracts/C03/openapi.json), [схемы](../contracts/C03/schemas/wire.schema.json),
[совместимость](../contracts/C03/compatibility.json), [состояния](../contracts/C03/state-machines.json).

## Что фактически выполнено

- JSON Schema 2020-12 meta-validation и OpenAPI 3.1 validation без обращения к удалённым `$ref`.
- 58 контрактных примеров: 19 допустимых, 39 негативных; ожидаемые результаты совпали.
- 12 проверок рёбер машин состояний jobs/delivery/consumer.
- 2 независимых golden-вектора canonical JSON UTF-8 (порядок полей, Unicode и нормализация 1.0).
- 3 HTTP request/response **формы** сопоставлены с OpenAPI; реальные HTTP-запросы не выполнялись.

Проверяются strict JSON/Unicode/depth, uint64 в строке и overflow, unknown major/minor,
неверный tenant/source/generation, digest/signature, дубли секций/records, partial semantics,
IPv4 prefix, forged center result/batch binding, fresh/expired/replayed heartbeat,
prebound enrollment CSR/public key и renewal proof, pending-resolution и rejected trim policy.

Fixtures используют ephemeral Ed25519 keys для создания синтетических подписей и CSR;
private keys не сохранялись. В fixture contexts — только synthetic IDs, public keys, nonce и
декларативные разрешения/состояния. Это **не** настоящие mTLS identities/secret bindings и не production данные.

## Воспроизведение

Инструменты установлены вне приложения: `/workspace/.surveyscan-contract-tools`.
Для другого окружения создать отдельный venv и установить зафиксированные зависимости
из [requirements.txt](../contracts/C03/checks/requirements.txt) с обычной TLS/checksum verification.

```bash
cd /workspace/surveyscan
/workspace/.surveyscan-contract-tools/bin/python \
  docs/plans/surveyscan-v2/contracts/C03/checks/validate_contracts.py \
  docs/plans/surveyscan-v2/evidence/C03-contract-validation.json
```

Runner сохраняет actual/expected по case ID, версии инструментов, counts и ненулевой exit status
при несовпадении. Не перенаправлять результат через команды, скрывающие его exit status.
Reference checker — пример трактовки контракта, не Go-handler и не замена server authorization.
Нельзя выдавать декларативный fixture context за исполненную проверку PostgreSQL/lease/revocation.

## Что ещё unrun

TLS handshake, trusted proxy identity, реальный enrollment consume/renew/revoke, обработка headers,
CSRF/session/cookie, DB uniqueness/locks/commit, настоящий upload/ACK, source clocks, lease races,
crash/outage/rebuild, подпись receipt только после commit и 24ч непрерывная эксплуатация.
Приёмочные сценарии C01 остаются unrun до пакетов реализации.

В C04 нужно подключить эти схемы/fixtures к CI и будущему Go-контракту, сохранив локальные
положительные/отрицательные примеры. Runtime проверка проводится против действующих handlers,
а не новым запуском этого reference checker. Версии/lockfiles приложения фиксируются отдельно.
