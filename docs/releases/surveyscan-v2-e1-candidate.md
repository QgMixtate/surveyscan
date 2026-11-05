# SurveyScan v2 E1 — предварительные release notes

Статус: **кандидат для проверки, SMB-релиз ещё не принят**. C14.02 выполняется, C14.03/04
ждут полного результата. Этот документ не означает публикацию тега, GitHub Release или deployment.

## Что подготовлено

Постоянный Linux host agent собирает сведения своего хоста и передаёт подписанные observations
назначенному site collector. Collector сохраняет пакеты и доставляет их в combined Go server;
PostgreSQL хранит реестр, историю, ответственность, профили и outbox. OpenBao обслуживает
scoped/non-exportable ключевые операции. Asset UID постоянен; source IDs и маршрут доставки отдельны.

Отдельный Web UI показывает список/карточку, IP/MAC/provenance/sections, ответственность и health
источника. Human CLI работает только через API: login/context/logout, assets/sources/status,
profiles и diagnostics. Tenant/role/Origin/CSRF проверяет backend, сессии переживают restart.
Spool/ACK/retry/quotas и backup/restore/checked update входят в E1; внешняя шина не требуется.

Внутренний кандидат: Go **0.0.0-c13**, Web **0.1.0-c14-web**, source **8560f57**,
Linux/amd64. Все четыре Go components и Web имеют source_dirty=false. Три daemon binaries
побайтно совпадают с работающим суточным комплектом; дальнейшие commits меняют тесты/документы.
Подготовлено27 public files с checksums/SPDX/schema/units. Manifest SHA256:
`0159a7ea65ed5281333892b9e447e7812696275951ec951deda27ad8b0995834`.

Кандидат подписан временным **test** Ed25519 key, проверен через отдельный test public anchor и
установлен только в пустой local staging root. Private signing key удалён. Это не production trust;
пользовательские secrets/identities/spools/backups в bundle отсутствуют. Артефакт не опубликован.
[Candidate evidence](../plans/surveyscan-v2/evidence/C14-candidate.json).

## Выполненные проверки

- C13: два свежих Debian12/systemd VM9+9, настоящий kernel reboot/autostart/nonroot/LoadCredential,
  operator unseal, UID/queues, combined checked update и CLI/Web. PG/Bao/files checkpoint и schema-safe
  recovery проверены отдельно. [Runtime](../plans/surveyscan-v2/evidence/C13-runtime.json),
  [hosted C13](../plans/surveyscan-v2/evidence/C13-published-final.json).
- C14:43 top-level Go tests +3 subtests,58 C03 fixtures; исходные import/contract guards сохранены,
  добавлен SQL ownership guard. [Architecture](../plans/surveyscan-v2/evidence/C14-architecture.json).
- Reconnect5: три реальных agent процесса на одном хосте, явный quota fixture, сохранность pending/
  sequence, bounded retries, simultaneous reconnect/четыре пустых очереди, повтор без новых эффектов.
  Настоящий ENOSPC проверен отдельным disposable tmpfs сценарием.
- Точные Web/Go candidate artifacts прошли Chromium16: auth/assets/profiles через реальный PG/API,
  partial/stale/unknown display matrix — явно mocked responses. Нет external runtime requests.
  [Browser](../plans/surveyscan-v2/evidence/C14-candidate-browser.json).
- Короткий preflight121.597s прошёл, но никогда не заменяет сутки.

Последний hosted1a6c611: v2/Web SUCCESS, повторный boot failed во второй VM. Причина старым
supervisor не сохранена; безопасная phase/line диагностика и повторные независимые стенды в работе.
Нельзя выдавать прежний C13 PASS за результат этого неуспешного повторения.

## Оставшиеся обязательные условия

Реальный24h run `10812e7a-8a6a-4dae-9dd5-b0583f503c83` начался5 ноября2026 в00:31:49UTC.
Завершение возможно **не раньше6 ноября00:31:49UTC** и только после проверки всех faults,
свежести, sequence/UID, обеих очередей и настоящего обновления machine certificates.
Проверять живой PID/свежие samples; работающий marker без процесса — не приёмка.
[Soak snapshot](../plans/surveyscan-v2/evidence/C14-soak.json), [инструкция](../../v2/deploy/SOAK.md).

После полного окна: C14.03 — разобрать фактические дефекты и повторить затронутое; C14.04 —
утвердить фактический acceptance report, артефакт/notes/operations и необходимые publication steps.
До этого C14 не done, C15 не начинается. Production signing/trust distribution остаются отдельным
операторским действием; merge/main/production deployment не выполнялись.

## Установка и ограничения

Target подтверждён на Debian12/amd64/systemd252. Оператор предоставляет PostgreSQL17,
OpenBao2.7.2, TLS/static edge, policy/CA/trust/custody и scope/source provisioning.
[README](../../v2/README.md), [systemd](../../v2/deploy/systemd/README.md),
[release](../../v2/deploy/RELEASE.md), [update](../../v2/deploy/UPDATE.md), [backup](../../v2/deploy/BACKUP.md).
Managed build host не получает system services. Runtime Go/static Web не требует Go compiler/Node;
operator tools требуют Python3/OpenSSL3. Не сбрасывать applied SQL/Bao/identity/state ради запуска.

Это не доказательство100users/SLA, production KMS/split custody, HA/geo/physical power loss.
Одинаковые machine-id+private keys не различают физические клоны; expired identity fails closed,
автоматический administrative reissue не реализован. Combined — текущий профиль; pgx.Tx ports
пока связывают E1 транзакции, выделение сервисов требует дальнейшей переработки.
Windows/agentless/discovery/topology/portable — E2; advanced reconciliation/full-text/100users — E3;
независимые production API/worker/шарды/geo — E5. ЖЦ/склад/запчасти и ITSM — последующие волны.
