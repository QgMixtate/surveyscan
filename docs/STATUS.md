# Текущее состояние surveyscan

Обновлено: 6 ноября 2026. **C14 принят в пределах Linux E1; 57/200 задач выполнены.**
C15.01 завершён как проектирование, C15.02 — in_progress; C15.03/04 и C16–C50 ещё не приняты.

Текущая ветка — `codex/v2-c15-windows`, worktree `/workspace/surveyscan-c15`,
[draft PR №5](https://github.com/QgMixtate/surveyscan/pull/5), база — ветка E1 из
[PR №4](https://github.com/QgMixtate/surveyscan/pull/4). Main не слит, официальный release,
production deployment и повторная публикация настроек среды не выполнялись.

**Последний код — fbca7ac: collector relay 1.2.** Отдельный private-флаг
`inventory12_enabled` у центра и коллектора выключен по умолчанию. Новый режим связывает
admission, проверку origin/signature/scope, транзакционную проекцию всех 12 частичных секций,
историю/audit/outbox, версионированное чтение и проверку прежнего signed ACK 1.0.
Снимки complete/ok 1.2 отклоняются до реализации provider-scoped deletion.
Старые C03/C09 контракты неизменны. Каталог SQL: 34 миграции / 47 owned tables;
применённые SQL не редактировались, новые таблицы добавлены миграцией 0033.

Фактически проверено локально: PG58; verify/C03 58; wire/collector race; Windows cross-build/vet.
Скомпилированный center-only case: 6 проверок. Полный data relay: 9 проверок с настоящими
mTLS, scoped nonexportable OpenBao Transit, PostgreSQL и API. Данные агента синтетические,
соответствуют Windows schema 1.2. Отключение своего центра, cold restart collector+center,
повторная отправка sequence2 сохраняют исходный batch и один UID (2 observations / 1 asset).
Удаление pending — только после проверки подписанного ACK. Конфигурационный downgrade
сохраняет staged bytes до lease/retry; уже committed ACK остаётся доступен.

Публикация fbca7ac подтверждена: все пять hosted workflows — SUCCESS, включая полный v2
42227311999 и две fresh Linux VM. [Точные runs](plans/surveyscan-v2/evidence/C15-hosted-fbca.json).
Последний handoff: [C15](plans/surveyscan-v2/handoffs/C15.md),
[relay evidence](plans/surveyscan-v2/evidence/C15-relay.json).

**Новый local increment — authenticated capability exchange agent→collector→center**:
[точный план](plans/surveyscan-v2/decisions/C15-agent-capability-next.md).
Collector outer frame и Go agent method реализованы: обе подписи/ключи/nonce/tenant/
audience/generation/expiry, quota-aware ceilings и intersection всех3offers.
Actual compiled mTLS/scopedTransit/PG relay10 прошёл с Python syntheticagent; отдельно
Go agent method через настоящий mTLS с production collector/center signing testdouble.
verify/C03 58, PG58, race agent/collector/wire и Windows cross-build passed. Публикация
нового increment pending; daemon метод ещё не вызывает. Next — Windows profile1.2.
Далее — Windows profile 1.2, независимая bounded collection/heartbeat, DACL/locks/host
binding, SCM/service/update, обычные права/Windows11/настоящий reboot и provider coverage.
Native SDK 12 baseline секций ранее проверен на WindowsServer2022/elevated; это ещё не
постоянная служба Windows и не полная приёмка C15. Продолжать автоматически по R-020/022/023.

C15-D03 (COM stdout bound), D04 (boot fixture33→34) и D05 (JSON HTML expansion в spool)
исправлены; исторические failed runs сохранены в [журнале](plans/surveyscan-v2/evidence/C15-defects.json).

E1: реальный soak86400,914с,2740 измерений,1419 observations,два продления сертификатов,
пустые очереди/один UID/без дублей — frozen source8560f57. Auth5→8с проверен отдельно
на39e401f (Argon2/лимиты попыток/hashslots не ослаблялись), all4 hosted SUCCESS и VM9+9.
[Приёмка](plans/surveyscan-v2/evidence/C14-acceptance.json),
[кандидат](plans/surveyscan-v2/evidence/C14-candidate-39.json):27 файлов, verify/staging,
Chromium16, тестовый ключ удалён. C15 не подменяет frozen24h или этот внутренний candidate.

Локальные C15 стенды используют C15 binaries и свои DB/порты/scoped mounts; общие E1 dev
credentials/Compose переиспользуются без копирования private keys. Новые private reports —
только C15/.local. Не запускать C15 dev up/down/reset с совпадающими E1 project/ports.
История и подробности — docs/REQUESTS.md; 57done в plan/CSV не менять без приёмки задач.

Новый scheduler localpassed: один read-only collection task вне actor; state/TLS/
counters/spool остаются serial. Heartbeat при blocked collection, no overlap/late
success discard проверены с HTTPS testdouble; compiled live Linux11 passed
(3cycles+restart4th/sameUID/verifiedACK/lock/revoke). verify/build/C03 58/race/
Winbuild passed. Publication pending; Windows daemon/новый24h unrun.
[Доказательства](plans/surveyscan-v2/evidence/C15-independent-collection.json).
