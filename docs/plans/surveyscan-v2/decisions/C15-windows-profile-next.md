# Следующий блок C15.02 — Windows profile и подключение runtime

Статус: planned, не реализовано. Порядок сохраняет текущий default-off режим и
не меняет принятый Linux E1/candidate. Native SDK/подписи/relay/actor сами по себе
ещё не являются работающей Windows-службой.

## Контракт и владение

1. Новый C15 profile contract1.2, отдельные DTO/schema/подписи и endpoint
   /api/v1/machine/inventory-profile. Observation1.2, batch1.2, profile1.2 — три
   независимо проверяемые версии. C03/C09/C12 endpoints и схемы неизменны.
2. Профиль явно задаёт Windows/amd64, фиксированный read-only baseline всех12
   секций, partial-only/no-deletion, лимиты worker/payload/batch/spool. Не принимает
   executable, shell, произвольный query/path/remote target. Ни команды служб,
   ни конфиги/пароли/ключи не становятся inventory fields.
3. Cadence/jitter/spool берутся из существующего Sources profile как общего
   источника, без второй конфликтующей настройки interval. Статический baseline
   имеет явный policy_id; его смысл не меняется под прежним ID. Effective revision
   — пара common-config revision + policy_id, а не один случайно совпавший номер.
4. Windows applied-progress отделяется от C12 progress: ACK только после durable
   cache commit, с source/generation/effective revision. Для этого нужна новая
   append-only Sources migration и отдельный API view; прежний C12 applied_revision
   не доказывает применение12секций. Не редактировать applied SQL0000–0033.
   При добавлении0034 сдвинуть private update fixture на0035, catalog/schema/table
   expectations, backup fingerprint count и boot fixture; сохранить checksum guards.

## Подписи и доставка

5. Agent подписывает nonce/tenant/origin/generation/platform/known revision новым
   отдельным request domain. Collector проверяет peer agent/assignment/signing key,
   пересылает исходный frame от своего mTLS. Center повторно проверяет active tenant/
   source/generation/revocation/assignment + agent key и signature внутри tx; platform
   из запроса — capability claim, не доверенный факт об ОС и не authorization.
6. Center подписывает origin-bound response с nonce, issued/expiry, двумя revisions
   и готовым effective config через существующий nonexportable Transit. Collector
   и agent проверяют enrollment-pinned center key. Ни одного local-key fallback при
   отказе внешнего signer. Collector не переписывает профиль и не выдаёт новый root.
7. Fresh three-hop capability proof обязателен перед первоначальным принятием12.
   Byte limits = минимум agent/collector/center/profile, с ACK+packet reserve.
   Профиль не разрешает расширить negotiated ceilings. Прежние staged bytes никогда
   не конвертируются/переподписываются при downgrade или смене policy.

## Время и offline

8. Provider30s + WaitDelay1s относятся к одной секции; весь sweep может длиться
   дольше. Отдельный signed overall collection budget обязан учитывать12 workers
   и startup/reap overhead. Для baseline предлагается420s при per-section30s;
   validation не допускает незаметно подставить Linux30s для всего Windows sweep.
   Ровно один collector task, heartbeat/state actor продолжается независимо.
9. Expiry capability/profile frame защищает свежее принятие/replay, а не заменяет
   server-side authorization каждой observation. Offline после успешного принятия
   может использовать последнюю durable проверенную конфигурацию в её byte bounds.
   Это отдельный cache validator: никогда не принимает впервые expired frame;
   проверяет обе signatures, pinned keys, origin generations, локальный host binding
   и monotonic effective revision. Старый ответ нельзя представить как свежий.
   Смена issuer/source generation или явный fresh offer без12 запрещает новые12
   collection attempts до согласования; pending сохраняется для replay. Отсутствие
   сети не подменяется ложным heartbeat/config contact или inventory success.
10. Новый runtime не включать, пока Windows private files/DACL/reparse protection,
    exclusive writer lock, atomic durable state и MachineGuid continuity не проверены.
    Следующая независимая подготовка C15.03 может реализовать эти prerequisites;
    C15.02 не закрывать по Linux testdouble или только cross-build.

## Проверки и публикация

11. Closed schema fixtures: wrong version/platform/sections/duplicates/script fields,
    invalid budgets/unsafe limits/revisions; role/domain/key/nonce/generation replay.
    PG real mTLS: inactive/foreign source/collector/revoked key, signer503/no fallback,
    durable applied-progress only after ACK, cadence/policy revision conflicts.
12. Native Windows: получить профиль, выполнить bounded12сбор и отправить исходные
    подписанные данные через collector→center→PG→typedAPI; field provenance и secret
    canaries, один отказавший provider, offline+restart+original bytes/UID, old peer.
    Hosted elevated Windows2022 не заменяет ordinary rights/Windows11/SCM/reboot.
13. Exact-SHA hosted CI, sanitized reports, STATUS/REQUESTS/plan/handoff. Не увеличивать
    global57done и не переходить к C16 до реальной приёмки пакета. Нет main merge,
    official release, production deploy или cloud settings publication.
