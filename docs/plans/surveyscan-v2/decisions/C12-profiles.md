# C12 — центральные профили и диагностика

2026-11-04 (Москва). Additive C12/1.0 JSON schema/OpenAPI; C03/C09 bytes неизменны.
C12.02 software scope: agent cadence/heartbeat/spool, collector heartbeat/spool,
versioned publication, trusted delivery/application status. Collector autonomous network inventory — C16,
поэтому inventory_seconds у collector пока фиксирован900, попытка менять отклоняется.
Host adapter E1 собирает identity/os/network вместе, произвольные scripts/sections не принимаются.

## Публикация

Sources owns profiles/progress, append0031 (32migrations/44tables). Human GET/PATCH
/api/v1/sources/{source_id}/profile: server-derived tenant, sources:read/admin, Origin/CSRF при правке,
If-Match "profile:<source>:<revision>", missing428/stale412. Full bounded options heartbeat30–3600,
inventory60–86400,jitter0–25,spool524288–1GiB. Revision1 — unmanaged/local bootstrap,
первый publish revision2, далее monotonic uint64. Source pending/revoked/disabled не изменяется.
Update+source revision+audit source.profile_updated+outbox source.profile_updated.v1 атомарны.
Outbox aggregate version — source revision, payload содержит толькоsource_id; отдельная bus не нужна.

profiles get/set в surveyscanctl: --id UUID, --revision из предыдущего GET, --profile-file JSON
дляполного update. Нельзя указывать tenant вместо credential. Документ контракта доступен через
GET/api/v1/contracts/c12. Формат чётко отделяет managed/config/applied_revision,
last_config_contact_at,last_contact_at,last_successful_inventory_at.

## Доставка/подтверждение

POST/api/v1/machine/profile с origin-signed ProfileRequest: tenant/source/generation/key,
nonce32randombytes,sent_at,applied_revision(nullable). Домен SURVEYSCAN-PROFILE-REQUEST-V1.
Collector проверяет verified agentTLS/assignment/sourcekey proof, backend повторяет current courier/
source/generation/site/tenant/binding и подпись. Старше120s/более30sвбудущем/ACKfuture отклоняются.
Подтверждение revision — заявление origin, не независимая аттестация исполнения; courier его не подделывает.
Повтор запроса в timestamp window не создаётinventory/HB; last_config_contact отражает только config poll.
Applied revision monotonic в пределах generation; global resource inventory/UID/state не меняется.

Ответ подписан доверенным center receipt key в отдельном домене SURVEYSCAN-PROFILE-V1;
payload содержит origin/nonce/config/issued/expiry<=5min. Agent и collector сверяют pinned CA-attested
center key,nonce/scope/version/bounds/time,не принимают rollback или другой config под тем жеrevision.
C03 legacy GETmachine/config остаётся с исходным JSON shape и теперь читает actual profile;
новые clients используют authenticated/signed C12 route, не доверяют unsigned legacy relay.
Bao failure не вызывает local sign fallback: polling явноошибается, operatingcache остаётся доступен.

## Runtime/cache

Poll20s,bounded3srequestcontext. Baseline unmanaged1 не переопределяет local config. Published2+
authoritative,сохраняется atomic0600 profile.json с подписью. Restart переиспользует cache после проверки
signature/scope; expiry относится к приёму нового ответа, offline разрешено продолжать last valid
NONSECRET operating profile бессрочно с явно устаревающим возрастом. Это не новый auth/secret lease.
Corrupt/public/symlink cache не принимается. Currentsource/collector auth всегда проверяется центром;
offline невозможно обещать немедленный revoke/остановку уже запущенного сбора.

Изменение cadence пересчитывает будущий deadline; первый inventory на boot остаётся immediate.
Quota shrink не вытесняет pending: bounded admission/backpressure сохраняется. Source/generation/
origin key/sequences/pending не сбрасываются. Collector heartbeat имеет свой durable counter в
credential directory; challenge120s независим от configpoll/inventory. Legacy collector безorigin key/
credential state не poll-ит и не heartbeat-ит от собственного имени; нужен C11 config sample.

## Ограничения и приёмка

Server profile GETdesired/applied и reports не означают100users/24h/HA доказательства.
Collector last-contact должен идти от собственного signedheartbeat, не от пересылки agentdata.
Profile polling не означает successful inventory/freshness; source disabling/revoke не означает
массовый missing/decommission. Local host binding из C11 сохраняется.
Далее C12.03: tenant-scoped server/import/outbox diagnostics, source spool/disk/cert telemetry,
backup age неизвестен без настоящего backup marker; не подставлять0/"healthy" вместо unknown.
C12.04 — оператор меняет interval, наблюдает реальный цикл и опубликованный/applied revision.

Итог C12.03/04: runtime telemetry добавлен в optional diagnostics requestminor1.1,baseline1.0
безtelemetryпринимается. Read-only SourceProfile UI и docs доступны; metric/alert детали — C12-diagnostics.md.
Три real admin CLIpublish1→2→3→4,120→60 cadence после55–80s,offline/restart иrevoke прошли.
