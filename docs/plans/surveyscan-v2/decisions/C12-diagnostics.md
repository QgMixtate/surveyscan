# C12 — диагностика, метрики и операторский сценарий

C12.03,2026-11-04 (Москва). Additive source profile requestminor1.1: необязательный diagnostics
защищён origin signature; minor1.0 остаётся допустим безtelemetry. C03 версии/JSON не менялись,
profile response по-прежнемуminor1.0. Старыйcollector/server, не знающий1.1, отвергает запрос;
client явно использует retained operatingcache, не переключается на unsigned/insecure канал.

## Источники

RuntimeDiagnostics: collected_at,pending_files,pending_bytes,oldest_pending_at,disk_available_bytes,
certificate_expires_at. Толькометаданные,безhostfacts/paths/keys/targetsecrets. Boundedscan<=4096files,
толькоregular pending,receipt не считается pending. Diskavailable — Statfs/Linux,на другойОС null.
Agent/collector обновляют private diagnostics.json0600 и подписывают telemetry при profilepoll20s;
local-status --diagnostics-file PRIVATE работаетбезцентра,строго проверяетshape,не печатаетcontextфайлы.

Append0032: Sources.runtime_diagnostics с tenant/source/generation,received_at отдельноотreportedtime.
Backend проверяет подпись/scope/clock/bounds; monotonic collected_at не заменяется старымreplay.
Telemetry — заявление origin, не hardware attestation и не successfulinventory. Certificateexpires
в reportedruntime получен локальнымTLSclient/provider,в sourceidentity отдельно показан maxknown validexpiry
из PG. Нельзя считать ниavailability,ниinventory freshness по одномуpoll.

## Сервер и приватность

GET/api/v1/diagnostics: JSONsnapshot C12/1.1; GET/api/v1/metrics: Prometheus exposition.
Оба требуют auth sources:read и server-derived tenant. СобственныйmoduleSQL: Sources дляsourcehealth,
Imports дляpendingraw/age/retry/deadletter,Messaging дляoutboxconsumer registry-version lag.
App толькоагрегирует. Ключи/valuesсекретов/errorstrings в metrics не включаются. Scraper может
использовать существующий ограниченный Bearer sources:read,CLI пока session-based.

Source rows максимум1000; truncation явноотмечен+alert. Не выдаватьзаwholefleethealthприtruncation.
HBage и inventoryage независимы; configdesired/applied отдельно. Старый pendingpayload с ужеcommitted
signedreceipt не считаетсяочередью послеGC. У очереди безpending oldestage=null,а не выдуманныйtimestamp.
Prometheus unknown gauge не публикуется как0; backup_age_known=0 обозначает отсутствиеevidence.

## Backup и предупреждения

Backupage=null поумолчанию. SURVEYSCAN_V2_BACKUP_MARKER можетуказыватьprivate0600 JSON
{"completed_at":"<UTC timestamp>"}; future/invalid/missing→unknown. Marker толькоотоператора/реального
успешногоbackupworkflow C13,не создаётсяhealthchecker-ом. Самbackup/restore здесь не реализован.

Alerts: BACKUP_AGE_UNKNOWN/BACKUP_TOO_OLD>24h; import/outbox deadlettercritical иbacklog>5min;
sourceHBunknown/stale>3intervals;desiredprofileunapplied; runtimeunknown/stale>90s;
spooldisk<128MiB,oldestpending>5min; certremaining<1h/expiredcritical. Это defaultoperational thresholds,
не SLO/100users. Portable и revoked/disabled sources не получают continuous-heartbeat alerts.
Ниодинalert не списываетактив/не создаётmassmissing. Source state — регистрация,не assetpresence.

Logs agent/collector — JSON сat/component/fixedevent,безсырогоHTTP/SQLerror/credential. Existing eventcodes
сохранены. CLI diagnostics возвращаетsnapshot; --output table дляreadresources показываетwhitelistcolumns,
unknown явно; controlcharacters изdevicefacts удаляютсяпередterminalrender. JSON остаётсяdefault.

## UI/оператор

Sources UI имеетread-only profilepanel: local/centralmode,desired/appliedrevision,inventory/HBinterval,
configcontact и successfulinventory. ResponseпроверяетсяbundledC12schema,source/tenant сверяются;
panel снимаетсяприlogout/navigation,401clearsworkspace. Правка—CLI/API сIf-Match иCSRF,не hiddenUIbypass.
C09compatibilitymanifest сохранён; отсутствиеC12route — ошибкаpanel,не ложнаяподдержкаprofiles.

Operator test: CLI120→60с, реальныйследующийscheduled inventoryчерез55–80с послеapply,безfakeclock;
тотжеUID,monotonicsequence,всёаудируется. C12doesnotclaim24hsoak/systemd/DR/geo/HA/enterprise fleetload.
