# C15 — additive Windows inventory contracts

Observation1.2 описывает12 typedsections: identity,os,network,hardware,software,updates,
services,users_groups,routes_ports,resources,protection,neighbors. Baseline partial-only:
нет complete/deletion. Отсутствующее поле не заменяется выдуманным значением; недоступный
provider не выдаётся за пустой ok. Fixture corpus24:8 positive/16 negative; синтетические,
не Windows API, service/rights/reboot proof. C03/C09/C12 schemas не меняются.

Из корня:

```sh
python docs/plans/surveyscan-v2/contracts/C15/validate.py
```

requirements.txt фиксирует checker dependencies; JSON читается UTF-8 и на Windows.
Go Inventory12 validator проверяет closed shapes, count/status/complete semantics,
JCS-safe integers, duplicate names/fields и bounds. Draft isolated payload ceiling1MiB
не является transport limit.

transport.schema.json и embedded c15-transport.schema.json: SignedObservation/Batch1.2,
canonical512KiB/signed576KiB/batch768KiB/100records before negotiated lower ceilings.
JCS/SHA256/Ed25519 с существующим observation domain. Origin/key/tenant/generation
проверяются отдельно от parse. Private center/collector inventory12_enabled defaultfalse;
managed collector identity обязательна. Opt-in actual partial12 admission/relay/projection/
replay поддержан, signed ACK остаётся1.0 и привязан к исходному1.2batch. HTTP202 сам по
себе не разрешает удаление pending. При downgrade original bytes сохраняются.

capabilities.schema.json: center frame с issuer=center иaudience=collector origin;
collector outer frame сissuer=collector origin/audience=agent origin инеизменённым
signedcenterframe. Два отдельных signature domains, nonce/tenant/generation/expiry и
ключи только из verifiedTLS/enrollment. POST /api/v1/machine/inventory-capabilities
на центре требует active collector, на managedcollector — assigned agent. Collector
учитывает spool-AckReserve-packetheadroom, agent берёт intersection всех3offers.
Готовый Go agent negotiation method пока не вызывается Windows daemon.

records.schema.json/records.openapi.json иmatchingserverembeds: additive typed fact pages
GET /api/v1/assets/{asset_uid}/inventory/facts/{section}, per-field provenance, revision
cursor,100fields/2MiB; HTTP409 при изменении projection. GET /api/v1/contracts/c15 публикует
OpenAPI. LegacyC09shape/tableprojection отделены. Новые rows не обязаны появляться в старой
three-section summary; typed1.2API является источником этих facts.

Software rows требуют provider-local registry_key; current_user требует principal_sid,
machine rows не имеют этого SID. Locator не asset_uid. Исторические19-fixture/failed
checker/COM/boot/spool/restore результаты сохранены в evidence и не переименовываютсявPASS.

Runtime checks: actual compiled collector+center/scopedTransit/mTLS/PG relay10 использует
синтетический enrolled Pythonagent, проверяет capabilities до upload, offline/coldrestart/
sameUID/ACK. Native Windows SDK проверяется отдельно через bounded ownbinary child для
всех12providers; это пока не постоянная Windows delivery/service. ExactSHA/runs иследующий
Windows profile/runtime этап — C15 handoff/evidence; global57done/C15.02IP.
