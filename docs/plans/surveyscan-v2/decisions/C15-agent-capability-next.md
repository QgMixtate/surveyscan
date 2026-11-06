# Следующий C15.02 increment — authenticated three-hop negotiation

Статус: implemented locally, verification passed; publication pending.
Transport negotiation API is implemented separately from the daemon/profile.
The numbered list below is the design; actual result and limits are in
[capability-chain evidence](../evidence/C15-capability-chain.json).
Нельзя объявлять finished Windowsagent/capability exchange по успешной доставке fixtures.

1. Collector POSTinventory-capabilities принимает тот же boundednonce от verifiedmTLS
   agent. c.peer проверяет tenant/collector relation/kind; метаданные не заменяют central
   active-origin authorization при записи. Вызывать центр от собственного текущегоmTLS.
2. Center возвращает неизменный signedcapabilities frame с audience=currentcollector,
   tenant/generation/requestnonce/expiry. Проверить enrollment-pinned centerkey до включения
   frame в ответ агенту; не брать новыйtrustroot из body. Old404/failedsigner→unavailable.
3. Outercollector frame: issuer collectorOrigin, audience agentOrigin,тотженonce/tenant,
   issued/expiry не позже innerexpiry, ownversions/limits/mode и raw signedcenter frame.
   Подписать CA-attested collector signingkey с новым отдельным domainprefix. Private
   managedidentity уже обязательна дляoptin12. c.mu только на короткое чтениеquota/config,
   не держать при network/signing. No raw key/nonce/private data logs.
4. Ownmaxlimits учитывать hardprotocol ceilings и максимальный одиночный spoolpacket:
   batch <= min(768KiB, configuredLimit-AckReserve-packetMetadataReserve), signed/canonical
   strictly меньше carrier, positive. Dynamic queue fullness отдельно429/backpressure.
5. Agent получает actual TLS verifiedpeer certificate и проверяет attested collector kind,
   tenant,collectorID и issuerOrigin/generation/keyID/publickey. Expected centerkey fromown
   C11 enrollment. Проверить обе signatures/audiences/nonce/expiry и взять intersection
   agent/collector/center offers. No collection-as12 beforeallhops; no pendingdowngrade/
   re-sign/delete when offer changes, oldpeer, expiry or dependency failure occurs.
6. Новый handler/DTO/schema рядом сC15caps, frozenC03/C09/C12 unchanged. Existing center
   endpoint default1.0 и optin12 remaintruthful. PublicC15OpenAPI describes both serverroles
   explicitly. Profile1.2 is a separate nextcontract; observationversion не profileversion.
7. Unit: wrongcenter/collector key, role-domain reuse, wrongnonce/tenant/issuer/audience/
   generation, stale/overextended expiry, corruptednestedframe, missingoldpeer, all three
   independent ceilings. Actual compiledmTLS/scopedTransit case verifies both signedframes,
   selects12 from three offers and then sendsfixture throughrealrelay. Labelsyntheticdata.
8. Newreport start=in_progress, sanitized allowlist only. Do not closeC15.02 on handshake:
   Windowsprofile/independentboundedcollection+DACL/hostbinding/locks/service/rights/reboot
   and documentedprovidercoverage remain. Keep57done untilactualacceptancecriteria pass.

Implementation locations: contracts/inventory_capabilities.go, wire/capabilities12.go,
collector/inventory_protocol.go (newcapability handler separate), agent/newrequestmethod,
C15cap schema/OpenAPI, scripts/c15_relay_smoke.py. Do not mutate E1private/frozenreports;
localtests reuseE1devmodulecredentials withC15binaries/ownDB/ports/scopedmounts.


Результат 2026-11-06: collector handler и Go Client.NegotiateInventory12 реализованы.
У collector offer batch <= min(768KiB, spoolLimit-AckReserve-4096); signed/canonical
оставляют по64KiB carrier headroom. Занятость очереди не меняет постоянный offer.
Outer frame lifetime <= inner, issuer/audience roles closed by schema; обе подписи,
nonce/tenant/generation/expiry проверяются независимо. API OpenAPI описывает обе роли.
makeverify/C03 58, PG58, agent/collector/wire race и Windows cross-build passed.
Actual compiled collector+center/scoped Transit/PG relay10 passed; synthetic agent
в Python проверяет обе подписи до upload. Go Client method проверен отдельно через
настоящий mutual TLS к production collector; center test handler использует local
Ed25519 и не объявляется OpenBao. 503, old center и forged inner подпись failclosed.
Далее Windows profile1.2 + bounded independent collection/heartbeat; метод negotiation
пока не вызывается daemon, не меняет C03 runtime/profile/spool и не закрывает C15.02.
