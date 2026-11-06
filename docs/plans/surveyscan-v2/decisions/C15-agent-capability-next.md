# Следующий C15.02 increment — authenticated three-hop negotiation

Статус planned, НЕ implemented. Data relay12 с manualtestconfig уже проверен отдельно.
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
