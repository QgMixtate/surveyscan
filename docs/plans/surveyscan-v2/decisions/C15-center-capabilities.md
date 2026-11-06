# C15 — authenticated center capability discovery

POST /api/v1/machine/inventory-capabilities accepts only JSON {nonce} (32randombytes,
strictbase64url43chars),max4096bytes,noquery. Real verified mTLS chain is mandatory;
PeerFingerprint rechecks active tenant/source/currentgeneration/certificate expiry/revocation
inPG. Only collectors obtain this center→collector description. No source/tenant override
is accepted from the request. This operation does not update heartbeat/inventory state.

Response has issuer=center,tenant,audience(source/kind/generation),requestnonce,issued_at,
expires_at(5min), supported observation/batch versions and optionalpartial12limits.
The current handlers still acceptC03only, so arrays are[1.0], limits12=null,modes=[].
The isolated draft codec does not cause false1.2advertisement. Later runtimeenable must
derive advertised support from both admission and registry projection configuration.

Signature domain SURVEYSCAN-INVENTORY-CAPABILITIES-V1\n, JCS/SHA256/Ed25519. Expected
centerkeyID/publickey come from C11 enrollment trust, never response-provided material.
Nonce,audience,tenant,expiry and both independent protocol arrays are checked. Receipt
signature cannot substitute forcapability signature. Clock skew forfutureissued_at30s,
TTLmax5min. Stale/wrong-generation/cross-tenant/wrongnonce responses are rejected.
Frame max64KiB, closed JSON/schema/strictbase64, positive ordered limit intersection.
Bigger peer ceilings clamp to local maxima; zero never means unlimited.

Center uses the existing configured Signer: C11 OpenBao Transit center key in remote
mode; explicit existing development key only when no remote Signer was configured.
A failing remote Signer returns503 with no local-key fallback. Server self-verifies its
frame against configured centerpublickey before replying. Response no-store/nosniff.
Collector→agent forwarding and three-hop network negotiation are still unimplemented.

Local evidence: real mTLS/enrollment/PG test +57fullPG PASS; wrong nonce/audience/tenant/
generation/key/domain/time/partialoffer/request bounds tested; wire-race and crossWindows
compile/vet passed. The integration mockSigner is explicitly not OpenBao. Separately,
actual OpenBao2.7.2/nonexportableTransit/compiledserver+collector/mTLS/PG pipeline20checks
passed in own DB/ports/scopedmounts, including newcapability200→seal503→unseal200 and
existing cert-renew/restart/replay/audit checks. No production deployment/root export.
Temporary resources cleaned, existing dev credentials borrowed without copyingkeys;
new reports onlyC15/.local. Historical E1 reports/frozen24h data not overwritten.

Capabilities do not replace ingest authorization, origin binding, replay/sequence checks,
source scope or typed projection. Next: opt-in version dispatch foradmission/registry/ACK,
actual partial12delivery+readAPI, then collector-authenticated forwarding/Windowsprofile/
independent scheduler. C15.02stillIP/global57done, SCM/reboot/rights not accepted.
