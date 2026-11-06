# C15 — opt-in center processing1.2

Private server JSON referenced by SURVEYSCAN_V2_MACHINE_CONFIG: inventory12_enabled defaultsfalse. ConfigureInventoryProtocol12 executes
only at startup before machine handlers. The same immutable decoder is installed in the
transactional Registry and UploadService. Capability offer1.2 requires both components;
a draft codec or registry alone is insufficient. Existing default C03 behavior remains.
This is an isolated center acceptance mode, not full Windows delivery/release acceptance.

InventoryDecoder supports frozenC03 and opt-in partial-only1.2. Raw/canonical/envelope
limits remain independently enforced. ok/complete1.2 snapshots are rejected before staging
until provider-scoped deletion exists. No applied SQL/C03/C09 schemas changed (34/47).

Stage retains the existing courier tenant/generation/collector/scope authorization and
durable quotas/fencing. Ingest still verifies source key/generation/namespace/scope, JCS,
SHA256/Ed25519, immutable evidence and exact duplicate signatures. Version1.2 selects
ProjectPartial12 in the same asset/link/history/audit/outbox transaction; no data silently
drops into oldflatten. Source success/freshness is not faked from partial observations.
New data reads through fact-page1.2; oldC09shape/tables remain separate.

MachineRegistry replay uses the same decoder. Shared receipt crypto/binding logic preserves
the signed CenterResult1.0 contract for either batch version. Verify every observationID,
sourceID,digest,batch delivery/digest and pinned centerkey; HTTP202 alone is not acceptance.
Existing POST always returns202, including a final signed body. GET receipt returns200.
The updated C15OpenAPI describes this behavior; no serverstatus change was made.

Pending12processing after configuration downgrade returns retryable unavailable before
claiming a lease/consuming attempts. It never creates a terminal schema reject/re-signs
or deletes staged bytes. Re-enabling resumes. Alreadycommitted cachedACK remains readable
with new admission disabled. JSONB may normalize outer formatting; canonical signed frame
and signature stay identical. Tests compare canonical bytes, not JSONB whitespace.

Local direct-service realPG/enrolledfingerprint/Ed25519: defaultreject, matchingenable,
partial12projection/all12sections/typedAPI, duplicateobservation/delivery replay, unchanged
ACK1.0, completeunsupportedreject, stagedbytes retained withoutclaims ondisable, cachedACK
available. FullPG58passed. These direct calls are distinct from actual mTLS below.

scripts/c15_center_smoke.py: compiledcenter with explicitprivateoptin, actualmTLS courier,
agent enrolled through compiledcollector, courier authorized to submit that delegated
agent's signed syntheticWindows-schema inventory directly to center; real scopednonexportable
Transit forCA/caps/receipt, PG/all12sections, humanfactAPI, unchangedC09 and signedreplay.
6checks passed; noactualWindows/collector12uploadrelay/threehopnegotiation claim. OwnDB/ports/
mounts cleaned; existingE1credentials reused withoutkeycopies and reports onlyC15/.local.
CI now runs this case and uploads only sanitizedc15-center-smoke.json.

Next: collector12dispatch/ACK and authenticated center→collector→agent forwarding with
nonce/audience/pinnedkeys; Windowsprofile/independentcollection and file/service lifecycle.
C15.02 remainsIP/global57done. No mainmerge/release/production deployment/environmentpublish.
