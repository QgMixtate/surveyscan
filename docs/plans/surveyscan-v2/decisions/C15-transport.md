# C15 — opt-in transport1.2 foundation and collector packet bound

Separate c15-transport.schema.json: SignedObservation(payload1.2) + Batch(version1.2,
records1.2 only). FrozenC03 unchanged; existing agent/collector/center handlers still useC03.
No machine endpoint/profile/capability exchange was enabled by this increment.

Effective initial ceilings: canonical observation512KiB, signed envelope576KiB,
raw/canonical batch768KiB,100records. The draft payload/isolated worker still has1MiB
validation ceiling; that is not an advertised delivery limit. Existing HTTP1MiB,
agentpending reader1MiB, collectorpacket reader2MiB remain unchanged. Actual encoding
and every envelope bound must all pass; no truncation or implicit payload splitting.

NegotiateInventory12 is a shared pure selection helper, NOT the network handshake.
Caller must authenticate/bind the three offers (agent,collector,center) first. All three
must explicitly support observation1.2 and batch1.2, have positive ordered limits;
effective result intersects every hop and local ceilings. Larger peer ceilings clamp;
zero is invalid, never unlimited. Missing/old peer fails, no1.0downgrade/re-sign ofpending.
HTTP capabilities, signed Windows profile12 and persistent negotiated state are not done.

InventoryTransport12.Observation parses/validates schema/JCS/semantic payload/digest and
strict base64signature shape. Parse-only is NOT authorization. Verify requires externally
authoritative tenant/source/generation/kind/keyID/publickey binding and Ed25519 signature.
The existing SURVEYSCAN-OBSERVATION-V1\n domain is preserved: minorversion is signed inside
canonical payload. Batch rejects mixedtenant/duplicateobservationID/legacyversion, has
inclusive raw and canonical byte limits plus record cap. Anti-replay/revocation/active key,
source-record scope and asset mapping remain application responsibilities, not this codec.
Projectioncurrentlypartial-only; completeprovidercoverage/scopeddeletion notimplemented.

Collector codec fix C15-D05 is active for existing C03. JSON HTML escaping could expand
an already-admitted valid batch beyond the2MiB packet reader. marshalPacket now uses
non-expanding JSON and checks the final size before either pending/receipt write. Same
atomic writes, quota/ACK reserve, signing checks and reader bounds remain. Old readable
escaped packets continue to work. Oversized legacy files are not silently rewritten.

Actual local mTLS/Ed25519 admission regression: synthetic10C03 records,300NICrows each,
rawbatch479558bytes; oldpacket2324798 >2097152 reader; newpacket479799, durable read keeps
exact canonicalbatch/digest and sender replay returns202. This is not a center/PG1.2E2E.
Separate opaqueJSON codec tests cover oldformat compatibility and oversize writer reject.
wire/collector -race passed; newtransport tests cover wrong authoritative bindings,
forgedsignature/digest, oldpeerreject, three exact bounds and all-hop limit intersection.

Next: authenticated capability exchange on real collector/center, versioned Windowsprofile,
route/admission dispatch +applicationtrust/replay gates, partial12projection transaction,
then scheduled signedWindowsdelivery/offline/replay/API. KeepC15.02in_progress/57done.
