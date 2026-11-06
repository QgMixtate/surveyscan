# C15 — delivery backoff follows durable progress

Public Client.Flush keeps its error contract. New private flushProgress additionally
reports whether at least one pending packet was removed after a verified signed ACK
and directory sync. Cached receipt recovery and fresh ACK paths use the same definition.
HTTP202/transport-only/unverified/retained/quarantined packets are never progress.

The state actor resets global delivery backoff when old work actually completes,
even if a newly produced packet remains processing. Without this distinction, continuous
arrivals can keep an otherwise successful sender at maximum retry delay, potentially
above the producer cadence. No-progress failures keep existing capped jitter/backoff.
This does not change bytes/signatures/sequences, acceptance rules or pending retention.

Unit regression: two valid C03 batches, old cached cryptographically valid remove ACK,
new schema-valid transport retain; only old packet is removed, fresh canonical bytes
remain, first pass reports progress and waiting, next pass reports waiting/no progress.
Existing offline/forged/quarantine/cached-recovery tests remain. Agent race/verify/build/
Windows cross-build passed. Actual compiled3agent/network-cut/quota/reconnect/replay
case5 passed;21.347s drain, one physical host, ownDB/ports/private state, no24h claim.
This condition is independently verified; it is not a proven explanation of C15-D07.
D07 failedboot retained; one local and two instrumented hosted freshVM9passed each.
Next publish/check exactSHA, then Windows profile/state/service gates.57done/C15.02IP.
