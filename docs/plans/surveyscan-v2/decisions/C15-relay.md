# C15 — opt-in collector relay1.2

Private collector JSON inventory12_enabled defaultsfalse. Enabling requires the existing
managed collector credential/signing identity; attested SourceID/signingkey must match.
The opt-in shared decoder admits C03 and partial-only1.2. Existing mTLS agent scope,
tenant/source/generation/kind/keyID, SHA256/Ed25519 and duplicate checks stay in place.
Original canonical batch/signatures persist through the same bounded atomic private spool.

Collector verifies unchanged CenterResult1.0 against the original1.2batch with enrollment-
pinned centerkey, every result/digest/source/observation/delivery binding. Only verified
remove disposition allows pending deletion; cache/read/replay use the same verifier.
No silent version downgrade, payload rewrite/re-sign or HTTP202-based removal occurs.
Opaque private packet codec remains bounded/non-HTML-expanding. Reader limit2MiB unchanged.

Default E1 flags stayoff. This is explicit opt-in experimental delivery, not Windows agent
release acceptance. Agent-side authenticated three-hop capability negotiation/Windows
profile/scheduler/DACL/service/rights/coverage are still pending. The test config itself
selects12; it does not pretend to be a completed capability exchange.

scripts/c15_relay_smoke.py uses compiledcollector+center, actualmTLS, enrolled synthetic
agent delegated to thiscourier, scoped nonexportable OpenBaoTransit, PG/all12sections,
humanfactAPI, unchangedC09, verifiedACK/replay.9checks passed locally. Native Windows is
not involved: records come from the synthetic C15contract corpus.

Additional actual failure checks: stop only owncenter, enqueue signedsequence2 and compare
storedcanonical batch to original; stop owncollector, restart both with same privateconfig/
keys/DB, automaticreconnect commits exactly2observations/1unchangedUID and removespending
only after verifiedACK. Shared dev services were not stopped/reset; testDB/ports/mounts
andownprocesses cleaned. No privatekeys copied; new reports onlyC15/.local.

CI runs both center-only6 and relay9 and uploads only sanitized reports. Eachnewcase marks
in_progress before work so a previous localpassedreport cannot be mistaken for thisattempt.
Newflags/handshake/API remain separate from frozenC03/C09 and existing profiles1.1.
Next: authenticated center capability forwarding to agent with nonce/audience/peerbinding,
Windowsprofile1.2 and independentcollection, thenWindowsstate/service/reboot acceptance.
C15.02stillIP/global57done, SQL34/47unchanged. No mainmerge/release/deploy/envpublish.
