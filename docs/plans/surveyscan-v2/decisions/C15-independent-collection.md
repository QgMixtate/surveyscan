# C15 — collection outside the agent state actor

Implementation local, verification passed; publication pending. C15.02 remains in_progress.

Run now starts a single read-only Collect task with a 30-second context deadline.
The worker receives only context, returns a Snapshot/error and completion timestamp
through a single-element channel. It cannot access Client, TLS, keys, counters, profile
or spool. The actor keeps running profile polling, renewal, challenge heartbeat and
queued delivery. Only it assigns sequence, signs, checks effective quota/host binding
again and atomically queues a validated snapshot. The synchronous Inventory method
uses the same commit path. Collection cadence restarts after completion; overlap is
forbidden. Profile/TLS changes stay serial and cannot race host collection.

Deadline cancels context; a late successful result is discarded. A provider ignoring
cancellation retains the only collection slot rather than spawning replacements.
This is a bound on concurrency, not forced termination of an arbitrary in-process
native call. Linux adapter starts no child process. Windows daemon remains disabled;
Windows provider process containment/reaping and SCM stop are still acceptance gates.
On shutdown the actor cancels the task; cooperative providers exit. Network work remains
serial and bounded by existing HTTP contexts: this is not a new hard heartbeat SLA.

Verification: make verify/build and unchanged58 C03 fixtures; agent race tests. A real
actor with private counters/spool and signed challenge heartbeat uses an HTTPS test
responder: two heartbeats succeed while one host collector is blocked; no unfinished
snapshot is signed, after release exactly one inventory sequence is persisted. Separate
late-success/cancel tests cover deadline discard and cooperative worker completion.
HTTP responder is a test double, not machine/PG authorization proof.

Actual compiled Linux agent/collector/server + real mTLS/PG:11 checks passed, three
scheduled real host cycles then a fourth after restart; one UID, monotonic counters,
verified ACK removal, process lock, revoke/enroll refusal. Host facts stay in temporary
DB/files; only sanitized report C15/.local/agent-smoke.json. Existing E1 private credentials
reused via E1 dev module with C15 binaries/own DB/ports; no shared service reset or key copy.
Windows/amd64 cross-build passed. Hosted checks pending. No new24h result is claimed;
C14 accepted frozen candidate/soak is not replaced by these binaries.

Next: Windows profile1.2 (separate from observation/batch version), followed by isolated
native providers and Windows state security/service acceptance. Do not close C15.02 or
increase57done on scheduler foundation alone.
