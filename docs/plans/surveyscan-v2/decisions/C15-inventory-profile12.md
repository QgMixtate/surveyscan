# C15 — signed inventory profile1.2 core

Implemented locally; publication/hosted pending. This is profile discovery/progress,
not automatic Windows collection or a completed Windows durable-cache implementation.

New POST /api/v1/machine/inventory-profile uses separate request/response domains,
version1.2, nonce/tenant/agent origin+generation/collector assignment. Collector checks
verified peer/signing identity then forwards unchanged; center rechecks current source,
revocation, assignment and signing key in PG. Responses use the existing C11 center
signer; failed remote signer never falls back to a supplied local key. Both pipeline
and collector opt-in flags remain required/defaultfalse.

The immutable windows-amd64-partial-baseline-v1 policy contains all12 read-only partial
sections, worker30s/overall420s, supported observation+batch1.2 and bounded byte limits.
Heartbeat/inventory/jitter/spool use the existing Sources common profile as their single
authority. Common revision and policy_id are distinct. Small spool limits reduce carrier/
signed/canonical budgets while preserving ACK+wrapper reserves. No executable/query/
script/remote-target fields are accepted. Platform is a capability claim, not OS proof.

Append-only Sources0034 creates inventory_profile_progress12,35migrations/48ownedtables.
An offer is not application. Applied is an authenticated origin report for a previously
offered revision; it is not remote attestation. Reports are monotonic/current-generation
and do not update C12 progress, heartbeat, inventory success or runtime diagnostics.
GET /api/v1/sources/{id}/inventory-profile is tenant-scoped, exposes separate reported
progress and enabled flag; historical progress remains readable when disabled.

Go Client.FetchInventoryProfile12 requires the private proof from a fresh negotiation,
revalidates the current collector generation and both pinned signatures, checks profile
nonce/source/collector/policy and intersects profile+three-hop limits. It is read-only:
it does not apply config, persist cache or send an applied report. This avoids claiming
an application before secure durable storage exists. Linux C03 runtime remains unchanged.

Checks: verify/build/C03 58, PG60, wire/agent/collector race, Winagentcrossbuild/vet.
Real compiled relay/mTLS/scopednonexportableTransit/PG scenario11 passed with a synthetic
enrolled agent. A private Linux test file+directory is fsynced before its explicit applied
report; this is a declared acceptance fixture, not the Windows cache. PG checks isolate
freshness/revisions/revocation and34→35 migration. Actual mutualTLS Go agent/collector test
uses a test center signer; real Transit proof is the compiled Python scenario.
Old C03/C09/C12 and applied SQL0000–0033 remain unchanged. Private update fixture moved
0034→0035; latest test-only update35→36; backup/boot/upgrade counts updated with guards.

Next: secure Windows DACL/reparse/root-relative file access, exclusive state lock/atomic
replacement/host continuity, then signed durable acceptance cache/offline verification
and applied reporting. Only then connect native collection to daemon. SCM03/04 later;
C15.02 stillin_progress/global57done. No main merge/release/deploy/env publication.
