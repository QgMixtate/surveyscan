# C15 — isolate every native Windows section

Implemented locally; cross-build/Windows test compilation passed, native execution pending CI.

All12 providers now use the existing own-executable inventory-worker command, closed
section vocabulary and bounded output reader. WriteWorkerSection dispatches one native
provider without reading configuration, enrollment, keys or target credentials. Updates/
protection retain COM initialization on their own OS thread. The other10 read local APIs
inside their own process; a blocking registry/NetAPI call can be killed by the parent.
Each child has30s context,1s WaitDelay, over-limit cancellation and cmd.Run wait/reap.
A crash/timeout/malformed/oversized/wrong-section response becomes one unavailable section;
following providers continue. Ordinary rights and provider partial semantics are unchanged.
No shell or profile-provided executable/command is accepted.

Collect remains an isolated native baseline, not Windows daemon enablement. Its caller
can impose an overall context; per-section30s does not mean the entire12-section sweep
is30s. Context cancellation returns collected sections plus error; future runtime/profile
must decide explicitly, never silently mark missing providers complete. Parent cancellation
and process-reaping proof for SCM still needs real service/stop/reboot acceptance.

New native test crashes the software worker and requires identity/OS and later services
remain present. Existing COM failure injection delegates other sections to the actual
built binary. Native baseline tests require SURVEYSCAN_C15_TEST_AGENT; without a built
worker they skip explicitly. Existing synthetic kill/reap/output-bound tests remain.
Local Linux makeverify/C03 58 + Winagent/test cross-build/vet; real Windows results pending.
Next: hosted native run, Windows profile1.2 and state security/SCM/rights/reboot gates.
57done/C15.02IP. No SQL/C03/C09/profile changes or Windows delivery/release claim.
