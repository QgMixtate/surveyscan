# Access: bounded login and safe dependency diagnostics

POST /api/v1/auth/sessions has an8s request context, below the public HTTP server10s
write timeout and CLI15s request timeout. The former5s context expired during a valid
Argon2 verification under controlled CPU contention:6464ms at48% processCPUquota
in a disposable two-vCPU TCG guest. Session creation then failed before it began.

The fix changes only the total login budget. Argon2id3passes/64MiB/1lane,2concurrent
hashslots, account/global rate limits, session limits/revocation, Origin/CSRF and
tenant authorization remain intact. No automatic replay of login POST is added.
This does not promise login availability under arbitrary load or blocked dependencies.

Unexpected login failures emit a fixed stage/reason and elapsed/verification milliseconds.
No username/password/hash/cookie/SQL/rawerror/requestbody reaches these diagnostics.
Expected authentication/rate/validation errors do not emit dependency-failure events.

Real PG contention test holds a user row lock: the request must return503 without
a cookie/credential; after unlocking, an explicit new request succeeds once.
Opt-in native CPU probe is test-operator tooling inside a disposable VM; it does
not modify hostcgroups or product deployment defaults. Historical CLI503 has no
original backendtrace; remediation of the reproduced class does not retrospectively
prove the cause of each historical failure.
