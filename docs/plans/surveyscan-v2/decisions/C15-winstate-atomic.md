# C15 — Windows handle-relative atomic replacement

Local implementation/crosscompile/vet only; native tests pending. Not yet adopted by
agent storage/cache/runtime. Base private-root c7e2f0a already passed all5hosted workflows,
including actual Windows DACL/reparse/hardlink/crossprocesslock tests. D09 fixed.

AtomicReplace requires the held exclusive state lock. It validates the old target on a
private handle, creates a random private stage relative to the same root, writes/flushes,
then NtSetInformationFile renames by the root handle and counted name, with replacement.
The renamed file is flushed/closed. A failed rename keeps the old target and deletes only
its own staged file by handle. No absolute path reopening or unsafe target repair occurs.
The ABI layout is explicit/limited to Windowsamd64. Existing CreateNew remains no-overwrite.

ReadOptional treats only a typed ERROR_FILE_NOT_FOUND for the simple leaf as absence;
ACL/reparse/I/O failure is not an empty cache. Read handles share delete while excluding
write, allowing atomic readers to finish on the old file object. Multiple hardlinks remain
rejected; zero links are permitted for an already-open deleted snapshot. Root.Close
releases owned lock exactly once, making late unlock safe and idempotent.

Native test plan: missing-vs-unsafe leaf; replacement only with lock; sharing-denied rename
preserves old bytes and cleans stage; independent readers see only complete old/new data;
separate child exits at before/after rename, and the next process can reacquire the OS lock.
Test hooks are package-private/nil in product, never populated from config/profile/environment.
Only the test helper reads fixture variables. All values are synthetic temporary state.

These are process-crash/namespace guarantees, not physical power-loss proof. Orphans after
a real pre-rename process crash can remain private; bounded cleanup/recovery is still needed
before runtime adoption. Durable signed acceptance/offline cache, Windows host continuity,
privatefile/diskspool adapters, automatic profile apply/ACK and SCM/reboot remain pending.
No C15.02 acceptance/counter increase, no service install or production changes.
