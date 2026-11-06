# C15 — isolated Windows private-state primitives

Local implementation/crosscompile/vet only; native execution pending. The module is
not imported by agent runtime and does not enable Windows enrollment or storage.

platform/winstate creates a new private writable directory with an explicit protected
DACL: current process account, SYSTEM and Administrators. Existing roots are opened
only after handle-based owner/ACL checks; no permission repair or silent adoption.
Null/unprotected/inherited/unknown-grant ACLs fail closed. Every file operation rechecks
the held root policy to detect drift. Diagnostics expose only closed phase/numeric
Windows status, not paths, SIDs, raw descriptors or file contents.

OpenRoot requires a local absolute drive path and compares normalized final handle
path with the requested canonical long path, rejecting leaf/ancestor reparse aliases.
Subsequent operations use NtCreateFile RootDirectory and a single closed ASCII file
name; no second absolute lookup, path traversal, alternate streams or device names.
Root handle denies delete sharing. Opened leaves must be regular disk files, no reparse
or multiple hardlinks; ACLs are checked on the same handle used for bounded reading.
CreateNew applies private descriptor before bytes, writes/flushes/closes, never overwrites.
Lock uses a fixed relative file with exclusive Windows share mode and is tested across
separate helper processes. Root lifetime/Close remains caller-owned.

This is private state under one Windows account, not an application sandbox or hardware
attestation. It is not a general readonly config root. Atomic replacement, staged crash
recovery, integrated agent files, MachineGuid host binding, signed offline acceptance
cache/applied ACK and SCM/reboot/rights matrix remain pending. CreateNew alone is not an
atomic cache replacement or a physical-power-loss guarantee. Existing Linux primitives
and fail-closed unsupported Windows runtime remain unchanged.

Native tests (new dedicated Windows CI step) cover roundtrip/bounds/no overwrite,
ACL drift/null/public/unprotected DACL, hardlink/leaf+ancestor reparse rejection, OS
exclusive lock across two processes and diagnostic canary redaction. No native PASS
is claimed until the workflow executes. All test fixtures are owned temporary folders.
