# PMIRI GC-C1 Clean-Room Launcher 0.1.0

This package implements the contract-level handoff decision only. It does not
create namespaces, mount filesystems, deny network access, inspect credentials,
run the runner or claim that the current workspace is isolated. Those facts
must be supplied as independently observed attestations.

Missing fingerprints or any unverified observation fail closed. The only
successful result is `READY_FOR_REPLAY`; this is not an R-FC result or PASS.
