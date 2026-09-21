# PMIRI GC-C1 Replay Runner 0.1.0

This is the pinned source package for the GC-C1 evidence/preflight runner.

## Contract boundary

- identity: `pmiri-gc-c1-replay`
- version: `0.1.0`
- latest aliases: forbidden
- self-upgrade: forbidden
- external dependencies: none
- network/connectors/credentials: not accessed by this module
- production data/code: not accessed by this module
- R-FC replay: not performed by this package creation step

The module exposes pure validation functions. A future launcher must establish
the clean-room environment and provide immutable fingerprints and attestations
before invoking the decision function. Any missing or unverifiable prerequisite
returns `BLOCKED`.
