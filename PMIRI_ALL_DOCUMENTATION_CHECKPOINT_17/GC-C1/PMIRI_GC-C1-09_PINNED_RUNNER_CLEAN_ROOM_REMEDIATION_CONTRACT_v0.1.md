# PMIRI GC-C1-09 — Pinned Runner and Clean-Room Remediation Contract

**Version:** 0.1  
**Status:** DESIGN_ONLY  
**Remediates:** PF-02, PF-03, PF-08, PF-09, PF-10, PF-11, PF-12, PF-13, PF-14 and PF-16  
**Execution:** NOT PERFORMED  

## 1. Boundary

This contract defines what must exist before Controlled Preflight 002 can be considered. It does not implement or execute the runner, create R-FC evidence, change production code/data, enter Gate D or assign PASS.

## 2. Exact runner pin

The only accepted identity is:

~~~text
runner_id: pmiri-gc-c1-replay
runner_version: 0.1.0
latest_alias_allowed: false
self_upgrade_allowed: false
~~~

The runner source/package must be a present, immutable artifact with:

- source/package SHA-256;
- runner manifest SHA-256;
- reproducible build or byte-identical distribution record;
- declared entrypoint and dependency closure;
- no runtime download, plugin discovery or self-modification;
- source and manifest fingerprints recorded before clean-room provisioning.

Missing source or a null fingerprint is `BLOCKED`, never `READY_FOR_REPLAY`.

## 3. Clean-room contract

Each case receives a fresh unique root. The runner may read only the immutable allowlist:

- pinned runner source/package;
- runner manifest;
- authority bundle;
- evidence schema;
- fixture catalog and selected case;
- preflight specification and scenario matrix;
- output/evidence/sealing schemas.

The runner must not read the repository, home directory, ambient caches, prior case roots, shared temporary state or undeclared connectors. Inputs are read-only. Outputs are written only to the case-scoped output root.

## 4. Isolation requirements

The environment must prove, not merely declare:

- network and connector access denied;
- credentials absent or inaccessible;
- filesystem allowlist enforced;
- subprocess and dynamic-loader policy bounded;
- CPU, memory, disk, process-count and wall-time limits enforced;
- UTF-8, UTC, fixed locale, deterministic sorting, injected clock and fixed seed;
- forced teardown and residue inspection;
- privacy classification/redaction before trace emission.

Any failed or unprovable isolation assertion produces `ISOLATION_VIOLATION` or `BLOCKED` according to the applicable PF check and prevents replay.

## 5. Required lifecycle

~~~text
PRECHECK
  → PROVISION_CLEAN_ROOM
  → VERIFY_PINNED_FINGERPRINTS
  → VERIFY_ISOLATION
  → CAPTURE_DECLARED_TRACE
  → SCHEMA_VALIDATE
  → SEAL_ARTIFACTS
  → TEARDOWN_AND_ATTEST
  → INDEPENDENT_REVIEW
~~~

No phase may silently skip a prior phase. A phase failure produces a preserved failure record and stops the case.

## 6. Sealed outputs

Before any future replay authorization, the runner design must support a sealed case bundle containing:

- preflight record;
- exact input fingerprint set;
- runner/environment/isolation attestations;
- action trace and oracle/actual comparison;
- privacy/redaction record;
- resource and teardown record;
- artifact manifest and final bundle digest;
- independent review reference.

If sealing is unavailable, PF-13 remains blocked.

## 7. Independent review boundary

The operator who provisions or runs the case cannot be the independent reviewer. The reviewer must receive the sealed bundle and manifest digest from a clean copy. A missing, same or unresolved identity keeps PF-16 blocked.

## 8. Exit criteria for remediation design

This remediation package is design-complete when the scenario matrix covers one baseline and one fault per remediation condition, each expected outcome is explicit, and the future runner can produce every required fingerprint and attestation without ambient state.
