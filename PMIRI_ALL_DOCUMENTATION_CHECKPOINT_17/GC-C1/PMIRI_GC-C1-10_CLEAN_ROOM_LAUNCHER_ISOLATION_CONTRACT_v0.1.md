# PMIRI GC-C1-10 — Clean-Room Launcher and Isolation Attestation Contract

**Version:** 0.1  
**Status:** DESIGN_ONLY  
**Execution:** NOT PERFORMED  
**R-FC replay:** NOT PERFORMED  

## 1. Boundary

This contract defines the launcher that a future pinned runner may use to obtain a verifiable clean-room environment. It does not claim that the current workspace is isolated, does not launch the runner, and does not authorize replay or PASS.

## 2. Launcher inputs

The launcher accepts only:

- pinned runner package and runner manifest;
- exact authority bundle;
- evidence schema, fixture catalog and selected case;
- preflight specification, scenario matrix and output/sealing schemas;
- explicit case identifier;
- resource/isolation profile;
- execution authorization record.

Every input is copied or mounted read-only and fingerprinted before the case root is created. Missing, mutable or unhashable input stops launch.

## 3. Case-root topology

Each case receives a fresh root with separate paths:

~~~text
case-root/
  inputs/       read-only allowlisted inputs
  work/         disposable process state
  outputs/      case-scoped writable artifacts
  attestation/  isolation and resource evidence
  teardown/     residue and cleanup evidence
~~~

The launcher must reject repository roots, home directories, shared caches, prior case roots, unresolved symlinks and pre-populated output roots. The launcher must not reuse state between cases.

## 4. Isolation controls

The launcher must establish and attest:

- network namespace/egress denial;
- connector and credential denial;
- read-only input mounts;
- allowlisted filesystem access;
- no home/repository/ambient cache access;
- no undeclared subprocess or dynamic dependency access;
- UTF-8, UTC, pinned locale and deterministic sorting;
- injected logical clock and fixed seed policy;
- CPU, memory, disk, process-count and wall-time limits;
- forced teardown and residue inspection.

If any control is unavailable or only declared but not observed, the launcher emits `ISOLATION_VIOLATION` or `BLOCKED` and does not start the runner.

## 5. Launcher lifecycle

~~~text
AUTHORIZE
  → HASH_INPUTS
  → CREATE_FRESH_ROOT
  → APPLY_ISOLATION
  → VERIFY_ISOLATION
  → MOUNT_ALLOWLIST
  → APPLY_DETERMINISM_AND_LIMITS
  → HANDOFF_OR_ABORT
  → TEARDOWN_AND_INSPECT
~~~

`HANDOFF_OR_ABORT` is the only point at which a future runner could receive control. A failed verification never falls through to handoff.

## 6. Attestation requirements

The launcher must emit an attestation containing:

- stable attestation ID and launcher version;
- case ID and authorization ID;
- runner, authority, schema, catalog, matrix and profile fingerprints;
- case-root policy and observed filesystem boundary;
- network, credential and connector observations;
- determinism configuration and observation;
- resource limits and enforcement observations;
- teardown result and residue inventory;
- privacy/redaction mode;
- outcome and failure reason;
- capture timestamp and attestation digest.

An attestation is `VERIFIED` only when every required dimension has an observed positive result. Otherwise it is `UNVERIFIED` or `FAILED`; it cannot be upgraded by editing a summary field.

## 7. Failure mapping

| Failure | Outcome |
|---|---|
| Missing authorization or input fingerprint | `BLOCKED` |
| Malformed profile or attestation | `VALIDATION_ERROR` |
| Network, credential, filesystem or connector escape | `ISOLATION_VIOLATION` |
| Missing limits, determinism or teardown evidence | `BLOCKED` |
| Residue after teardown | `ISOLATION_VIOLATION` |

All failures remain sealed and are preserved for independent review.

## 8. Current state

The current workspace has no verified clean-room attestation. Therefore the latest preflight remains `BLOCKED`. This document defines the remediation target; it is not evidence that the target has been achieved.
