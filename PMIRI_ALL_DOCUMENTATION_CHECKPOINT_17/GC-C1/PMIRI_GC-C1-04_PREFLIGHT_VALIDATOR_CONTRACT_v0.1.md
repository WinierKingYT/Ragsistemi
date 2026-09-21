# PMIRI — GC-C1-04 Preflight Validator Contract

**Version:** 0.1  
**Status:** \`DESIGN ONLY / NOT EXECUTED\`  
**Gate:** C.1 — Closure Evidence Hardening  
**Implementation authorization:** \`NOT GRANTED\`

## 1. Purpose

GC-C1-04 defines the mandatory preflight performed before any R-FC replay.
A replay cannot begin, and cannot produce a valid evidence record, unless all
hard preflight checks pass.

This contract does not execute tests, assign \`PASS\`, change Gate-C semantics,
define Gate-D policy, or authorize production implementation.

## 2. Preflight result

The preflight validator returns exactly one overall result:

~~~text
READY_FOR_REPLAY
BLOCKED
VALIDATION_ERROR
ISOLATION_VIOLATION
~~~

Rules:

- \`READY_FOR_REPLAY\` means only that execution prerequisites are present;
  it does not mean any R-FC case passed.
- \`BLOCKED\` means a required dependency, authority, capability, or input is
  missing or unverifiable.
- \`VALIDATION_ERROR\` means an input or manifest violates its declared schema.
- \`ISOLATION_VIOLATION\` means the clean-room boundary is absent, weakened, or
  unverifiable.
- Any hard-check failure prevents replay.

## 3. Required exact inputs

The validator must receive:

- runner source/package and immutable fingerprint;
- \`PMIRI_GC-C1-03_REPLAY_RUNNER_MANIFEST.json\`;
- \`PMIRI_GC-C1-02_EVIDENCE_RECORD.schema.json\`;
- \`PMIRI_GC-C1-02_REPLAY_FIXTURE_CATALOG.json\`;
- \`PMIRI_GC-C1-01_GATE_C_EVIDENCE_MATRIX_v0.1.md\`;
- exact accepted Gate-C R1/R2/R3 authority files and SHA-256 fingerprints;
- the selected fixture case;
- a declared environment contract.

Filenames, mutable paths, \`latest\` aliases, and unstated defaults are not
authority.

## 4. Hard preflight checks

### PF-01 — Runner identity

Verify runner ID is \`pmiri-gc-c1-replay\` and the declared runner version is
present and immutable.

### PF-02 — Runner package integrity

Verify the runner source/package fingerprint matches the declared fingerprint.
Self-upgrade and dependency download are forbidden.

### PF-03 — Manifest integrity

Verify the runner manifest parses, has the expected format/version, and its
content fingerprint is recorded.

### PF-04 — Authority bundle integrity

Verify every required authority file exists, is readable, and matches its
declared SHA-256 fingerprint. Missing R1/R2/R3 authority material is
\`BLOCKED\`.

### PF-05 — Schema integrity

Verify the Evidence Record schema parses and its fingerprint matches the
declared input. A schema validation failure is \`VALIDATION_ERROR\`.

### PF-06 — Fixture catalog integrity

Verify the fixture catalog parses, contains exactly the selected check/case,
and its fingerprint matches the declared input.

### PF-07 — Matrix/catalog coverage

Verify the selected case maps to one of \`R-FC-01\` through \`R-FC-17\`, and
that the catalog contains both a positive and an adversarial case for that
check.

### PF-08 — Clean-room capability

Verify a fresh case root, read-only input allowlist, case-scoped output path,
home/repository denial, shared-session denial, and teardown capability.

### PF-09 — Network and credential denial

Verify network and external connectors are denied, and no ambient credential or
authentication token is visible to the case process.

### PF-10 — Filesystem allowlist

Verify the case can read only declared inputs and write only to its
case-scoped output directory. Undeclared files must be denied.

### PF-11 — Resource limits

Verify CPU, memory, disk, process-count, and wall-time limits are declared and
enforceable. Missing limits are \`BLOCKED\`.

### PF-12 — Deterministic runtime

Verify UTF-8, declared line-ending normalization, UTC timezone, pinned locale,
stable sorting, injected logical clock, fixed seed or declared absence, and
pinned canonical serialization.

### PF-13 — Output path and sealing

Verify output directory is empty or uniquely case-scoped, writable only by the
case process, and capable of producing sealed artifact fingerprints.

### PF-14 — Privacy controls

Verify synthetic fixture classification, redaction profile, raw-output
handling, and stable fingerprint preservation. Unapproved sensitive input is
\`BLOCKED\`.

### PF-15 — Evidence schema readiness

Verify the future evidence record can reference the selected fixture,
authority, replay runner, environment, output artifacts, lineage, and review
placeholder. This check validates structure only; it does not create a PASS.

### PF-16 — Review separation

Verify the operator identity and independent reviewer identity are declared as
different identities. The reviewer may remain an unassigned placeholder at
preflight, but cannot equal the operator.

## 5. Preflight evidence record

The validator must emit a preflight record containing:

~~~yaml
preflight_id: <stable id>
spec_version: 0.1
status: RECORDED
runner:
  runner_id: pmiri-gc-c1-replay
  runner_version: 0.1.0
  source_fingerprint: <sha256>
  manifest_fingerprint: <sha256>
inputs:
  authority_bundle_fingerprint: <sha256>
  schema_fingerprint: <sha256>
  catalog_fingerprint: <sha256>
  matrix_fingerprint: <sha256>
selected_fixture_id: <id>
selected_case_id: <id>
environment:
  environment_fingerprint: <sha256>
  network: DENIED|UNVERIFIED
  credentials: DENIED|UNVERIFIED
  filesystem: ALLOWLIST_VERIFIED|UNVERIFIED
  determinism: VERIFIED|UNVERIFIED
  resource_limits: VERIFIED|UNVERIFIED
  teardown: AVAILABLE|UNVERIFIED
checks:
  - check_id: PF-01
    severity: HARD_BLOCK
    result: READY|BLOCKED|VALIDATION_ERROR|ISOLATION_VIOLATION
    assertion: <check assertion>
    observation: <redacted observation>
    evidence_refs: [<artifact ref>]
    observed_fingerprints: [<sha256>]
artifacts:
  output_fingerprint: <sha256>
  artifact_manifest_fingerprint: <sha256>
  isolation_attestation_ref: <artifact ref>
  privacy_record_ref: <artifact ref>
  seal_status: UNSEALED|SEALED|INTEGRITY_FAILURE|INCOMPLETE|INVALIDATED
overall_result: READY_FOR_REPLAY|BLOCKED|VALIDATION_ERROR|ISOLATION_VIOLATION
captured_at: <UTC timestamp>
~~~

A preflight record is not an R-FC evidence record and cannot be used to claim
that an R-FC replay passed. The canonical per-check result is `READY`; `PASS`
is forbidden in this record.

## 6. Failure and fail-closed rules

- A missing or mismatched authority fingerprint blocks replay.
- A missing runner or environment fingerprint blocks replay.
- A failed isolation check returns \`ISOLATION_VIOLATION\`.
- A malformed schema, manifest, catalog, or fixture returns
  \`VALIDATION_ERROR\`.
- A missing resource limit returns \`BLOCKED\`.
- Any visible ambient credential returns \`ISOLATION_VIOLATION\`.
- Any undeclared filesystem access returns \`ISOLATION_VIOLATION\`.
- Any network access attempt returns \`ISOLATION_VIOLATION\`.
- An actual semantic \`INDETERMINATE\` result is not resolved by preflight and
  must remain visible during replay/review.
- No failed check may be downgraded to warning.
- No preflight result may assign R-FC \`PASS\`.

## 7. Preflight exit criteria

GC-C1-04 is complete as a contract only when:

- PF-01 through PF-16 are machine-readable;
- every check has a hard failure disposition;
- exact input fingerprints are mandatory;
- clean-room, network, credential, and filesystem boundaries are explicit;
- deterministic runtime requirements are explicit;
- preflight output is itself fingerprintable;
- preflight cannot assign an R-FC result;
- \`READY_FOR_REPLAY\` is distinct from \`PASS\`;
- no R-FC test is executed by this package.

Until an actual pinned validator runs and is independently reviewed, GC-C1
remains design-only and R-FC-01 through R-FC-17 remain \`UNVERIFIED\`.
