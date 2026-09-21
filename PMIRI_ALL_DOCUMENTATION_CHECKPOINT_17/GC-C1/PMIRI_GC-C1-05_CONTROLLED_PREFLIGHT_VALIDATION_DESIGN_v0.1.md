# PMIRI — GC-C1-05 Controlled Preflight Validation Design

**Version:** 0.1  
**Status:** \`DESIGN ONLY / NOT EXECUTED\`  
**Gate:** C.1 — Closure Evidence Hardening  
**Implementation authorization:** \`NOT GRANTED\`

## 1. Purpose

This document defines the controlled validation design for the 16 hard-block
preflight checks in GC-C1-04.

It defines scenarios and oracles only. It does not run the validator, execute
R-FC tests, assign \`PASS\`, alter Gate-C semantics, enter Gate D, or unblock
production implementation.

## 2. Validation model

Validation uses:

1. one valid baseline;
2. one isolated fault per negative scenario;
3. identical inputs and environment across scenarios;
4. no shared state between scenarios;
5. expected-result comparison;
6. artifact and isolation capture;
7. independent review after execution.

Only the named fault may differ between the baseline and its negative case.
If more than one fault is present, the scenario is invalid for controlled
attribution.

## 3. Baseline scenario

The baseline contains:

- runner \`pmiri-gc-c1-replay\` version \`0.1.0\`;
- exact manifest, schema, catalog, matrix, and R1/R2/R3 authority hashes;
- fresh case root;
- read-only input allowlist;
- case-scoped writable output;
- denied network/connectors;
- no ambient credentials;
- pinned UTF-8, UTC, locale, sorting, serialization, clock, and seed;
- declared CPU, memory, disk, process, and wall-time limits;
- synthetic fixture data;
- distinct operator and reviewer identities.

Expected baseline result:

~~~text
READY_FOR_REPLAY
~~~

This is only a preflight readiness result. It is not an R-FC result and not a
Gate-C \`PASS\`.

## 4. One-fault-at-a-time scenarios

| Scenario | Fault injected | Expected result | Replay must prove |
|---|---|---|---|
| PFV-00 | No fault; all declared prerequisites valid. | \`READY_FOR_REPLAY\` | All 16 checks are satisfied and no R-FC execution occurs. |
| PFV-01 | Runner ID or version differs from the declared manifest. | \`BLOCKED\` | Identity mismatch prevents replay. |
| PFV-02 | Runner source fingerprint differs or self-upgrade is attempted. | \`BLOCKED\` | Unpinned runner cannot execute. |
| PFV-03 | Manifest is malformed or its fingerprint differs. | \`VALIDATION_ERROR\` | Invalid manifest prevents replay. |
| PFV-04 | One required authority file is missing or hash-mismatched. | \`BLOCKED\` | Incomplete authority bundle prevents replay. |
| PFV-05 | Evidence schema is malformed or hash-mismatched. | \`VALIDATION_ERROR\` | Schema cannot be silently replaced. |
| PFV-06 | Fixture catalog is malformed or selected-case fingerprint differs. | \`VALIDATION_ERROR\` | Invalid catalog/case prevents replay. |
| PFV-07 | Selected case has no R-FC mapping or lacks positive/adversarial coverage. | \`BLOCKED\` | Coverage gap prevents replay. |
| PFV-08 | Fresh root, teardown, or required isolation capability is unavailable. | \`ISOLATION_VIOLATION\` | Replay cannot run outside a verified clean room. |
| PFV-09 | Network is reachable or an ambient credential is visible. | \`ISOLATION_VIOLATION\` | External access/credential exposure prevents replay. |
| PFV-10 | Undeclared filesystem read or write is possible. | \`ISOLATION_VIOLATION\` | Allowlist breach prevents replay. |
| PFV-11 | Any resource limit is missing or unenforceable. | \`BLOCKED\` | Unbounded execution prevents replay. |
| PFV-12 | Wall clock, locale, serialization, encoding, or seed is not pinned. | \`BLOCKED\` | Nondeterministic execution prevents replay. |
| PFV-13 | Output path is shared, pre-populated, or cannot seal artifacts. | \`BLOCKED\` | Output ambiguity or unsealed artifacts prevent replay. |
| PFV-14 | Sensitive/non-synthetic input or unavailable redaction control is present. | \`BLOCKED\` | Privacy uncertainty prevents replay. |
| PFV-15 | Evidence record cannot reference required fixture, authority, runner, environment, output, lineage, or review fields. | \`VALIDATION_ERROR\` | Structurally incomplete evidence cannot be emitted. |
| PFV-16 | Operator and reviewer identities are equal or reviewer identity is absent. | \`BLOCKED\` | Review independence cannot be bypassed. |

## 5. Control rules

- The validator must stop at the first hard failure or record all failures
  without proceeding to replay.
- A failed preflight cannot be converted to a warning.
- No scenario may execute an R-FC action after a hard preflight failure.
- A preflight record must include all PF-01…PF-16 results, even when execution
  stops early.
- Scenario, input, authority, environment, and manifest fingerprints must be
  captured before the result is interpreted.
- The baseline and each negative scenario require separate case roots and
  separate output artifacts.
- The validator must not mutate production code, production data, canonical
  state, or the fixture catalog.
- A preflight \`READY_FOR_REPLAY\` result may authorize only the next replay
  phase; it cannot assign evidence status \`PASS\`.

## 6. Required captured artifacts

Each scenario must produce:

1. scenario definition and fingerprint;
2. preflight input manifest;
3. authority/schema/catalog fingerprints;
4. runner and environment fingerprints;
5. per-check result records;
6. isolation and denial probes;
7. deterministic-runtime record;
8. output-path/sealing capability record;
9. privacy-control record;
10. final preflight result;
11. redacted stdout/stderr or equivalent trace;
12. independent-review placeholder.

## 7. Controlled-validation exit criteria

GC-C1-05 may close only when:

- PFV-00 and PFV-01…PFV-16 are defined in machine-readable form;
- every negative scenario changes exactly one declared condition;
- every scenario has a deterministic expected result;
- each hard failure maps to one of the four allowed overall outcomes;
- no scenario executes an R-FC test;
- no scenario assigns R-FC \`PASS\`;
- scenario and artifact fingerprints are mandatory;
- clean-room and privacy boundaries are part of the oracle;
- the result can be independently reviewed.

Until execution and independent review occur, all scenarios remain
\`DESIGN_ONLY\`, and R-FC-01 through R-FC-17 remain \`UNVERIFIED\`.

