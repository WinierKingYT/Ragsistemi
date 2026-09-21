# PMIRI GC-C1-05A — Controlled Preflight Execution Preparation

**Version:** 0.1  
**Status:** DESIGN_ONLY  
**Execution authorization:** NOT_GRANTED  
**R-FC status:** UNVERIFIED  

## 1. Purpose and boundary

This packet prepares a future controlled preflight run against the accepted GC-C1 contracts. It binds GC-C1-01 through GC-C1-08, defines the operator checklist and records the authorization decision that must precede execution.

This packet does not execute PF checks, invoke the replay runner, replay R-FC fixtures, modify production code/data, enter Gate D or assign PASS.

## 2. Bound input set

Before authorization, the operator must fingerprint and record these exact inputs:

| Input | Required reference |
|---|---|
| Evidence matrix | GC-C1-01 |
| Evidence schema and fixture catalog | GC-C1-02 |
| Runner/clean-room contract and runner manifest | GC-C1-03 |
| Preflight contract and PF specification | GC-C1-04 |
| Controlled scenario matrix | GC-C1-05 |
| Output/evidence contract and preflight record schema | GC-C1-06 |
| Artifact sealing contract and manifest schema | GC-C1-07 |
| Accepted authority bundle | GC-C1-08 |

Any changed, missing or unresolved input produces `BLOCKED` and requires a new preparation record.

## 3. Operator preflight checklist

The operator records one result for every item. `READY` is the only affirmative preparation result; no item may be converted to a warning.

| ID | Preparation assertion | Hard stop |
|---|---|---|
| OP-01 | Execution authorization record is present, signed/attested and still valid. | Missing or expired authorization |
| OP-02 | All C1-01..C1-08 input fingerprints match the bound set. | Any mismatch or omission |
| OP-03 | Runner identity/version and source/manifest fingerprints are pinned. | Latest alias or self-upgrade |
| OP-04 | PF-01..PF-16 are loaded from the canonical specification. | Missing, duplicate or reordered check definition |
| OP-05 | Selected fixture and case are declared and mapped to R-FC-01..R-FC-17. | Unmapped or ambiguous case |
| OP-06 | Clean-room filesystem is empty/allowlisted and output root is case-scoped. | Shared or pre-populated output |
| OP-07 | Network access is denied and credential sources are unavailable. | Network/credential exposure |
| OP-08 | Determinism settings, locale, encoding, clock policy and seed policy are recorded. | Unverified deterministic runtime |
| OP-09 | CPU, memory, time, file-count and output-size limits are configured. | Missing or unenforced limit |
| OP-10 | Privacy classification, redaction and raw-output handling are configured. | Sensitive output can escape |
| OP-11 | Teardown and residue inspection are available. | Teardown unavailable |
| OP-12 | Operator and independent reviewer identities are distinct. | Same or unknown identity |
| OP-13 | Artifact manifest/sealing procedure is available and version-pinned. | Cannot seal or verify |
| OP-14 | Stop/abort channel and immutable failure capture are available. | Failure can be hidden |

## 4. Execution authorization contract

Execution is permitted only when an authorization record contains:

- authorization ID, scope and expiry;
- exact bound fingerprints for authority, schemas, catalog, matrix, runner and preparation packet;
- selected fixture/case or an explicit statement that no replay is yet selected;
- named operator and distinct independent reviewer;
- approved environment/isolation profile;
- explicit confirmation that production implementation, ingestion, migration and Gate D are outside scope;
- decision `AUTHORIZED_FOR_CONTROLLED_PREFLIGHT_ONLY`.

The decision must remain `NOT_GRANTED` until a human/authorized authority completes the record. This document cannot grant its own authorization.

## 5. Stop conditions

Stop immediately and emit a sealed blocked record if:

- any OP item is `BLOCKED`, `UNVERIFIED` or missing;
- any PF-01..PF-16 input is missing or has a fingerprint mismatch;
- network, credential, filesystem or privacy isolation is not proven;
- the selected fixture/case changes after authorization;
- the runner attempts self-upgrade, undeclared I/O or undeclared calls;
- output cannot be sealed or teardown cannot be verified;
- a negative result, exception or blocked state cannot be preserved.

Stop conditions are hard failures, not warnings and not R-FC results.

## 6. Allowed result boundaries

The future preflight may emit only `READY_FOR_REPLAY`, `BLOCKED`, `VALIDATION_ERROR` or `ISOLATION_VIOLATION`. `READY_FOR_REPLAY` permits only the separately authorized replay phase. It cannot assign R-FC `PASS`.

## 7. Handoff package

The operator must hand off, without mutating the originals:

1. authorization record;
2. preparation record with OP-01..OP-14 results;
3. preflight record template bound to PF-01..PF-16;
4. exact fingerprint set;
5. environment/isolation evidence template;
6. privacy and teardown attestations;
7. sealed manifest placeholder;
8. independent reviewer assignment/reference.

The handoff is preparation only. Until the authorization record is separately accepted, execution remains blocked.
