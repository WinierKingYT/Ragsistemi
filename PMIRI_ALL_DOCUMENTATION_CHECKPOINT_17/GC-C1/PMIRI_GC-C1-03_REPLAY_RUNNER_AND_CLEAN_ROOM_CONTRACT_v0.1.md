# PMIRI — GC-C1-03 Replay Runner and Clean-Room Execution Contract

**Version:** 0.1  
**Status:** \`DESIGN ONLY / NOT EXECUTED\`  
**Gate:** C.1 — Closure Evidence Hardening  
**Implementation authorization:** \`NOT GRANTED\`  
**Runner manifest:** \`PMIRI_GC-C1-03_REPLAY_RUNNER_MANIFEST.json\`

## 1. Purpose

This contract defines how a future replay runner must execute the
GC-C1-02 fixture catalog and produce evidence records accepted by the
GC-C1-02 Evidence Record schema.

It does not execute any R-FC test, declare any Gate-C check \`PASS\`, alter
Gate-C semantics, define Gate-D policy, or authorize production work.

## 2. Authoritative inputs

The runner MUST consume exact, immutable inputs:

- \`PMIRI_GC-C1-01_GATE_C_EVIDENCE_MATRIX_v0.1.md\`;
- \`PMIRI_GC-C1-02_EVIDENCE_RECORD.schema.json\`;
- \`PMIRI_GC-C1-02_REPLAY_FIXTURE_CATALOG.json\`;
- the exact accepted Gate-C R1/R2/R3 authority references and hashes;
- the runner manifest for the declared runner version.

A filename alone is not an authority reference. Each input must have a
content fingerprint and the replay manifest must record that fingerprint.

## 3. Runner identity

The runner identity is:

~~~yaml
runner_id: pmiri-gc-c1-replay
runner_version: 0.1.0
manifest_version: 0.1
latest_alias_allowed: false
network_default: deny
ambient_credentials_allowed: false
shared_session_state_allowed: false
~~~

A replay is not attributable to a runner unless the runner source/package
fingerprint, manifest fingerprint, and environment fingerprint are captured.

A runner may not self-upgrade, download dependencies, or silently select a
different version during a replay.

## 4. Clean-room isolation

Each fixture case MUST run in a fresh isolated execution root.

The clean-room MUST provide:

- a new case-specific filesystem root;
- an explicit read-only input mount/list;
- an explicit output directory;
- no access to the user's home directory;
- no access to repository working trees outside declared inputs;
- no inherited environment secrets or authentication tokens;
- no shared process, connection, cache, cursor, or session state;
- no network or external connector access by default;
- UTC locale, stable encoding, and stable sorting;
- injected clock/time rather than wall-clock reads;
- injected randomness or a fixed seed where randomness is unavoidable;
- bounded CPU, memory, disk, process count, and wall time;
- forced teardown after completion, timeout, or isolation violation.

The runner MUST fail closed as an execution system if it cannot establish the
declared isolation boundary. It must not convert an unisolated run into a
valid evidence record.

## 5. Deterministic input rules

Before execution, the runner MUST:

1. parse each fixture as UTF-8;
2. canonicalize structured input using one pinned serialization rule;
3. normalize line endings and declare the normalization;
4. set timezone and locale explicitly;
5. inject a fixed logical clock;
6. inject a fixed random seed or declare randomness absent;
7. compute SHA-256 fingerprints for all input artifacts;
8. record the ordered fixture action list;
9. reject undeclared input files or environment dependencies.

The same fixture, authority bundle, runner version, and environment contract
must produce the same normalized input fingerprint.

A differing fingerprint requires a new replay identity; it may not overwrite an
earlier evidence record.

## 6. Execution lifecycle

The runner lifecycle is fixed:

~~~text
PREFLIGHT
  ↓
PROVISION_CLEAN_ROOM
  ↓
VERIFY_AUTHORITY_AND_FIXTURE_FINGERPRINTS
  ↓
EXECUTE_DECLARED_ACTION_TRACE
  ↓
CAPTURE_RAW_AND_TYPED_RESULTS
  ↓
VALIDATE_EVIDENCE_RECORD_SCHEMA
  ↓
SEAL_ARTIFACT_HASHES
  ↓
TEARDOWN_AND_ISOLATION_ATTESTATION
  ↓
HAND_OFF_FOR_INDEPENDENT_REVIEW
~~~

No phase may be skipped silently.

### 6.1 Preflight

Preflight must verify:

- runner identity and version;
- manifest integrity;
- required schema and catalog presence;
- authority references and hashes;
- clean-room capabilities;
- resource limits;
- network and credential denial;
- output path availability;
- clock, locale, encoding, and seed configuration.

Missing or unverifiable preflight data produces \`BLOCKED\`, not \`PASS\`.

### 6.2 Execute

Execution may use only the fixture's declared setup and action trace. The
runner must not invent extra retrieval, policy, connector, or provider calls.

Every action must record:

- step number;
- operation;
- input reference;
- injected state change or fault;
- start/end logical time;
- result or exception class.

### 6.3 Capture

The runner must capture:

- typed actual disposition;
- output artifact reference and SHA-256 fingerprint;
- authorization and evidence lineage references;
- boundary/fence references when applicable;
- stdout/stderr or equivalent trace after privacy filtering;
- resource and isolation events;
- validator result;
- complete action trace.

Raw sensitive payloads must never be emitted by default.

### 6.4 Seal

After capture, the runner creates a sealed replay manifest containing:

- runner and manifest fingerprints;
- authority and fixture fingerprints;
- environment fingerprint;
- output/artifact fingerprints;
- action-trace fingerprint;
- capture timestamp in UTC;
- teardown result;
- final runner outcome.

Any artifact changed after sealing invalidates the evidence record.

## 7. Runner outcome and evidence status

The runner outcome is separate from the Gate-C evidence status:

~~~text
MATCHED             Actual result satisfies the fixture oracle.
MISMATCHED          Actual result violates the fixture oracle.
EXECUTION_ERROR     Runner or subject execution failed unexpectedly.
TIMEOUT             Resource or wall-time limit exceeded.
ISOLATION_VIOLATION Clean-room boundary was violated or unverifiable.
VALIDATION_ERROR    Evidence output failed schema or integrity validation.
BLOCKED             Required input, authority, capability, or dependency missing.
~~~

Mapping rules:

- \`MATCHED\` produces an evidence record with status \`UNVERIFIED\` until an
  independent reviewer accepts it;
- \`MISMATCHED\` produces an evidence record with status \`FAIL\`;
- \`EXECUTION_ERROR\`, \`TIMEOUT\`, \`ISOLATION_VIOLATION\`, and \`VALIDATION_ERROR\`
  produce status \`BLOCKED\` unless an independent review explicitly classifies
  the result as a contract failure;
- \`BLOCKED\` produces status \`BLOCKED\`;
- an actual semantic disposition of \`INDETERMINATE\` never becomes \`PASS\`
  automatically and must remain explicitly visible in the actual result.

The runner is not permitted to mark \`PASS\`. Only the evidence workflow after
independent review may assign \`PASS\`.

## 8. Evidence artifacts

Each case must produce, at minimum:

1. machine-readable evidence record;
2. sealed replay manifest;
3. fixture/input fingerprint set;
4. action trace;
5. oracle and actual result comparison;
6. output artifact fingerprint;
7. environment fingerprint;
8. clean-room/isolation attestation;
9. schema validation result;
10. privacy-filtering result;
11. independent-review placeholder.

Artifacts must be content-addressed or otherwise tamper-evident. Artifact
references must not be confused with authorization.

## 9. Privacy boundary

The replay corpus must use synthetic data unless a separate privacy authority
explicitly approves otherwise.

The runner must:

- deny network access by default;
- deny ambient credentials;
- redact secrets, personal identifiers, and raw restricted payloads;
- preserve stable hashes after redaction;
- record which redaction profile was applied;
- avoid storing raw stdout/stderr when it contains sensitive values;
- keep evidence sufficient for independent disposition verification.

Privacy redaction must not silently change the typed oracle or actual
disposition. If it does, the case is \`BLOCKED\` for review.

## 10. Independent review

The runner operator is not the independent reviewer.

Independent review must use:

- the sealed replay manifest;
- the exact fixture and authority fingerprints;
- the evidence record;
- the output artifacts;
- a separate review identity;
- a separate replay or inspection process where practical.

The independent reviewer must be able to reject:

- a matched result with incomplete evidence;
- a result produced outside the clean room;
- a result with authority or fingerprint mismatch;
- a result whose actual disposition is stronger than the oracle permits;
- a result where \`PASS\` was assigned by the runner itself.

## 11. Prohibited shortcuts

The following invalidate the replay:

- using \`latest\`, floating dependencies, or unpinned runner code;
- reading hidden session state or shared caches;
- using network access not declared in the manifest;
- relying on ambient credentials;
- allowing wall-clock or locale-dependent behavior;
- omitting failed actions from the trace;
- replacing a missing artifact with prose;
- overwriting an earlier replay identity;
- treating a cursor, URI, artifact ID, or evidence reference as authorization;
- marking \`PASS\` before independent review;
- using the runner to modify production code, production data, or canonical state.

## 12. GC-C1-03 exit criteria

GC-C1-03 may close only when:

- the runner identity/version and manifest are immutable and fingerprinted;
- clean-room capabilities are demonstrably available;
- deterministic input rules are executable;
- the evidence record schema validates generated records;
- all failure mappings are explicit;
- network, credential, shared-session, and filesystem boundaries are tested;
- artifact sealing and tamper detection are defined;
- privacy filtering is replayable;
- independent review is structurally separate;
- no R-FC test has been falsely reported as executed by this design contract.

Until then, GC-C1 remains \`DESIGN ONLY\`; R-FC-01 through R-FC-17 remain
\`UNVERIFIED\`.

