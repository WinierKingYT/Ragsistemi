# PMIRI — GC-C1-06 Preflight Validator Output/Evidence Contract

**Version:** 0.1  
**Status:** DESIGN ONLY / NOT EXECUTED  
**Gate:** C.1 — Closure Evidence Hardening  
**Implementation authorization:** NOT GRANTED

## 1. Purpose

This contract defines the immutable output produced by a future GC-C1 preflight
validator. It makes readiness, failure, fingerprints, isolation, and review
evidence machine-verifiable.

It does not execute preflight, execute R-FC tests, assign PASS, change Gate-C
semantics, enter Gate D, or unblock production work.

## 2. Overall result semantics

~~~text
READY_FOR_REPLAY
BLOCKED
VALIDATION_ERROR
ISOLATION_VIOLATION
~~~

READY_FOR_REPLAY means prerequisites are satisfied only. It never means an R-FC
check passed.

## 3. Required output envelope

The output must include:

- stable preflight_id;
- runner ID and version;
- runner source and manifest fingerprints;
- exact authority bundle, schema, catalog, and matrix fingerprints;
- selected fixture/case identity;
- environment fingerprint;
- all PF-01…PF-16 check records;
- isolation and denial probes;
- deterministic-runtime record;
- resource-limit record;
- output/sealing capability record;
- privacy-control record;
- final result;
- UTC capture time;
- sealed artifact manifest.

No field may be silently omitted because the result is negative.

## 4. Per-check record

Every PF check record must contain:

~~~yaml
check_id: PF-01..PF-16
severity: HARD_BLOCK
result: READY|BLOCKED|VALIDATION_ERROR|ISOLATION_VIOLATION
assertion: <the check's declared assertion>
observation: <redacted factual observation>
evidence_refs: [<content-addressed refs>]
observed_fingerprints: [<sha256 values>]
failure_reason: <required for non-READY result>
~~~

PASS is not a valid preflight check result. Preflight readiness is a separate
vocabulary from R-FC evidence status.

## 5. Fingerprint rules

Fingerprints must be SHA-256 over canonical bytes. The output must distinguish:

- declared fingerprint;
- observed fingerprint;
- match result.

A mismatch is evidence, not a warning. Redaction may hide payload values but
must not remove the fingerprints or their comparison result.

## 6. Isolation and deterministic evidence

The output must record whether the following were verified:

- fresh case root;
- read-only input allowlist;
- case-scoped output;
- home/repository denial;
- network and connector denial;
- ambient credential denial;
- shared process/cache/session denial;
- undeclared filesystem denial;
- teardown capability;
- UTF-8 and declared line-ending behavior;
- UTC timezone and pinned locale;
- stable sorting and serialization;
- injected logical clock;
- fixed seed or declared absence;
- bounded resource limits.

An unverified capability is not equivalent to a successful capability.

## 7. Failure mapping

- missing or mismatched required authority → BLOCKED;
- malformed manifest/schema/catalog/fixture → VALIDATION_ERROR;
- unavailable or unverifiable isolation → ISOLATION_VIOLATION;
- reachable network, visible credential, or allowlist breach →
  ISOLATION_VIOLATION;
- missing resource/determinism/output/privacy/review prerequisite → BLOCKED;
- any hard failure prevents replay;
- no failure may be downgraded to a warning;
- no output may assign an R-FC PASS.

## 8. Sealing and review

After all checks are recorded, the envelope must be sealed with:

- output fingerprint;
- artifact manifest fingerprint;
- environment fingerprint;
- runner/manifest fingerprints;
- capture timestamp;
- teardown result.

Any post-seal change invalidates the envelope.

The validator may produce a review placeholder, but cannot approve itself.
Independent review is required before any later evidence workflow can assign
R-FC PASS.

## 9. Privacy requirements

The preflight output must use synthetic data by default. It must record:

- privacy classification;
- redaction profile;
- raw-output handling;
- whether sensitive material was detected;
- stable fingerprints after redaction.

Sensitive content must not be copied into the output merely to prove that it
was detected.

## 10. Exit criteria

GC-C1-06 is complete as a design contract only when:

- the output schema is machine-readable and strict;
- PF-01…PF-16 are required and individually recorded;
- overall outcomes are limited to the four declared values;
- fingerprint comparison is explicit;
- isolation, deterministic runtime, limits, privacy, and sealing are captured;
- preflight readiness is separate from R-FC PASS;
- failure is fail-closed;
- no tests are executed by this package.

Until a pinned validator emits and independently reviews this envelope, all
preflight scenarios remain DESIGN ONLY and R-FC-01…R-FC-17 remain UNVERIFIED.

