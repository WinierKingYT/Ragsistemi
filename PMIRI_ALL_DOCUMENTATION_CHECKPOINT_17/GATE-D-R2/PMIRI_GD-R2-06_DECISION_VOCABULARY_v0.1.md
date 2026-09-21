# PMIRI — Gate D Round 2 — Canonical Decision Vocabulary

**Version:** 0.2  
**Status:** `CANDIDATE / BLOCKER-CLOSURE`  
**Gate:** D2  
**Implementation authorization:** `NOT GRANTED`

## 1. Purpose

This document separates evidence state, final action, content lifecycle and
reason class. A state is never itself an authorization result.

The machine-readable enum source is:

```text
PMIRI_GD-R2-06_DECISION_VOCABULARY.schema.json
```

All D2 records MUST use the exact enum values below. Human-readable text may
explain a result but cannot add, rename or override an enum value.

The schema file keeps its stable bundle filename, while its authoritative
`$id` and `vocabulary_version` are now `0.2`.

## 2. Evidence states

### 2.1 Trust state

```text
TRUSTED_FOR_BOUND_PURPOSE
CONDITIONALLY_TRUSTED
UNTRUSTED
UNKNOWN
EXPIRED
REVOKED
CONTRADICTED
INVALID
```

### 2.2 Capability state

```text
FRESH
STALE
MISSING
REVOKED
CONTRADICTED
INVALID
OUT_OF_SCOPE
```

### 2.3 Obligation impact state

```text
PRESERVED
PRESERVED_WITH_CONSTRAINT
WEAKENED
UNSATISFIABLE
INVALIDATED
NOT_APPLICABLE
```

## 3. Final action result

```text
ALLOW
ALLOW_WITH_CONSTRAINTS
DENY
REQUIRE_REVIEW
REQUIRE_REVALIDATION
LOCAL_ONLY
```

`LOCAL_ONLY` means that the material may remain on an authorized local path,
but the current decision does not authorize external disclosure. It is not a
weaker form of `ALLOW`.

The following values MUST NOT appear in an `action_result` field:

```text
FRESH
STALE
UNKNOWN
CONTRADICTED
DEGRADED
UNSATISFIABLE
QUARANTINE
BOUNDED_ABORT
```

Those values belong to evidence, obligation, lifecycle or reason fields.

## 3.1 Closed operation and purpose vocabularies

Operations and purposes are closed-world fields. The only valid operations
are:

```text
provider_call
connector_fetch
attachment_fetch
external_fetch
```

The only valid purposes are:

```text
retrieval
context_delivery
external_fetch
attachment_import
provider_call
```

An unknown or unsupported operation/purpose is an
`INTERNAL_CONTRACT_INVALID` condition and must be denied or held for review;
there is no `other` fallback.

## 4. Content lifecycle

```text
NOT_APPLICABLE
QUARANTINED
ADMITTED_TYPED_DATA
REJECTED
DISCARDED
ABORTED
```

For example, a response-size violation is represented as:

```text
action_result: DENY
content_lifecycle: ABORTED
reason_class: RESOURCE_LIMIT_EXCEEDED
```

An attachment containing instruction-like text is represented as:

```text
action_result: LOCAL_ONLY
content_lifecycle: QUARANTINED
reason_class: UNTRUSTED_EXTERNAL_CONTROL_TEXT
```

## 5. Reason classes

The canonical reason classes are:

```text
NONE
AUTHORITY_MISSING
AUTHORITY_CONFLICT
EXACT_BINDING_MISSING
SCOPE_MISMATCH
POLICY_UNKNOWN
POLICY_STALE
POLICY_CONTRADICTION
STALE_EVIDENCE
REVOKED_EVIDENCE
CLASSIFICATION_MISMATCH
MATERIAL_FINGERPRINT_MISMATCH
CAPABILITY_MISSING
CAPABILITY_OUT_OF_SCOPE
DESTINATION_NOT_ALLOWLISTED
CREDENTIAL_SCOPE_INVALID
CREDENTIAL_VISIBILITY_RISK
URL_INVALID
UNSUPPORTED_SCHEME
PRIVATE_ADDRESS
DNS_REBINDING
REDIRECT_UNAUTHORIZED
TLS_IDENTITY_MISMATCH
RESOURCE_LIMIT_EXCEEDED
CONTENT_TYPE_DISALLOWED
SEMANTIC_OBLIGATION_UNSATISFIABLE
CITATION_INVALID
HIDDEN_RETRIEVAL_ATTEMPT
POLICY_EPOCH_CHANGED
TEARDOWN_UNPROVEN
UNTRUSTED_EXTERNAL_CONTROL_TEXT
INTERNAL_CONTRACT_INVALID
REVIEW_REQUIRED
```

## 6. Mandatory state-to-action mapping

The following state-to-action matrix is exhaustive for the evidence states.
The permitted set is applied only after the other D1/D2 intersection checks;
it is not a grant by itself.

| Evidence state | Permitted action results |
|---|---|
| `TRUSTED_FOR_BOUND_PURPOSE` | `ALLOW`, `ALLOW_WITH_CONSTRAINTS`, `DENY`, `REQUIRE_REVIEW`, `REQUIRE_REVALIDATION`, `LOCAL_ONLY` |
| `CONDITIONALLY_TRUSTED` | `ALLOW_WITH_CONSTRAINTS`, `DENY`, `REQUIRE_REVIEW`, `REQUIRE_REVALIDATION`, `LOCAL_ONLY` |
| `UNKNOWN`, `UNTRUSTED`, `EXPIRED`, `REVOKED`, `CONTRADICTED`, `INVALID` | `DENY`, `REQUIRE_REVIEW`, `REQUIRE_REVALIDATION`, `LOCAL_ONLY` |
| `FRESH` capability | `ALLOW`, `ALLOW_WITH_CONSTRAINTS`, `DENY`, `REQUIRE_REVIEW`, `REQUIRE_REVALIDATION`, `LOCAL_ONLY` |
| `STALE`, `MISSING`, `REVOKED`, `CONTRADICTED`, `INVALID`, `OUT_OF_SCOPE` capability | `DENY`, `REQUIRE_REVIEW`, `REQUIRE_REVALIDATION`, `LOCAL_ONLY` |

No component may convert a state to an action outside this matrix. The
`MISSING` capability state additionally requires
`reason_class=CAPABILITY_MISSING`; exact binding mismatch requires the
appropriate binding-failure reason and an action that cannot authorize
external disclosure. Obligation-impact, lifecycle and network conditions
remain separate typed checks.

The matrix is structurally enforced in the trust-decision,
capability-decision and integrated-envelope schemas and normatively expanded
in `PMIRI_GD-R2_CROSS_FIELD_VALIDATION_RULES_v0.4.md`.

## 7. Canonical serialization and fingerprint input

All D2 JSON records use the following shared serialization rules:

- UTF-8 encoding;
- JSON object keys sorted lexicographically at every object depth;
- compact separators with no insignificant whitespace;
- array order preserved exactly as declared by the record contract;
- finite JSON numbers only; no NaN or Infinity;
- timestamps represented as RFC 3339 date-time strings in UTC;
- no trailing newline in the fingerprint input.

Each record fingerprint is SHA-256 over its canonical record with the
record’s own fingerprint field omitted. A derived decision additionally binds
the exact fingerprints of every referenced authority, input, policy, validity,
material and transformation record required by its schema. A displayed
fingerprint is never used as a substitute for the referenced record.

## 8. Acceptance boundary

This vocabulary is a candidate blocker-closure artifact. It does not grant
D2 acceptance and does not authorize implementation or runtime validation.
