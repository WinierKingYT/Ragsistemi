# PMIRI — Gate D Round 2 — Integrated Decision Model and Adversarial Matrix

**Version:** 0.3  
**Status:** `CANDIDATE / DESIGN-ONLY / REVIEW REQUIRED`  
**Gate:** D2  
**Implementation authorization:** `NOT GRANTED`

## 1. Integrated D2 decision chain

```text
RequestAuthorizationBinding
        ↓
AuthorizationSubjectChain
        ↓
PurposeBinding
        ↓
SecurityClassificationBinding
        ↓
DerivedSensitivityAssessment
        ↓
DestinationSecurityBinding
        ↓
Provider/Connector Trust Decision
        ↓
Capability Freshness Decision
        ↓
Redaction / Constrained Egress Decision
        ↓
External Fetch / Network Decision
        ↓
SecurityDecisionValidity
        ↓
Final External Emission Fence
```

Each stage may narrow or deny. No later stage may widen a previous authority,
classification, purpose, material set or destination binding.

## 2. Required cross-object bindings

The normative envelope is
`PMIRI_GD-R2-05_INTEGRATED_DECISION_ENVELOPE.schema.json`.

The final outbound decision must bind all of:

```text
request authorization fingerprint
authorization-lineage ref and fingerprint
source EvidenceSet ref and fingerprint
ContextIntent ref and fingerprint
inherited epistemic-ceiling ref and fingerprint
semantic-obligations ref and fingerprint
subject-chain fingerprint
purpose fingerprint
exact operation and purpose
material manifest fingerprint
destination binding fingerprint
trust assertion set fingerprint
capability observation set fingerprint
redaction/constrained artifact fingerprint
typed outbound network decision ref and fingerprint
typed fetched-content lifecycle ref and fingerprint when operation is content-bearing
network resolution/allowlist fingerprint
policy version
authority manifest fingerprint
validity, connection and policy invalidation epochs
```

For `emission_mode=EXTERNAL`, the constrained-artifact and network-binding
fingerprints are mandatory, non-null and must resolve to the exact records used
by the emission fence. For `emission_mode=LOCAL_ONLY`, those two downstream
fingerprints may be null only when `action_result=LOCAL_ONLY`; this is a
non-egress branch and cannot be upgraded later without a new external decision.

The `authority manifest fingerprint` is required by
`PMIRI_GD-R2-05_INTEGRATED_DECISION_ENVELOPE.schema.json` and MUST identify
`PMIRI_GD-R2_AUTHORITY_BUNDLE_MANIFEST_v0.1.json`. It binds the exact accepted
Gate-C and D1 member set consumed by the decision.

If one required binding is missing, stale, contradictory or mismatched, the
decision is not externally emit-able.

The integrated schema revision is `0.3`. Cross-record equality that cannot be
expressed by JSON Schema alone is a normative validator obligation: resolve
each referenced record, compare its fingerprint and operation/purpose/epoch
fields to the envelope, and fail closed on any mismatch or missing record.
The `outbound_network_decision_ref` MUST resolve to record type
`PMIRI_D2_OUTBOUND_NETWORK_DECISION`; content-bearing operations additionally
bind the exact fetched-content lifecycle record. `provider_call` requires
`content_lifecycle=NOT_APPLICABLE` and null lifecycle references. Content-
bearing operations additionally carry explicit lifecycle projection fields:
origin binding, destination binding, admission state, retrieval visibility,
history terminal state and terminal response fingerprint. These values must
equal the resolved lifecycle record and the outbound network decision; the
outbound and integrated operation and purpose must equal the lifecycle's
operation and purpose. The integrated destination binding reference must
equal the lifecycle and outbound destination binding references.

## 3. State vocabulary versus action vocabulary

Trust states and capability freshness states are evidence classifications. They
are not themselves permission to emit. The final action decision is a separate
typed field.

```text
trust state:       TRUSTED_FOR_BOUND_PURPOSE | UNKNOWN | REVOKED | ...
capability state:  FRESH | STALE | MISSING | CONTRADICTED | ...
action result:     ALLOW | ALLOW_WITH_CONSTRAINTS | DENY | ...
```

For example, a `FRESH` capability observation can still produce `DENY` when
the destination classification or purpose binding is incompatible. A
`CONDITIONALLY_TRUSTED` destination can produce
`ALLOW_WITH_CONSTRAINTS`, but never silently produces unrestricted `ALLOW`.

The complete state-to-action rule is closed and is enforced by the decision
schemas plus `PMIRI_GD-R2_CROSS_FIELD_VALIDATION_RULES_v0.5.md`:

| Evidence state | Permitted action results |
|---|---|
| `TRUSTED_FOR_BOUND_PURPOSE` | `ALLOW`, `ALLOW_WITH_CONSTRAINTS`, `DENY`, `REQUIRE_REVIEW`, `REQUIRE_REVALIDATION`, `LOCAL_ONLY` |
| `CONDITIONALLY_TRUSTED` | `ALLOW_WITH_CONSTRAINTS`, `DENY`, `REQUIRE_REVIEW`, `REQUIRE_REVALIDATION`, `LOCAL_ONLY` |
| `UNKNOWN`, `UNTRUSTED`, `EXPIRED`, `REVOKED`, `CONTRADICTED`, `INVALID` | `DENY`, `REQUIRE_REVIEW`, `REQUIRE_REVALIDATION`, `LOCAL_ONLY` |
| `FRESH` capability | `ALLOW`, `ALLOW_WITH_CONSTRAINTS`, `DENY`, `REQUIRE_REVIEW`, `REQUIRE_REVALIDATION`, `LOCAL_ONLY` |
| `STALE`, `MISSING`, `REVOKED`, `CONTRADICTED`, `INVALID`, `OUT_OF_SCOPE` capability | `DENY`, `REQUIRE_REVIEW`, `REQUIRE_REVALIDATION`, `LOCAL_ONLY` |

The integrated result is the intersection of the applicable trust and
capability rows after D1, policy, egress, network and validity checks.

## 4. Decision result vocabulary

```text
ALLOW
ALLOW_WITH_CONSTRAINTS
DENY
REQUIRE_REVIEW
REQUIRE_REVALIDATION
LOCAL_ONLY
```

These are the canonical `action_result` dispositions. `STALE`, `UNKNOWN`,
`CONTRADICTED` and `INVALID` belong to evidence state fields; obligation
impacts and content lifecycle have their own enums. Human-readable text may
explain them but cannot override them.

## 5. Adversarial coverage requirement

The D2 review must include at least one positive and one adversarial case for
each of the following classes:

- provider/model/feature substitution;
- stale or revoked capability;
- unknown retention/training/subprocessor policy;
- destination classification mismatch;
- redaction removing a conflict or qualifier;
- citation map invalidation after transformation;
- constrained compiler attempting hidden retrieval;
- connector credential over-scope;
- `http` downgrade or unsupported URL scheme;
- localhost/private/metadata address;
- DNS rebinding;
- redirect to an unapproved or private target;
- oversized/compressed/mislabelled response;
- attachment content attempting to become trusted control;
- network policy change between decision and emission;
- stale decision-cache replay;
- teardown or cancellation failure.

## 6. D2 candidate status

This integrated model is a candidate package. It does not claim:

- D2 acceptance;
- runtime network enforcement;
- provider policy verification;
- connector credential isolation;
- SSRF test execution;
- production egress authorization.

The independent reviewers returned `FIX-FIRST` with findings
`IR-D2-01` through `IR-D2-15`. Correction revision `0.3` addresses those
findings at the documentary contract level but still requires a new independent
recheck. No D2 acceptance or runtime authorization is claimed.

The next D2 round must perform a hard contract review against the machine-
readable schemas, canonical vocabulary, authority/freshness matrix and all
accepted D1/C contracts.
