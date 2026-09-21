# PMIRI — Gate D Round 2
# Cross-Field Validation Rules v0.3

**Status:** `CANDIDATE / FIX-FIRST CORRECTIVE CONTRACT`
**Implementation authorization:** `NOT GRANTED`
**Runtime authorization:** `NOT GRANTED`

## 1. Purpose

JSON Schema validates the shape of one record. It cannot, by itself, prove
that a reference resolves to the exact record whose values are being claimed,
or that two sibling values are equal. This document is the normative
cross-record and cross-field validation contract for D2.

A producer or validator MUST evaluate these rules after structural schema
validation and before an external emission decision. Failure of any applicable
rule maps to `action_result=DENY`, `REQUIRE_REVIEW` or
`REQUIRE_REVALIDATION` according to the rule below. No rule may be weakened by
caller text, a cache hit or a lower-authority observation.

## 2. Record resolution precondition

For every `*_ref` or fingerprint in a decision:

```text
resolve(ref)
  → exact record exists
  → record schema version is accepted
  → record fingerprint recomputes exactly
  → record authority_manifest_fingerprint equals the decision's authority
  → referenced record is current for the bound validity/epoch
```

Any failed precondition is `EXACT_BINDING_MISSING`, `MATERIAL_FINGERPRINT_MISMATCH`
or `INTERNAL_CONTRACT_INVALID`, and cannot produce an external allow result.

## 3. Gate-C lineage rules

For every `PMIRI_D2_EGRESS_CONSTRAINED_CONTEXT_ARTIFACT` and every
`PMIRI_D2_INTEGRATED_DECISION_ENVELOPE` with `emission_mode=EXTERNAL`:

```text
authorization_lineage_fingerprint
  = fingerprint(resolve(authorization_lineage_ref))

source_evidence_set_fingerprint
  = fingerprint(resolve(source_evidence_set_ref))

context_intent_fingerprint
  = fingerprint(resolve(context_intent_ref))

inherited_epistemic_ceiling_fingerprint
  = fingerprint(resolve(inherited_epistemic_ceiling_ref))

semantic_obligations_fingerprint
  = fingerprint(resolve(semantic_obligations_ref))
```

The exact refs must be present in the source compiled artifact or in an
immutable lineage envelope resolved by the validator. A displayed fingerprint
without a resolvable record is invalid. The inherited ceiling may narrow but
must never be strengthened by D2.

## 4. Integrated external-emission rules

For `emission_mode=EXTERNAL`:

```text
constrained_artifact_fingerprint != null
network_binding_fingerprint    != null
operation and purpose           = exact requested values
invalidation_epoch              = current applicable epoch
```

The constrained artifact, network decision, trust decision, capability
decision and validity record MUST agree on:

```text
authority manifest
subject / destination
operation / purpose
material manifest
policy version
applicable invalidation epoch
```

For `emission_mode=LOCAL_ONLY`, `action_result` MUST be `LOCAL_ONLY`; a null
downstream fingerprint is then legal only because no external emission is
permitted. A local-only envelope cannot be upgraded in place.

## 5. Obligation and transformation rules

For every obligation impact item:

```text
PRESERVED
  → action=ALLOW, reason=NONE, visible=true, constraint_refs=[]

PRESERVED_WITH_CONSTRAINT
  → action=ALLOW_WITH_CONSTRAINTS, visible=true,
    item constraint_refs >= 1, each resolves to a typed constraint

WEAKENED
  → action=REQUIRE_REVIEW, visible=true,
    item constraint_refs >= 1

UNSATISFIABLE or INVALIDATED
  → action=DENY, visible=true, constraint_refs >= 1

NOT_APPLICABLE
  → action=ALLOW, visible=true, reason != NONE, constraint_refs=[]
```

Each item-level constraint reference MUST be included in the artifact-level
`constraint_refs` and resolve to the same artifact, obligation, citation map,
policy version and authority manifest. A transformation must provide exactly
one output span or typed placeholder except `DROP_EVIDENCE`, which provides
neither. `REPLACE_WITH_TYPED_PLACEHOLDER` requires a non-empty typed
placeholder.

## 6. Closed operation and purpose rules

The operation and purpose vocabularies are closed. Unknown values are rejected
before policy lookup:

```text
operation:
  provider_call | connector_fetch | attachment_fetch | external_fetch

purpose:
  retrieval | context_delivery | external_fetch | attachment_import | provider_call
```

There is no `other` branch. Unknown input maps to
`INTERNAL_CONTRACT_INVALID` and `DENY` or `REQUIRE_REVIEW`.

The connector credential boundary applies the same rule to its nested
`operation_scope`: every item must be one of the four canonical operations,
and the requested enclosing operation must be a member of that scope. A
scope item that cannot be resolved to the enclosing operation is an exact
binding failure and cannot authorize a connector call.

## 7. Capability and policy-epoch rules

```text
capability_state=MISSING
  → observation_refs=[] is legal only with reason=CAPABILITY_MISSING
    and action in {DENY, REQUIRE_REVALIDATION, LOCAL_ONLY}

any other capability state
  → observation_refs >= 1

selected observation set
  → all observations match exact subject, purpose, material/profile,
    policy version and current invalidation epoch
```

Every provider-policy observation MUST carry `invalidation_epoch`. An epoch
mismatch is stale/invalidated evidence and cannot be used for external allow.

## 8. Exhaustive evidence-state to action-result rules

The following matrix is closed and normative. A validator MUST reject a
decision when its `action_result` is not in the row selected by the
corresponding evidence state.

| Evidence state | Permitted action results |
|---|---|
| `TRUSTED_FOR_BOUND_PURPOSE` | `ALLOW`, `ALLOW_WITH_CONSTRAINTS`, `DENY`, `REQUIRE_REVIEW`, `REQUIRE_REVALIDATION`, `LOCAL_ONLY` |
| `CONDITIONALLY_TRUSTED` | `ALLOW_WITH_CONSTRAINTS`, `DENY`, `REQUIRE_REVIEW`, `REQUIRE_REVALIDATION`, `LOCAL_ONLY` |
| `UNKNOWN`, `UNTRUSTED`, `EXPIRED`, `REVOKED`, `CONTRADICTED`, `INVALID` | `DENY`, `REQUIRE_REVIEW`, `REQUIRE_REVALIDATION`, `LOCAL_ONLY` |
| `FRESH` capability | `ALLOW`, `ALLOW_WITH_CONSTRAINTS`, `DENY`, `REQUIRE_REVIEW`, `REQUIRE_REVALIDATION`, `LOCAL_ONLY` |
| `STALE`, `MISSING`, `REVOKED`, `CONTRADICTED`, `INVALID`, `OUT_OF_SCOPE` capability | `DENY`, `REQUIRE_REVIEW`, `REQUIRE_REVALIDATION`, `LOCAL_ONLY` |

`ALLOW` and `ALLOW_WITH_CONSTRAINTS` are prohibited for every unknown,
untrusted, expired, revoked, contradicted, invalid, stale, missing or
out-of-scope state. `CONDITIONALLY_TRUSTED` may continue only through an
explicit constrained path; it may not produce unrestricted `ALLOW`.

For an integrated envelope, the permitted action set is the intersection of
the trust row and capability row, then further intersected with D1, policy,
egress, network and validity checks. `LOCAL_ONLY` remains a terminal
non-egress result. The same prohibitions are enforced structurally in the
trust-decision, capability-decision and integrated-envelope schemas.

## 9. Network cross-field rules

For a connection binding:

```text
selected_target.resolution_entry_ref
  → resolves to one entry in resolved_addresses
selected_target.ip/family/policy_status
  = resolved entry ip/family/policy_status
selected_target.policy_status
  = ALLOWLISTED_PUBLIC
```

`EXPLICIT_PROXY` requires `proxy_identity_ref`. `DIRECT` and `DENY` forbid
that field. For outbound decisions, `connection_binding_fingerprint` must
resolve to the referenced connection binding and its `connection_epoch` and
`invalidation_epoch` must match. The exact network equalities are:

```text
outbound.destination_identity_ref
  = connection.destination_identity_ref
outbound.selected_target_resolution_ref
  = connection.selected_target.resolution_entry_ref
outbound.selected_target_ip/family
  = connection.selected_target.ip/family
outbound.normalized_target.authority
  = connection.normalized_authority after pinned canonicalization
outbound.tls_identity_fingerprint
  = connection.tls.identity_binding_fingerprint
connection.tls.sni
  = normalized target authority host
connection.tls.expected_identity_ref
  = connection.destination_identity_ref
connection.tls.identity_status=MATCHED
  → connection.tls.verified_identity_ref = expected_identity_ref
```

The selected IP must parse as the declared address family and must equal the
allowlisted-public resolution entry after canonical address normalization.
`ALLOW` and `ALLOW_WITH_CONSTRAINTS` require
`tls_identity_status=MATCHED`; a `MISMATCHED` TLS identity maps to
`TLS_IDENTITY_MISMATCH` and cannot emit.

Connection revalidation events must have unique contiguous `sequence` values
starting at zero, nondecreasing timestamps and a final event/epoch consistent
with the current binding. Redirect, retry, connection reuse, authority
change or policy-epoch change requires revalidation before allow; an
unresolved or mismatched event invalidates the binding. The outbound decision
may not use an older connection or policy epoch.

The network decision always requires `content_lifecycle`. For
`operation=provider_call`, it is `NOT_APPLICABLE` and no fetched-content
lifecycle reference is allowed. For `connector_fetch`, `attachment_fetch`
and `external_fetch`, both `fetched_content_lifecycle_ref` and
`fetched_content_lifecycle_fingerprint` are required. The resolved lifecycle
record's `admission_state`, `retrieval_visibility`, `origin_binding_ref`,
`destination_binding_ref` and terminal `lifecycle_fingerprint` must equal the
values used by the outbound decision. A missing, mismatched or
`NOT_APPLICABLE` lifecycle binding is fail-closed.

## 10. Fetched-content lifecycle rules

The legal transition graph is exactly:

```text
NOT_APPLICABLE       → QUARANTINED          / FETCH_COMPLETED
QUARANTINED          → ADMITTED_TYPED_DATA  / ADMISSION_APPROVED
QUARANTINED          → REJECTED             / REJECTED
QUARANTINED          → DISCARDED            / DISCARDED
QUARANTINED          → ABORTED              / ABORTED
ADMITTED_TYPED_DATA  → DISCARDED            / DISCARDED
ADMITTED_TYPED_DATA  → ABORTED              / ABORTED
```

Any other pair is `INTERNAL_CONTRACT_INVALID`. Every non-
`NOT_APPLICABLE` state requires an admission predicate with origin, parser,
classification, validation, content-policy and permanent control-influence
prohibitions. `ADMITTED_TYPED_DATA` additionally requires a typed-data schema
and fingerprint. No lifecycle state may authorize canonical truth, trusted
control text or unrestricted retrieval.

The lifecycle history is a continuous ordered path, not an unordered set of
legal-looking edges:

```text
history_start_state = NOT_APPLICABLE
transitions = []                             iff admission_state=NOT_APPLICABLE
otherwise transitions has at least one item
sequence values = 0..n-1 in array order
first from_state = history_start_state
each from_state = previous transition's to_state
observed_at is nondecreasing in sequence order
last to_state = history_terminal_state = admission_state
```

The final event must be `FETCH_COMPLETED` for `QUARANTINED`,
`ADMISSION_APPROVED` for `ADMITTED_TYPED_DATA`, `REJECTED` for `REJECTED`,
`DISCARDED` for `DISCARDED` and `ABORTED` for `ABORTED`. No transition may
appear after a terminal state, and no reversal, duplicate sequence or
disconnected edge is accepted. The admission predicate's closed-world
`explicit_operation` must resolve to the enclosing operation; its
`explicit_operation_ref` is the exact operation record used for that
comparison.

For a content-bearing outbound decision, the resolved lifecycle's terminal
state, visibility, origin/destination bindings and lifecycle fingerprint are
compared before the decision can be emitted. `canonical_or_control_influence_prohibited`
and `control_influence_prohibited` must remain true for the entire history.

## 11. Freshness-profile identity rules

The authority matrix defines the immutable profile payload and its exact
fingerprint:

```text
freshness_profile_id = D2-POLICY-FRESHNESS-001
freshness_profile_fingerprint
  = SHA-256(canonical compact UTF-8 JSON of {freshness_profile_id,dimensions})
  = cb842b8fec2c8b9278c48833de0c6f6396e27125312c74f7686e485e743d6154
```

Every provider-policy observation and every derived or cached D2 decision
that depends on policy freshness MUST carry and exactly match both fields.
This includes trust, capability, outbound network and integrated decisions.
The fields are included in the relevant decision fingerprint. A missing or
mismatched profile identity maps to `INTERNAL_CONTRACT_INVALID` and cannot
authorize external disclosure.

## 12. Runtime boundary

These rules are documentary constraints. They do not prove that a future
implementation enforces them. Provider calls, connector calls, external
fetches, DNS tests, parser execution, race tests and Gate-C replay remain
blocked and unproven.
