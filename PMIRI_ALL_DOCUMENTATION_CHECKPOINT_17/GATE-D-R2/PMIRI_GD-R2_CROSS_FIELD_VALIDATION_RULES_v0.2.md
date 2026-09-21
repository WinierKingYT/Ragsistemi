# PMIRI — Gate D Round 2
# Cross-Field Validation Rules v0.2

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

## 8. Network cross-field rules

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
resolve to the referenced connection binding and its `connection_epoch` must
match. `ALLOW` and `ALLOW_WITH_CONSTRAINTS` require
`tls_identity_status=MATCHED`; a `MISMATCHED` TLS identity maps to
`TLS_IDENTITY_MISMATCH` and cannot emit.

The network decision always requires `content_lifecycle`. For
`operation=provider_call`, it is `NOT_APPLICABLE`; for content-bearing fetches
it must agree with the fetched-content lifecycle record and visibility.

## 9. Fetched-content lifecycle rules

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

## 10. Runtime boundary

These rules are documentary constraints. They do not prove that a future
implementation enforces them. Provider calls, connector calls, external
fetches, DNS tests, parser execution, race tests and Gate-C replay remain
blocked and unproven.

