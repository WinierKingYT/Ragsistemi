# PMIRI — Gate D Round 2
# Cross-Field Validation Rules v0.5

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

The integrated envelope MUST carry typed
`outbound_network_decision_ref` and
`outbound_network_decision_fingerprint` values for `EXTERNAL` emission. The
resolved record MUST have record type `PMIRI_D2_OUTBOUND_NETWORK_DECISION`,
and its connection-binding reference/fingerprint must resolve to the same
network proof named by the envelope. For
`connector_fetch`, `attachment_fetch` and `external_fetch`, the envelope
must also carry non-null `fetched_content_lifecycle_ref` and
`fetched_content_lifecycle_fingerprint`; the resolved lifecycle must match
the outbound decision's operation, purpose, destination, origin,
`operation`, `purpose`, `admission_state`, `retrieval_visibility`, terminal
response fingerprint and applicable epochs. The lifecycle record's
`operation` and `purpose` MUST equal the outbound and integrated operation and
purpose. `fetched_content_origin_binding_ref` and
`fetched_content_destination_binding_ref` MUST equal the lifecycle's
`origin_binding_ref` and `destination_binding_ref`; the latter MUST equal the
integrated `destination_binding_ref`. `fetched_content_admission_state` and
`fetched_content_history_terminal_state` MUST equal the lifecycle's
`admission_state` and `history_terminal_state`; its retrieval visibility and
terminal response fingerprint MUST equal the lifecycle's
`retrieval_visibility` and `terminal_response_fingerprint`. The outbound and
integrated lifecycle reference and fingerprint MUST resolve to the same
record. The integrated `destination_binding_ref` and operation/purpose MUST
equal the outbound record's corresponding values. No external allow result is
valid without these exact equalities.
For `provider_call`, both lifecycle fields are explicitly null and
`content_lifecycle=NOT_APPLICABLE`. A generic network hash without these
typed equality checks is insufficient for external emission.

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
canonicalization_profile_id/fingerprint
  = exact profile ID/fingerprint from PMIRI_GD-R2-04_NETWORK_CANONICALIZATION_PROFILE.json
resolution_set_status=ALL_ALLOWLISTED_PUBLIC
  iff every resolved_addresses[*].policy_status=ALLOWLISTED_PUBLIC
resolution_set_status=DENIED_MIXED
  iff at least one resolved address has any DENIED_* status
selected_target.resolution_entry_ref
  → resolves to one entry in resolved_addresses
selected_target.ip/family/policy_status
  = resolved entry ip/family/policy_status
selected_target.policy_status
  = ALLOWLISTED_PUBLIC
```

`selected_target=null` is the typed `NO_APPROVED_SELECTION` branch. It is
legal only when `resolution_set_status=DENIED_MIXED` and
`binding_status` is `DENIED` or `STALE`; it is the required representation
when every returned address is denied. A non-null selected target still must
resolve to a returned `ALLOWLISTED_PUBLIC` entry.

`DENIED_MIXED` is a typed denial state. It permits a diagnostic selected
public address to remain recorded, but it makes every outbound allow action
invalid. A connection with `binding_status=VALIDATED` MUST have
`resolution_set_status=ALL_ALLOWLISTED_PUBLIC`; a connection with
`DENIED_MIXED` MUST have `binding_status=DENIED` or `STALE`. The outbound
decision copies `resolution_set_status` and cannot use `ALLOW` or
`ALLOW_WITH_CONSTRAINTS` for `DENIED_MIXED`.

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
  = connection.normalized_authority after
    D2-NETWORK-CANONICALIZATION-001 / version 1.0
outbound.tls_identity_fingerprint
  = connection.tls.identity_binding_fingerprint
outbound.connection_binding_status = resolved binding.binding_status
outbound.final_revalidation_event_sequence
  = resolved binding.revalidation_events[-1].sequence
outbound.final_revalidation_result
  = resolved binding.revalidation_events[-1].result
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

Every outbound `ALLOW` or `ALLOW_WITH_CONSTRAINTS` result MUST also carry
`connection_binding_status=VALIDATED` and
`final_revalidation_result=MATCHED`. Its
`final_revalidation_event_sequence` MUST identify the last revalidation event
of the resolved binding, whose connection and invalidation epochs MUST equal
the outbound epochs. Any `DENIED` or `STALE` binding, missing final match or
epoch mismatch is fail-closed, regardless of copied selected-target fields.

The canonicalization profile is normative: input HTTPS is accepted and output
scheme is serialized as `HTTPS`; only port 443
is accepted and an explicit 443 is omitted; DNS names use IDNA2008 UTS46
non-transitional 15.1 A-labels, lowercase and no trailing dot; IPv6 uses
RFC5952 lowercase compressed form and brackets in authority; fragments,
userinfo, malformed percent encodings and encoded delimiters are rejected;
SNI is the lowercase A-label DNS host. The profile file is the authoritative
implementation input and its fingerprint must match the binding.
Destination identity covers only serialized scheme and authority. The exact
request path/query is a separate binding: empty path becomes `/`, RFC3986
dot-segments are removed, unreserved characters are decoded, reserved
semantics are preserved, percent-encoding hex is uppercase, query parameter
order is preserved, an absent query remains absent and path/query are not
silently folded into authority identity. The request-target fingerprint and
the actual connector request must use this same profile.

Connection revalidation events must have unique contiguous `sequence` values
starting at zero, nondecreasing timestamps and exact epoch equations:

```text
event[0].event_type = INITIAL_RESOLUTION
event[0].prior_connection_epoch = event[0].connection_epoch
event[0].prior_invalidation_epoch = event[0].invalidation_epoch

REDIRECT | RETRY | CONNECTION_REUSE | AUTHORITY_CHANGE:
  current connection_epoch = prior_connection_epoch + 1
  current invalidation_epoch = prior_invalidation_epoch

POLICY_EPOCH_CHANGE:
  current connection_epoch = prior_connection_epoch
  current invalidation_epoch = prior_invalidation_epoch + 1

binding.connection_epoch = last event.connection_epoch
binding.invalidation_epoch = last event.invalidation_epoch
outbound.connection_epoch = binding.connection_epoch
outbound.invalidation_epoch = binding.invalidation_epoch
```

The initial event must be `MATCHED` for a validated binding. Every trigger
event requires a fresh resolution/TLS/policy comparison before its `MATCHED`
result can be used; `MISMATCHED` or `DENIED` makes the binding non-validated
and disallows both allow actions. The first event's epoch is the explicit
current baseline for that connection binding; a future implementation must
persist it rather than infer it from wall-clock time.

The network decision always requires `content_lifecycle`. For
`operation=provider_call`, it is `NOT_APPLICABLE` and no fetched-content
lifecycle reference is allowed. For `connector_fetch`, `attachment_fetch`
and `external_fetch`, both `fetched_content_lifecycle_ref` and
`fetched_content_lifecycle_fingerprint` are required. The resolved lifecycle
record's operation, purpose, `admission_state`, `retrieval_visibility`,
`origin_binding_ref`, `destination_binding_ref`, `history_terminal_state` and
`terminal_response_fingerprint` must equal the explicit projection fields
used by the outbound decision. `terminal_response_fingerprint` MUST equal
`response_fingerprint` in the lifecycle record. A missing, mismatched or
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
  = 604dd146196571cf7dd5d25eec7d8db066cebbeca07814ccfe647c9edd267d41
```

Every provider-policy observation and every derived or cached D2 decision
that depends on policy freshness MUST carry and exactly match both fields.
This includes trust, capability, outbound network and integrated decisions.
The fields are included in the relevant decision fingerprint. A missing or
mismatched profile identity maps to `INTERNAL_CONTRACT_INVALID` and cannot
authorize external disclosure.

## 12. Matrix expected-outcome and policy-value rules

Every scenario's `expected` object MUST validate against
`PMIRI_GD-R2-05_EXPECTED_OUTCOME.schema.json` and carry the exact
`expected_schema_ref` value. The tagged `evidence_state` union is closed;
diagnostic trigger annotations cannot change the acceptance-bearing action,
lifecycle, reason or required bindings. Alternatives such as `A or B` are
not valid expected outcomes. `fixture_id=null` and `runtime_status=BLOCKED`
remain explicit documentary constraints, not a test pass.

Every provider-policy observation's `observed_value` MUST validate against
the tagged union in
`PMIRI_GD-R2-07_PROVIDER_POLICY_OBSERVATION.schema.json`. Its `value_type`
MUST equal the enclosing `policy_dimension` exactly. An untyped `{}` value,
an unknown tagged type or a value schema from another dimension is
`INTERNAL_CONTRACT_INVALID` and cannot authorize external disclosure.

## 13. Schema URI resource resolution

`PMIRI_GD-R2_SCHEMA_RESOURCE_REGISTRY_v0.1.json` is normative for schema
loading. All D2 schema `$ref` values MUST be absolute PMIRI URIs; relative
filename references are prohibited. The loader MUST map each URI before the
fragment to exactly one bundled file, verify that the file `$id` equals the
mapped URI, then resolve the JSON Pointer fragment. A local filename scan
alone is not standards-complete URI resolution. Registry verification is a
structural check and does not prove runtime enforcement.

## 14. Runtime boundary

These rules are documentary constraints. They do not prove that a future
implementation enforces them. Provider calls, connector calls, external
fetches, DNS tests, parser execution, race tests and Gate-C replay remain
blocked and unproven.
