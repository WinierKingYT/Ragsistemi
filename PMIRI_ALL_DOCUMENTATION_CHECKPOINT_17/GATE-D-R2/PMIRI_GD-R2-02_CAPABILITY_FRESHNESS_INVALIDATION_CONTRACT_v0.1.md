# PMIRI — Gate D Round 2 — Capability Freshness and Invalidation Contract

**Version:** 0.3  
**Status:** `CANDIDATE / DESIGN-ONLY`  
**Gate:** D2  
**Implementation authorization:** `NOT GRANTED`

## 1. Mission

Define how PMIRI obtains, scopes, expires, invalidates and fails closed on
provider, model, connector and endpoint capability facts.

Capability facts are security-relevant policy inputs. They are not permanent
properties inferred from a provider name or model family.

## 2. Capability observation

Every usable capability fact MUST be represented as an observation. The
machine-readable record contract is
`PMIRI_GD-R2-02_CAPABILITY_OBSERVATION.schema.json`; the YAML below is
explanatory and MUST remain isomorphic to that schema:

```yaml
capability_observation_id: <stable id>
subject_binding: <exact destination/model/feature/endpoint>
capability_contract_version: 0.1
capability_key: attachment_input|structured_output|provider_model_feature|retention_deletion|training_use|subprocessors|processing_region|credential_operation_scope|redirect_fetch_behavior|destination_identity|resource_limits
observed_value: <closed tagged value whose value_type exactly equals capability_key>
scope:
  purpose: retrieval|context_delivery|external_fetch|attachment_import|provider_call
  material_classes: [<classes>]
  region: <region or explicit unknown>
  feature_profile: <profile or explicit unknown>
source_authority: <trusted authority>
evidence_refs: [<evidence refs>]
observed_at: <UTC timestamp>
valid_from: <UTC timestamp>
valid_until: <UTC timestamp>
invalidation_epoch: <epoch>
observation_fingerprint: <sha256>
status: ACTIVE|EXPIRED|REVOKED|SUPERSEDED|CONTRADICTED|INVALID
```

A capability observation without exact subject binding is not fit for a
destination decision.

The capability observation schema is a closed, versioned key/value union. The
`capability_contract_version` is `0.1`; unknown keys, unknown `value_type`
tags, untyped JSON values and key/tag mismatches are invalid. The canonical
typed `observed_value`, including its `value_type` tag and all value fields,
is part of `observation_fingerprint`; a fingerprint over only the key is not
an observation of the claimed capability.

## 3. Capability dimensions

D2 MUST support separate observations for at least:

- structured output support and schema behavior;
- attachment/input type and size limits;
- provider/model feature availability;
- retention and deletion behavior;
- training/use policy;
- subprocessor and processing-region facts;
- connector authentication and operation capability;
- redirect/fetch behavior where the connector is involved;
- destination identity and endpoint binding;
- declared rate/resource limits when they affect safe egress.

One positive capability cannot imply another. “Supports JSON” does not prove
“does not retain submitted material”.

## 4. Freshness states

These are `capability_state` values, not final permissions. The exact enum and
the separate `action_result` enum are defined by
`PMIRI_GD-R2-06_DECISION_VOCABULARY.schema.json`.

The capability evaluator returns:

```text
FRESH
STALE
MISSING
REVOKED
CONTRADICTED
INVALID
OUT_OF_SCOPE
```

Freshness is evaluated against the requested purpose, destination, material
class, policy version and current time. A globally fresh observation may still
be `OUT_OF_SCOPE` for the requested feature or material class.

## 5. Validity and cache rules

The observation record is serialized by
`PMIRI_GD-R2-02_CAPABILITY_OBSERVATION.schema.json`; the derived decision is
serialized by `PMIRI_GD-R2-02_CAPABILITY_DECISION.schema.json`. The decision
MUST also bind the exact `authority_manifest_fingerprint` used to resolve its
observations.

Capability observations and decisions MUST bind to the exact freshness profile
used by the evaluator:

```text
freshness_profile_id
freshness_profile_fingerprint
```

The profile fingerprint covers the immutable age boundaries and revalidation
triggers. A decision or cache record with a missing or mismatched profile
identity is invalid and cannot authorize external disclosure.

Capability decisions MUST bind to:

```text
exact subject identity
exact purpose
exact material/profile fingerprint
capability observation set
policy version
invalidation epoch
freshness profile ID and fingerprint
validity interval
```

The corrected capability-observation schema revision is `0.3`; the
capability-decision schema remains `0.2` and requires both
`material_manifest_fingerprint` and `capability_profile_fingerprint` in
addition to the reference field `material_manifest_ref`. A decision for any
state other than `MISSING` must contain at least one observation reference.
`MISSING` is the only state that may have an empty observation set; it must use
`reason_class=CAPABILITY_MISSING` and cannot produce `ALLOW`.

A cached capability decision cannot be reused when any of these changes:

- destination/model/feature identity;
- security classification or derived sensitivity;
- provider policy or trust registry version;
- capability invalidation epoch;
- freshness profile ID and fingerprint;
- material or constrained-profile fingerprint;
- purpose or requested operation;
- freshness window.

Cache keys are not authorization. Cache hits must still pass current validity
and revocation checks.

## 6. Invalidation sources

An observation is invalidated by any of:

- explicit registry revocation;
- source authority withdrawal;
- provider policy change;
- model or feature replacement;
- endpoint or destination identity change;
- subprocessor change affecting the asserted policy;
- expired validity interval;
- contradictory authoritative observation;
- material-class or purpose scope change;
- detected destination or certificate mismatch;
- inability to prove the current policy version.

Provider-policy observations also carry the integer `invalidation_epoch`.
The evaluator MUST compare that value with the current policy epoch before
using an observation. An epoch mismatch makes the observation stale or
invalidated and prevents external permission.

Invalidation is monotonic for the affected decision epoch. A later positive
observation must create a new observation and a new decision; it must not
silently mutate historical evidence.

## 7. Fail-closed behavior

For external disclosure, the state-to-action mapping is exhaustive:

```text
capability_state=FRESH + all required dimensions present
                                              → evaluate egress
capability_state=STALE/MISSING/REVOKED/CONTRADICTED/INVALID/OUT_OF_SCOPE
                                              → action_result=DENY,
                                                REQUIRE_REVIEW,
                                                REQUIRE_REVALIDATION or LOCAL_ONLY
```

`ALLOW` and `ALLOW_WITH_CONSTRAINTS` are prohibited for every state in the
second row. `OUT_OF_SCOPE` is not repaired by silently widening the scope; a
new exact evaluation is required. The same mapping is enforced in the
capability-decision schema and the integrated envelope.

`INDETERMINATE` is not a successful capability state. If a caller-visible
result is necessary, it must state that the external destination cannot be
validated and must not emit the protected material.

The derived decision MUST use
`PMIRI_GD-R2-02_CAPABILITY_DECISION.schema.json` and emit the separate fields
`capability_state`, `action_result` and `reason_class`. A freshness state must
never be serialized as an action result.

## 8. Capability substitution protection

The following substitutions require a fresh evaluation:

- provider A → provider B;
- model A → model B;
- feature disabled → feature enabled;
- endpoint host A → endpoint host B;
- attachment profile A → profile B;
- structured-output profile A → profile B;
- declared retention/training policy A → policy B.

An earlier `DestinationBindingProof` cannot authorize a substituted
destination or feature.

## 9. Exit criteria

D2-02 is design-complete only when the observation and decision schemas,
observation scope, freshness, invalidation, cache binding, contradiction
handling and fail-closed behavior are all covered by positive and adversarial
cases.

This candidate does not declare D2 accepted.
