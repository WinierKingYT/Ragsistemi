# PMIRI Gate D Round 2 — Independent Review Decision v0.2

```yaml
review_id: PMIRI-GD-R2-INDEPENDENT-REVIEW-DECISION-002
reviewer_role: independent documentary reviewer
reviewer_identity: GPT-5 Codex (OpenAI), separate review execution
authoring_context_available: false
review_started_at: 2026-09-11T19:08:17Z
independence_status: INDEPENDENT
manifest_fingerprint: b6fc4015d16d8d463376566a4e4eec7060c34fa2f01dfc9e7677f08e9bb23cda
package_modified_during_review: false
decision: FIX-FIRST
acceptance_status: PENDING_AUTHORITY_DECISION
implementation_authorization: NOT_GRANTED
runtime_authorization: NOT_GRANTED
```

## Review boundary and identity verification

This is a documentary review only. No provider, connector, DNS, network,
parser, ingestion, migration, production or runtime action was performed. The
D2 candidate package was not modified.

The manifest fingerprint was recomputed as SHA-256 over the canonical JSON
manifest with `manifest_fingerprint` omitted, using the manifest-declared
sorting, compact-separator, UTF-8 and no-trailing-newline rules. The result
matches the declared current value above.

The Gate-C archive hash and all 10 manifest-bound Gate-C member hashes match.
The D1 archive hash and all 14 manifest-bound D1 member hashes match. The
manifest-bound literal extraction paths are absent, but the exact members are
resolvable through the declared archive/materialized roots and match byte for
byte. All 36 manifest-listed D2 candidate members match their declared hashes;
there is no unlisted root-level D2 candidate member. All D2 JSON files parse,
all local `$ref` targets resolve, schema IDs and record-type constants are
unique, and the matrix contains 17 required classes with 34 scenarios (17
positive and 17 adversarial), each with exact schema/matrix references and a
blocked runtime reason.

## Anti-anchoring record

Before reading the prior decision, fresh-pass report or corrective-closure
report, I independently reviewed the manifest, candidate index, accepted
Gate-C/D1 members, every D2 contract/schema/matrix member, the seven prior
finding topics and the cross-field rules. My preliminary verdict was
`FIX-FIRST`. The preliminary blockers were the missing exact binding from an
outbound decision to a fetched-content lifecycle record, the absence of
continuous lifecycle/current-state validation, and unresolved network
target/TLS/epoch equality rules. The prior reports were read only afterward
for comparison and did not replace that evidence trail.

## Decision rationale

`FIX-FIRST` remains required. The correction revision materially addresses the
seven prior decision findings at the stated structural level, but the current
schemas and cross-field contract still leave emission-relevant ambiguity:

- a content-bearing outbound decision has no exact lifecycle-record reference;
- the lifecycle graph validates individual edges but not a continuous history
  whose terminal state equals the record's current state;
- selected outbound resolution, canonical IP/TLS identity and revalidation
  epoch relationships are incomplete;
- stale/unknown/revoked evidence is not exhaustively prohibited from pairing
  with an allow action by one shared conditional rule.

These are documentary blockers, not runtime findings. This decision does not
call the package accepted, runtime verified, production-ready or authorized.

## Reassessment of prior decision findings IR-D2-01..07

```yaml
- finding_id: IR-D2-01
  severity: BLOCKER
  status: STRUCTURALLY_ADDRESSED
  area: Gate-C lineage and constrained egress
  evidence_refs:
    - PMIRI_GD-R2-03_EGRESS_CONSTRAINED_CONTEXT_ARTIFACT.schema.json#/required
    - PMIRI_GD-R2-03_EGRESS_CONSTRAINED_CONTEXT_ARTIFACT.schema.json#/properties/authorization_lineage_ref
    - PMIRI_GD-R2-03_EGRESS_CONSTRAINED_CONTEXT_ARTIFACT.schema.json#/properties/semantic_obligations_ref
    - PMIRI_GD-R2_CROSS_FIELD_VALIDATION_RULES_v0.2.md §2-§3
    - PMIRI_ALL_DOCUMENTATION_CHECKPOINT_15/ARCHIVE_SOURCES/PMIRI_v1.0_Gate_C_Accepted.zip::PMIRI_v1.0_Gate_C_Accepted/02_AUTHORIZATION_LINEAGE_AND_EXTERNAL_EMISSION_FENCES.md §AuthorizationLineageRef
  impact: The corrected artifact and integrated envelope require the Gate-C lineage, source-evidence, context-intent, epistemic-ceiling and semantic-obligation refs/fingerprints at the documentary contract level.
  required_action: No further closure action for the prior finding; retain exact ref resolution and fingerprint recomputation as a validator obligation.
  runtime_boundary: No lineage-record resolver, constrained compiler or ProviderSendFence replay was run.

- finding_id: IR-D2-02
  severity: BLOCKER
  status: STRUCTURALLY_ADDRESSED
  area: Integrated final emission bindings
  evidence_refs:
    - PMIRI_GD-R2-05_INTEGRATED_DECISION_ENVELOPE.schema.json#/required
    - PMIRI_GD-R2-05_INTEGRATED_DECISION_ENVELOPE.schema.json#/allOf
    - PMIRI_GD-R2_CROSS_FIELD_VALIDATION_RULES_v0.2.md §4
    - PMIRI_ALL_DOCUMENTATION_CHECKPOINT_15/ARCHIVE_SOURCES/PMIRI_v1.0_Gate_C_Accepted.zip::PMIRI_v1.0_Gate_C_Accepted/01_GATE_C_CROSS_ROUND_COMPATIBILITY_CONTRACT.md §Cross-round invariants
  impact: External envelopes now conditionally require non-null constrained-artifact and network fingerprints, while operation, purpose, invalidation epoch and emission mode are required; local-only is explicitly non-egress.
  required_action: Retain the conditional external/local separation and add the residual lifecycle and state/action bindings recorded below.
  runtime_boundary: No emission-fence, cache or epoch-race execution was run.

- finding_id: IR-D2-03
  severity: BLOCKER
  status: STRUCTURALLY_ADDRESSED
  area: Redaction semantic determinism
  evidence_refs:
    - PMIRI_GD-R2-03_EGRESS_CONSTRAINED_CONTEXT_ARTIFACT.schema.json#/properties/obligation_impacts
    - PMIRI_GD-R2-03_EGRESS_CONSTRAINED_CONTEXT_ARTIFACT.schema.json#/properties/constraint_refs
    - PMIRI_GD-R2-03_REDACTION_TRANSFORMATION.schema.json#/allOf
    - PMIRI_GD-R2-03_OBLIGATION_TRANSFORMATION_DECISION_MATRIX.json#/rows
    - PMIRI_GD-R2_CROSS_FIELD_VALIDATION_RULES_v0.2.md §5
  impact: Impact/action/visibility conditions, typed constraint references and transformation output rules now exist at the schema and cross-field contract level.
  required_action: Retain these conditions and correct the duplicate documentary `constraint_refs` declaration noted in IR-D2-15.
  runtime_boundary: No redaction, citation remap or obligation replay was run.

- finding_id: IR-D2-04
  severity: BLOCKER
  status: STRUCTURALLY_ADDRESSED
  area: Operation/purpose coverage and fail-closed default
  evidence_refs:
    - PMIRI_GD-R2-06_DECISION_VOCABULARY.schema.json#/$defs/operation
    - PMIRI_GD-R2-06_DECISION_VOCABULARY.schema.json#/$defs/purpose
    - PMIRI_GD-R2-04_OUTBOUND_NETWORK_DECISION.schema.json#/properties/operation
    - PMIRI_GD-R2-07_PROVIDER_POLICY_AUTHORITY_MATRIX.json#/dimensions
    - PMIRI_GD-R2_CROSS_FIELD_VALIDATION_RULES_v0.2.md §6
  impact: The primary operation and purpose fields are closed-world and unknown values map to `INTERNAL_CONTRACT_INVALID`; no `other` escape hatch remains in those fields.
  required_action: Extend the same closed-world rule to nested operation/purpose-bearing fields identified in IR-D2-11.
  runtime_boundary: No operation routing or provider-policy evaluator was executed.

- finding_id: IR-D2-05
  severity: HIGH
  status: STRUCTURALLY_ADDRESSED
  area: Capability and policy invalidation binding
  evidence_refs:
    - PMIRI_GD-R2-02_CAPABILITY_DECISION.schema.json#/required
    - PMIRI_GD-R2-02_CAPABILITY_DECISION.schema.json#/allOf
    - PMIRI_GD-R2-07_PROVIDER_POLICY_OBSERVATION.schema.json#/required
    - PMIRI_GD-R2-07_PROVIDER_POLICY_OBSERVATION.schema.json#/properties/invalidation_epoch
    - PMIRI_GD-R2_CROSS_FIELD_VALIDATION_RULES_v0.2.md §7
  impact: Capability decisions now require material/profile fingerprints and observations except for the explicit `MISSING` case; provider-policy observations carry a non-negative invalidation epoch.
  required_action: Retain these bindings and add an exact freshness-profile identity as required by IR-D2-12.
  runtime_boundary: No producer validation, cache replay or invalidation test was run.

- finding_id: IR-D2-06
  severity: HIGH
  status: STRUCTURALLY_ADDRESSED
  area: DNS, connection and TLS cross-field safety
  evidence_refs:
    - PMIRI_GD-R2-04_CONNECTION_BINDING.schema.json#/properties/selected_target
    - PMIRI_GD-R2-04_CONNECTION_BINDING.schema.json#/allOf
    - PMIRI_GD-R2-04_OUTBOUND_NETWORK_DECISION.schema.json#/allOf
    - PMIRI_GD-R2_CROSS_FIELD_VALIDATION_RULES_v0.2.md §8
  impact: The corrected package adds selected-resolution equality, proxy-mode conditions, allowlisted-public status and TLS-match requirements at the documentary level.
  required_action: Retain those rules and close the residual selected-target, IP, TLS-identity and revalidation-epoch gaps in IR-D2-13.
  runtime_boundary: No DNS, proxy, TLS, redirect, socket or resource-limit test was run.

- finding_id: IR-D2-07
  severity: HIGH
  status: STRUCTURALLY_ADDRESSED
  area: Fetched-content lifecycle determinism
  evidence_refs:
    - PMIRI_GD-R2-04_FETCHED_CONTENT_LIFECYCLE.schema.json#/allOf
    - PMIRI_GD-R2-04_FETCHED_CONTENT_LIFECYCLE.schema.json#/properties/transitions
    - PMIRI_GD-R2_CROSS_FIELD_VALIDATION_RULES_v0.2.md §9
    - PMIRI_ALL_DOCUMENTATION_CHECKPOINT_15/ARCHIVE_SOURCES/PMIRI_v1.0_Gate_C_Accepted.zip::PMIRI_v1.0_Gate_C_Accepted/03_EGRESS_CONSTRAINED_CONTEXT_ARTIFACT.md §No evidence resurrection
  impact: State-dependent admission predicates, visibility values and the seven allowed edge types now exist, but graph continuity and exact network-record linkage remain open in IR-D2-09 and IR-D2-10.
  required_action: Retain the state-specific conditions and add continuous-history/current-state validation.
  runtime_boundary: No attachment fetch, parser, quarantine or typed-data admission runtime was executed.
```

## New independent findings

```yaml
- finding_id: IR-D2-08
  severity: BLOCKER
  status: OPEN
  area: Evidence-state to action-result fail-closed mapping
  evidence_refs:
    - PMIRI_GD-R2-01_TRUST_DECISION.schema.json#/properties/trust_state
    - PMIRI_GD-R2-01_TRUST_DECISION.schema.json#/properties/action_result
    - PMIRI_GD-R2-01_TRUST_DECISION.schema.json#/allOf
    - PMIRI_GD-R2-02_CAPABILITY_DECISION.schema.json#/properties/capability_state
    - PMIRI_GD-R2-02_CAPABILITY_DECISION.schema.json#/properties/action_result
    - PMIRI_GD-R2-02_CAPABILITY_DECISION.schema.json#/allOf
    - PMIRI_GD-R2-05_INTEGRATED_DECISION_ENVELOPE.schema.json#/properties/trust_state
    - PMIRI_GD-R2-05_INTEGRATED_DECISION_ENVELOPE.schema.json#/properties/capability_state
    - PMIRI_GD-R2-05_INTEGRATED_DECISION_ENVELOPE.schema.json#/allOf
    - PMIRI_GD-R2_CROSS_FIELD_VALIDATION_RULES_v0.2.md §6-§7
    - PMIRI_GD-R2-01_PROVIDER_CONNECTOR_TRUST_REGISTRY_CONTRACT_v0.1.md §4 and §9
    - PMIRI_GD-R2-02_CAPABILITY_FRESHNESS_INVALIDATION_CONTRACT_v0.1.md §7
  impact: The shared enums are separated, but the decision schemas and integrated envelope do not conditionally prohibit every allow action for `UNKNOWN`, `EXPIRED`, `STALE`, `REVOKED`, `CONTRADICTED`, `INVALID` or `OUT_OF_SCOPE` evidence. The prose mapping is not an exhaustive, single cross-field equality rule, so a state/action combination can change emission eligibility.
  required_action: Add an exhaustive state-to-action matrix to the cross-field contract and enforce it in each decision/envelope schema or in one explicitly normative validator contract; prohibit `ALLOW` and `ALLOW_WITH_CONSTRAINTS` wherever the applicable state/action mapping forbids them.
  runtime_boundary: No state/action producer validation, emission-fence evaluation or provider disclosure was run.

- finding_id: IR-D2-09
  severity: BLOCKER
  status: OPEN
  area: Outbound decision to fetched-content lifecycle binding
  evidence_refs:
    - PMIRI_GD-R2-04_OUTBOUND_NETWORK_DECISION.schema.json#/required
    - PMIRI_GD-R2-04_OUTBOUND_NETWORK_DECISION.schema.json#/properties/content_lifecycle
    - PMIRI_GD-R2-04_OUTBOUND_NETWORK_DECISION.schema.json#/allOf
    - PMIRI_GD-R2-04_FETCHED_CONTENT_LIFECYCLE.schema.json#/$id
    - PMIRI_GD-R2_CROSS_FIELD_VALIDATION_RULES_v0.2.md §8
    - PMIRI_GD-R2-04_EXTERNAL_FETCH_SSRF_NETWORK_BOUNDARY_CONTRACT_v0.1.md §8-§9
  impact: A content-bearing `connector_fetch`, `attachment_fetch` or `external_fetch` decision carries only a lifecycle enum; it has no exact lifecycle-record reference. The schema only forces `NOT_APPLICABLE` for `provider_call`, and the cross-field rule cannot resolve an unreferenced lifecycle record or its visibility/admission evidence.
  required_action: Add a required fetched-content lifecycle reference for content-bearing operations, require non-`NOT_APPLICABLE` state where applicable, and compare the resolved lifecycle state, visibility, origin/destination and terminal fingerprint with the network decision.
  runtime_boundary: No fetch, content admission, visibility enforcement or network decision execution was run.

- finding_id: IR-D2-10
  severity: BLOCKER
  status: OPEN
  area: Lifecycle graph continuity and terminal-state binding
  evidence_refs:
    - PMIRI_GD-R2-04_FETCHED_CONTENT_LIFECYCLE.schema.json#/properties/admission_state
    - PMIRI_GD-R2-04_FETCHED_CONTENT_LIFECYCLE.schema.json#/properties/transitions
    - PMIRI_GD-R2-04_FETCHED_CONTENT_LIFECYCLE.schema.json#/properties/transitions/items/oneOf
    - PMIRI_GD-R2-04_FETCHED_CONTENT_LIFECYCLE.schema.json#/allOf
    - PMIRI_GD-R2_CROSS_FIELD_VALIDATION_RULES_v0.2.md §9
  impact: The schema validates each transition as one of seven legal edge shapes but does not require the array to start at the initial state, remain contiguous, be time-ordered, or end at the record's `admission_state`. A record can therefore carry a legal edge set whose history disagrees with its current state and visibility.
  required_action: Require a continuous ordered path from `NOT_APPLICABLE` through the current state, bind the final `to_state` to `admission_state`, reject impossible duplicate/reversal histories, and define terminal-event requirements and epoch/fingerprint linkage.
  runtime_boundary: No lifecycle transition validator, parser or quarantine runtime was run.

- finding_id: IR-D2-11
  severity: HIGH
  status: FIX_REQUIRED
  area: Nested operation/purpose vocabulary and capability-record isomorphism
  evidence_refs:
    - PMIRI_GD-R2-02_CAPABILITY_FRESHNESS_INVALIDATION_CONTRACT_v0.1.md §2 Capability observation
    - PMIRI_GD-R2-02_CAPABILITY_OBSERVATION.schema.json#/required
    - PMIRI_GD-R2-02_CAPABILITY_OBSERVATION.schema.json#/properties/scope/properties/purpose
    - PMIRI_GD-R2-04_FETCHED_CONTENT_LIFECYCLE.schema.json#/properties/admission_predicate/properties/explicit_operation_ref
    - PMIRI_GD-R2-06_DECISION_VOCABULARY.schema.json#/$defs/operation
    - PMIRI_GD-R2-06_DECISION_VOCABULARY.schema.json#/$defs/purpose
  impact: The capability prose names `subject_binding_ref`, while the schema requires `subject_binding`; the capability scope purpose and lifecycle admission operation are free-form strings rather than closed vocabulary refs. A producer following the prose can fail schema validation, while a structurally valid nested value can evade the primary closed-world operation/purpose checks.
  required_action: Make the prose and schema field names identical, bind nested purpose/operation fields to the canonical enums, and require exact resolution/equality to the enclosing decision values.
  runtime_boundary: No producer serialization, schema validation or operation-routing execution was run.

- finding_id: IR-D2-12
  severity: HIGH
  status: FIX_REQUIRED
  area: Policy freshness-profile identity and epoch determinism
  evidence_refs:
    - PMIRI_GD-R2-07_PROVIDER_POLICY_AUTHORITY_AND_FRESHNESS_CONTRACT_v0.1.md §4 Freshness profile
    - PMIRI_GD-R2-07_PROVIDER_POLICY_AUTHORITY_AND_FRESHNESS_CONTRACT_v0.1.md §7 Historical and cache rules
    - PMIRI_GD-R2-07_PROVIDER_POLICY_AUTHORITY_MATRIX.json#/freshness_profile_id
    - PMIRI_GD-R2-07_PROVIDER_POLICY_OBSERVATION.schema.json#/required
    - PMIRI_GD-R2-07_PROVIDER_POLICY_OBSERVATION.schema.json#/properties
    - PMIRI_GD-R2-05_INTEGRATED_DECISION_ENVELOPE.schema.json#/required
  impact: The matrix identifies `D2-POLICY-FRESHNESS-001`, and the cache contract requires freshness-profile binding, but observations and the integrated envelope bind only policy version and invalidation epoch. Two profiles with different age boundaries are not distinguished by the required decision fields.
  required_action: Add the exact freshness-profile ID and fingerprint (or an immutable equivalent) to policy observations and every derived/cached decision, and include it in the decision fingerprint and equality checks.
  runtime_boundary: No policy-age, cache or epoch-change evaluation was run.

- finding_id: IR-D2-13
  severity: BLOCKER
  status: OPEN
  area: Selected network target, TLS identity and connection-epoch equality
  evidence_refs:
    - PMIRI_GD-R2-04_CONNECTION_BINDING.schema.json#/properties/normalized_authority
    - PMIRI_GD-R2-04_CONNECTION_BINDING.schema.json#/properties/resolved_addresses/items/properties/ip
    - PMIRI_GD-R2-04_CONNECTION_BINDING.schema.json#/properties/selected_target
    - PMIRI_GD-R2-04_CONNECTION_BINDING.schema.json#/properties/tls
    - PMIRI_GD-R2-04_CONNECTION_BINDING.schema.json#/properties/revalidation_events
    - PMIRI_GD-R2-04_OUTBOUND_NETWORK_DECISION.schema.json#/properties/selected_target_resolution_ref
    - PMIRI_GD-R2-04_OUTBOUND_NETWORK_DECISION.schema.json#/properties/connection_epoch
    - PMIRI_GD-R2_CROSS_FIELD_VALIDATION_RULES_v0.2.md §8
    - PMIRI_GD-R2-04_EXTERNAL_FETCH_SSRF_NETWORK_BOUNDARY_CONTRACT_v0.1.md §5 and §9
  impact: The cross-field rules bind the selected target within a connection record, but do not state that the outbound decision's selected-resolution reference equals that connection record's selected reference. IP values and normalized authority/SNI are unconstrained strings, and revalidation-event epochs/ordering are not tied to the binding epoch. TLS `MATCHED` is required for allow but the evidence establishing SNI/authority/certificate identity is not deterministically compared.
  required_action: Require canonical IP/address-family validation; equate the outbound selected reference to the connection binding selection; bind normalized authority, destination identity, TLS SNI and certificate identity; and require ordered revalidation events to match the current connection and network-policy epochs, including reuse/redirect/authority-change invalidation.
  runtime_boundary: No DNS resolution, proxy, TLS handshake, connection reuse, redirect or socket test was run.

- finding_id: IR-D2-14
  severity: MEDIUM
  status: FIX_REQUIRED
  area: Adversarial expected-output typing
  evidence_refs:
    - PMIRI_GD-R2-05_ADVERSARIAL_SCENARIO_MATRIX.json#/scenarios
    - PMIRI_GD-R2-05_ADVERSARIAL_SCENARIO_MATRIX.json#/scenarios/0/expected
    - PMIRI_GD-R2-05_ADVERSARIAL_SCENARIO_MATRIX.json#/scenarios/0/fixture_id
    - PMIRI_GD-R2-05_ADVERSARIAL_SCENARIO_MATRIX.json#/blocked_reason_default
    - PMIRI_GD-R2_INDEPENDENT_HARD_RECHECK_PROTOCOL_v0.1.md §Pass E
  impact: Coverage is structurally present, but all 34 `fixture_id` values are null and the `expected` values are free-form strings with alternatives such as `ALLOW or ALLOW_WITH_CONSTRAINTS`; they are not typed expected records that a validator can compare field-by-field.
  required_action: Add a structured expected object per scenario containing exact enum-valued action, evidence state, lifecycle, reason and required bindings, while retaining the explicit blocked runtime reason.
  runtime_boundary: No positive or adversarial fixture replay was authorized or run.

- finding_id: IR-D2-15
  severity: LOW
  status: FIX_REQUIRED
  area: Correction-revision traceability
  evidence_refs:
    - PMIRI_GD-R2_CORRECTIVE_CLOSURE_REPORT_v0.2.md §1
    - PMIRI_GD-R2-01_TRUST_DECISION.schema.json#/properties/schema_version
    - PMIRI_GD-R2-02_CAPABILITY_OBSERVATION.schema.json#/properties/schema_version
    - PMIRI_GD-R2-03_TYPED_CONSTRAINT.schema.json#/properties/schema_version
    - PMIRI_GD-R2-04_RESOURCE_LIMITS_PROFILE.schema.json#/properties/schema_version
    - PMIRI_GD-R2-03_REDACTION_CONSTRAINED_EGRESS_CONTRACT_v0.1.md §3
  impact: The closure report says corrected candidate schemas use revision `0.2`, but four manifest-listed schemas still declare `0.1`; the redaction contract's illustrative YAML also repeats artifact-level `constraint_refs`. This creates avoidable ambiguity about which schema revision and field occurrence a validator must use.
  required_action: Enumerate the authoritative revision of every schema explicitly and remove the duplicate illustrative field so the correction report, contracts and schemas are mutually consistent.
  runtime_boundary: No schema-version negotiation or validator implementation was run.
```

## Post-comparison conclusion

The prior fresh-pass report's provisional `DOCUMENTARY-READY` result and the
corrective-closure report's `STRUCTURALLY_ADDRESSED` labels were considered
after the independent preliminary assessment. They correctly describe several
structural additions, but they do not resolve the exact omissions above. The
package therefore remains `FIX-FIRST` and `acceptance_status` remains
`PENDING_AUTHORITY_DECISION`.

No conclusion is made that D2 is accepted, production-ready, runtime-enforced,
provider-trust-verified, credential-isolation-verified, network/SSRF-defended,
or Gate-C runtime-passed. Implementation, ingestion, migration, provider,
connector and network authorization remain `NOT_GRANTED`.
