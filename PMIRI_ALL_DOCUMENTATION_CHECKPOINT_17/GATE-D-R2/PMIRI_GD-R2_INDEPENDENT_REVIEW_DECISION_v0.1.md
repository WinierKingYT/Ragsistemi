# PMIRI Gate D Round 2 — Independent Review Decision

```yaml
review_id: PMIRI-GD-R2-INDEPENDENT-REVIEW-DECISION-001
reviewer_role: independent documentary reviewer
reviewer_identity: GPT-5 Codex (OpenAI)
authoring_context_available: false
review_started_at: 2026-09-11T18:36:37Z
independence_status: INDEPENDENT
manifest_fingerprint: dfc4d3f21b0bfe85eb754b769dd09eeb4c607d1f98bf21b8aefb4b693a02109b
package_modified_during_review: false
decision: FIX-FIRST
acceptance_status: PENDING_AUTHORITY_DECISION
implementation_authorization: NOT_GRANTED
runtime_authorization: NOT_GRANTED
```

## Review boundary and anti-anchoring record

This is a documentary review only. No provider, connector, DNS, network,
ingestion, migration, production or runtime action was performed. The review
started with the brief, protocol, authority manifest, candidate index, closure
recheck, prior hard-review findings, every manifest-listed D2 member, and the
accepted Gate-C and D1 R1 authority inputs.

The manifest fingerprint was recomputed as
`SHA-256(canonical manifest with manifest_fingerprint omitted)` and matched the
declared value above. Every manifest-listed D2 member, the Gate-C archive and
its 10 listed members, and the D1 archive and its 14 listed members matched
their declared SHA-256 values. All local D2 JSON members parsed, all local
schema references resolved, and the adversarial matrix contained 17 required
classes with 34 scenarios, each carrying exact schema/matrix references and a
blocked runtime reason.

The preliminary decision and findings in this file were recorded before the
prior `PMIRI_GD-R2_INDEPENDENT_HARD_RECHECK_REPORT_v0.1.md` was read. That
report was read only afterward for comparison; it is not the source of the
findings below.

## Decision rationale

`FIX-FIRST` is required because the documentary package still permits
emission-relevant ambiguity. In particular, the schema layer does not require
the Gate-C authorization/semantic lineage needed by an external-bound
constrained artifact, permits the integrated final envelope to omit two
required downstream fingerprints, and leaves several fail-closed mappings as
non-enforced cross-field prose. This is not D2 acceptance and does not grant
implementation or runtime authorization.

## Evidence-based findings

| Finding | Severity | Status | Area | Impact | Required action | Runtime boundary |
|---|---|---|---|---|---|---|
| IR-D2-01 | BLOCKER | OPEN | Gate-C lineage and constrained egress | A valid constrained artifact can omit the accepted Gate-C `AuthorizationLineageRef`, source EvidenceSet/context-intent lineage, inherited epistemic ceiling and semantic-obligation binding. Its external-boundary authorization and non-widening proof are therefore not mechanically complete. | Add required exact refs/fingerprints, or an exact immutable parent binding, for the accepted Gate-C authorization lineage, source material/semantic obligations and inherited epistemic ceiling in the constrained-artifact contract and final emission path. | No producer validation, constrained compilation or ProviderSendFence replay was run. |
| IR-D2-02 | BLOCKER | OPEN | Integrated final emission bindings | D2-05 requires constrained-artifact and network resolution/allowlist fingerprints, but the integrated envelope schema makes both nullable and does not require them. The schema also does not bind the operation or an explicit invalidation epoch, although accepted D1 validity requires operation- and epoch-aware reuse. A final envelope can consequently validate without the exact redaction/network proof needed for emission. | Make the downstream fingerprints required and non-null for external emission; add exact operation and applicable policy/invalidation-epoch bindings, with a separately defined non-egress branch if null is genuinely permitted. | No final emission fence, cache replay or policy-epoch race was executed. |
| IR-D2-03 | BLOCKER | OPEN | Redaction semantic determinism | The egress-artifact schema permits `PRESERVED_WITH_CONSTRAINT` or `WEAKENED` without any `constraint_refs`, and permits `NOT_APPLICABLE` without its required typed reason. The transformation schema has no kind-dependent requirement for an output span or typed placeholder and carries no authority-manifest binding. These gaps permit a constraint-bearing result to be serialized without the visible constraint/provenance needed to determine whether external emission is allowed. | Encode the matrix’s conditional requirements in the schemas or in one exact normative validation contract: required constraint refs/visibility and reasons by impact, kind-specific output/placeholder requirements, and authority/policy binding for each transformation. | No redaction implementation, citation remap or obligation replay was run. |
| IR-D2-04 | BLOCKER | OPEN | Operation/purpose coverage and fail-closed default | Multiple schemas permit `operation=other` or `purpose=other`, while the provider-policy authority matrix has no required dimensions or default disposition for `other`. An operation can therefore avoid the minimum-authority, freshness and conflict checks that govern named external operations. | Remove the escape-hatch enum values or define an explicit default: unrecognized/other operations and purposes must be rejected or held before external disclosure, with a complete required-dimension mapping. | No operation routing, provider-policy evaluation or external disclosure was executed. |
| IR-D2-05 | HIGH | OPEN | Capability and policy invalidation binding | The capability decision schema permits an empty `observation_refs` array and binds only a free-form material-manifest reference, despite the contract requiring all required observations and exact material/profile binding. The provider-policy observation schema has no invalidation-epoch field, although the policy algorithm and cache rules rely on epoch changes. A `FRESH` or cached decision can therefore lack a mechanically verifiable evidence set or epoch invalidation basis. | Require at least one observation where applicable, bind the exact material/profile fingerprint, add the policy invalidation epoch to observations/decisions, and define the zero-observation behavior for every state. | No schema validation against producer records or cache/invalidation replay was run. |
| IR-D2-06 | HIGH | OPEN | DNS, connection and TLS cross-field safety | The connection-binding schema does not constrain `selected_target` to a member of `resolved_addresses` with `ALLOWLISTED_PUBLIC` status, does not conditionally require a proxy identity for `EXPLICIT_PROXY`, and permits `tls.identity_status=MISMATCHED` without a schema-level denial condition. The outbound decision also makes `content_lifecycle` optional although terminal lifecycle mappings are normative. These combinations can change whether a network action is emitted. | Add cross-field constraints and explicit terminal mappings: selected target must equal an approved resolved address; proxy mode must match its identity; mismatched TLS must deny/revalidate; and content lifecycle must be required when applicable, especially for abort/reject outcomes. | No DNS, proxy, TLS, redirect, socket or resource-limit test was run. |
| IR-D2-07 | HIGH | OPEN | Fetched-content lifecycle determinism | The lifecycle schema conditionally requires an admission predicate only for `ADMITTED_TYPED_DATA`; it does not require the validation/classification/instruction-prohibition evidence for quarantine or other admission states, and it does not validate legal state transitions or the relationship between admission state and retrieval visibility. The contract’s quarantine/control-influence boundary is consequently not fully machine-checkable. | Define the legal transition graph and state-dependent required fields, including the exact admission predicate and visibility for typed data and the permanent prohibition on canonical/control influence. | No attachment fetch, parser, quarantine or typed-data admission runtime was executed. |

## Structurally addressed but not runtime-proven

- The vocabulary separates trust state, capability state, obligation impact,
  action result, content lifecycle and reason class at the prose/matrix level.
- The manifest provides exact accepted Gate-C/D1 lineage hashes and D2 member
  hashes, and the 34-scenario matrix provides documentary coverage.
- Candidate status and `NOT_GRANTED` implementation/runtime boundaries remain
  explicit throughout the reviewed package.

These structural positives do not close the open findings or establish runtime
enforcement, provider truth, credential isolation, SSRF defense, Gate-C replay,
or D2 acceptance.

## Post-preliminary comparison

After the preliminary result above existed, the prior independent hard
recheck report was read for comparison. It records `DOCUMENTARY-READY` as a
provisional result and reports Pass B as structural and Pass D as documentary
(`PMIRI_GD-R2_INDEPENDENT_HARD_RECHECK_REPORT_v0.1.md §2–§3`). Those assertions
do not resolve the exact schema omissions identified independently:
`§5 Cross-round compatibility assertions` summarizes inherited lineage but
does not make the missing Gate-C bindings required in the D2 schemas, and
`§6 Not proven in this pass` confirms that no standards-complete validator or
runtime evidence was available. The comparison therefore does not change the
independent `FIX-FIRST` decision.

## Finding schema (applies to every finding above)

```yaml
finding_id: <stable finding identifier shown in the table>
severity: BLOCKER|HIGH|MEDIUM|LOW
status: OPEN|FIX_REQUIRED|STRUCTURALLY_ADDRESSED|NOT_PROVEN
area: <review area>
evidence_refs: [<exact file and section or JSON path>]
impact: <specific consequence>
required_action: <smallest documentary correction or proof needed>
runtime_boundary: <what remains untested>
```

### Exact evidence references

```yaml
- finding_id: IR-D2-01
  severity: BLOCKER
  status: OPEN
  area: Gate-C lineage and constrained egress
  evidence_refs:
    - PMIRI_GD-R2-03_EGRESS_CONSTRAINED_CONTEXT_ARTIFACT.schema.json#/required
    - PMIRI_GD-R2-03_EGRESS_CONSTRAINED_CONTEXT_ARTIFACT.schema.json#/properties
    - PMIRI_GD-R2-05_INTEGRATED_DECISION_ENVELOPE.schema.json#/required
    - PMIRI_v1.0_Gate_C_Accepted/02_AUTHORIZATION_LINEAGE_AND_EXTERNAL_EMISSION_FENCES.md §AuthorizationLineageRef
    - PMIRI_v1.0_Gate_C_Accepted/03_EGRESS_CONSTRAINED_CONTEXT_ARTIFACT.md §Type separation
  impact: External-bound derived material lacks a required, checkable inherited authorization and semantic ceiling.
  required_action: Add required immutable lineage, source semantic and epistemic-ceiling bindings.
  runtime_boundary: No constrained compiler or emission-fence replay.

- finding_id: IR-D2-02
  severity: BLOCKER
  status: OPEN
  area: Integrated final emission bindings
  evidence_refs:
    - PMIRI_GD-R2-05_INTEGRATED_DECISION_MODEL_AND_ADVERSARIAL_MATRIX_v0.1.md §2 Required cross-object bindings
    - PMIRI_GD-R2-05_INTEGRATED_DECISION_ENVELOPE.schema.json#/required
    - PMIRI_GD-R2-05_INTEGRATED_DECISION_ENVELOPE.schema.json#/properties/constrained_artifact_fingerprint
    - PMIRI_GD-R2-05_INTEGRATED_DECISION_ENVELOPE.schema.json#/properties/network_binding_fingerprint
    - PMIRI_v1.1.1_Gate_D_R1_Accepted/04_REQUEST_AUTHORIZATION_AND_SECURITY_DECISION_VALIDITY.md §SecurityDecisionValidity
  impact: A final envelope can lack exact downstream proof, operation binding or epoch binding.
  required_action: Require non-null downstream fingerprints and add operation/epoch bindings or an explicit non-egress schema branch.
  runtime_boundary: No emission-fence, cache or epoch-race execution.

- finding_id: IR-D2-03
  severity: BLOCKER
  status: OPEN
  area: Redaction semantic determinism
  evidence_refs:
    - PMIRI_GD-R2-03_EGRESS_CONSTRAINED_CONTEXT_ARTIFACT.schema.json#/properties/obligation_impacts
    - PMIRI_GD-R2-03_EGRESS_CONSTRAINED_CONTEXT_ARTIFACT.schema.json#/properties/constraint_refs
    - PMIRI_GD-R2-03_REDACTION_TRANSFORMATION.schema.json#/properties
    - PMIRI_GD-R2-03_OBLIGATION_TRANSFORMATION_DECISION_MATRIX.json#/rows
    - PMIRI_GD-R2-03_REDACTION_CONSTRAINED_EGRESS_CONTRACT_v0.1.md §5 Semantic-obligation impact
  impact: Constraint-bearing or transformed records can omit the evidence that determines their emission disposition.
  required_action: Add conditional schema/validation requirements for impacts, reasons, transformation outputs and authority binding.
  runtime_boundary: No redaction, citation or obligation replay.

- finding_id: IR-D2-04
  severity: BLOCKER
  status: OPEN
  area: Operation/purpose coverage and fail-closed default
  evidence_refs:
    - PMIRI_GD-R2-01_TRUST_ASSERTION.schema.json#/properties/purpose
    - PMIRI_GD-R2-04_OUTBOUND_NETWORK_DECISION.schema.json#/properties/operation
    - PMIRI_GD-R2-07_PROVIDER_POLICY_AUTHORITY_MATRIX.json#/dimensions
    - PMIRI_GD-R2-07_PROVIDER_POLICY_AUTHORITY_AND_FRESHNESS_CONTRACT_v0.1.md §5 Required decision algorithm
  impact: Unnamed operations/purposes have no required-policy coverage and can evade fail-closed checks.
  required_action: Remove escape hatches or define a default deny/review/revalidation mapping for them.
  runtime_boundary: No routing or policy-evaluator execution.

- finding_id: IR-D2-05
  severity: HIGH
  status: OPEN
  area: Capability and policy invalidation binding
  evidence_refs:
    - PMIRI_GD-R2-02_CAPABILITY_DECISION.schema.json#/properties/observation_refs
    - PMIRI_GD-R2-02_CAPABILITY_DECISION.schema.json#/properties/material_manifest_ref
    - PMIRI_GD-R2-02_CAPABILITY_FRESHNESS_INVALIDATION_CONTRACT_v0.1.md §5 Validity and cache rules
    - PMIRI_GD-R2-07_PROVIDER_POLICY_OBSERVATION.schema.json#/properties
    - PMIRI_GD-R2-07_PROVIDER_POLICY_AUTHORITY_AND_FRESHNESS_CONTRACT_v0.1.md §5 Required decision algorithm
  impact: Evidence completeness and policy-epoch invalidation are not mechanically bound.
  required_action: Require the evidence/material bindings and add an explicit policy invalidation epoch.
  runtime_boundary: No producer validation or cache replay.

- finding_id: IR-D2-06
  severity: HIGH
  status: OPEN
  area: DNS, connection and TLS cross-field safety
  evidence_refs:
    - PMIRI_GD-R2-04_CONNECTION_BINDING.schema.json#/properties/selected_target
    - PMIRI_GD-R2-04_CONNECTION_BINDING.schema.json#/properties/proxy
    - PMIRI_GD-R2-04_CONNECTION_BINDING.schema.json#/properties/tls
    - PMIRI_GD-R2-04_OUTBOUND_NETWORK_DECISION.schema.json#/properties/content_lifecycle
    - PMIRI_GD-R2-04_EXTERNAL_FETCH_SSRF_NETWORK_BOUNDARY_CONTRACT_v0.1.md §5 DNS rebinding and connection binding
    - PMIRI_GD-R2-04_EXTERNAL_FETCH_SSRF_NETWORK_BOUNDARY_CONTRACT_v0.1.md §7 Response and resource limits
  impact: A schema-valid record can fail to prove that the actual connection is the approved, authenticated target and terminal lifecycle.
  required_action: Add cross-field invariants and required terminal lifecycle/action mappings.
  runtime_boundary: No DNS, proxy, TLS, redirect, socket or limit test.

- finding_id: IR-D2-07
  severity: HIGH
  status: OPEN
  area: Fetched-content lifecycle determinism
  evidence_refs:
    - PMIRI_GD-R2-04_FETCHED_CONTENT_LIFECYCLE.schema.json#/required
    - PMIRI_GD-R2-04_FETCHED_CONTENT_LIFECYCLE.schema.json#/properties/admission_predicate
    - PMIRI_GD-R2-04_FETCHED_CONTENT_LIFECYCLE.schema.json#/properties/transitions
    - PMIRI_GD-R2-04_EXTERNAL_FETCH_SSRF_NETWORK_BOUNDARY_CONTRACT_v0.1.md §8 Attachment and fetched-content handling
    - PMIRI_v1.0_Gate_C_Accepted/03_EGRESS_CONSTRAINED_CONTEXT_ARTIFACT.md §No evidence resurrection
  impact: Quarantine/admission/visibility behavior is not fully checkable from the lifecycle record.
  required_action: Define legal transitions and state-dependent admission, provenance, visibility and control-influence constraints.
  runtime_boundary: No attachment fetch, parser, quarantine or typed-data admission.
```
