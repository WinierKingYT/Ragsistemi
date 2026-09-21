# PMIRI — Gate D Round 2 — Redaction and Constrained Egress Contract

**Version:** 0.2  
**Status:** `CANDIDATE / DESIGN-ONLY`  
**Gate:** D2  
**Implementation authorization:** `NOT GRANTED`

## 1. Mission

Define how PMIRI narrows an already admitted provider-neutral context for one
exact destination without retrieving, resurrecting or silently changing the
meaning of excluded evidence.

Redaction is a destination-specific derived operation. It does not change
canonical truth, source records, Gate-B semantics or the provider-neutral
`CompiledContextArtifact`.

## 2. Required artifact separation

The chain is:

```text
CompiledContextArtifact
        ↓ destination policy + D1/D2 decisions
EgressConstrainedContextArtifact
        ↓ destination binding and final emission fences
ProviderEnvelope
```

The constrained artifact MUST retain a reference to its source artifact and a
machine-readable material transformation manifest.

## 3. Constrained artifact contract

The normative record contract is
`PMIRI_GD-R2-03_EGRESS_CONSTRAINED_CONTEXT_ARTIFACT.schema.json` and each
transformation is governed by
`PMIRI_GD-R2-03_REDACTION_TRANSFORMATION.schema.json`.
Typed visible constraints are governed by
`PMIRI_GD-R2-03_TYPED_CONSTRAINT.schema.json`; the deterministic impact/action
mapping is maintained in
`PMIRI_GD-R2-03_OBLIGATION_TRANSFORMATION_DECISION_MATRIX.json`.

The corrected candidate schemas use schema revision `0.2` under their `$id`
and `schema_version` fields. The stable filenames remain the bundle paths;
the schema identifiers, not the filename suffix, are authoritative.

```yaml
egress_constrained_context_artifact:
  artifact_id: <stable id>
  source_compiled_artifact_ref: <provider-neutral artifact>
  authorization_lineage_ref: <accepted Gate-C AuthorizationLineageRef>
  authorization_lineage_fingerprint: <sha256>
  source_evidence_set_ref: <accepted Gate-C EvidenceSet>
  source_evidence_set_fingerprint: <sha256>
  context_intent_ref: <accepted Gate-C ContextIntent>
  context_intent_fingerprint: <sha256>
  inherited_epistemic_ceiling_ref: <accepted Gate-C epistemic ceiling>
  inherited_epistemic_ceiling_fingerprint: <sha256>
  semantic_obligations_ref: <accepted Gate-C semantic obligations>
  semantic_obligations_fingerprint: <sha256>
  operation: <provider_call|connector_fetch|attachment_fetch|external_fetch>
  purpose: <canonical purpose>
  destination_security_binding_ref: <exact destination binding>
  trust_decision_ref: <D2 trust decision>
  capability_decision_ref: <D2 capability decision>
  redaction_profile_ref: <profile>
  material_manifest_ref: <D1 EgressMaterialManifest>
  authority_manifest_fingerprint: <accepted authority bundle fingerprint>
  included_evidence_refs: [<refs>]
  excluded_evidence_refs: [<refs>]
  transformation_refs: [<redaction transformations>]
  obligation_impacts:
    - obligation_id: <stable obligation id>
      impact: PRESERVED|PRESERVED_WITH_CONSTRAINT|WEAKENED|UNSATISFIABLE|INVALIDATED|NOT_APPLICABLE
      required_action: ALLOW|ALLOW_WITH_CONSTRAINTS|DENY|REQUIRE_REVIEW|REQUIRE_REVALIDATION|LOCAL_ONLY
      constraint_visible: <true|false>
      reason_class: <canonical reason; NONE only for PRESERVED>
      constraint_refs: [<typed constraints; empty only when no constraint applies>]
  constraint_refs: [<all typed visible constraint refs>]
  citation_map_ref: <updated map>
  output_fingerprint: <sha256>
  validity_ref: <SecurityDecisionValidity>
```

No external provider call may use a constrained artifact whose source,
destination, policy, capability or material fingerprint does not match the
final `ProviderEnvelope`.

## 4. Allowed transformations

The policy may select only explicitly declared transformations:

```text
DROP_EVIDENCE
MASK_SPAN
GENERALIZE_VALUE
QUANTIZE_VALUE
REMOVE_METADATA
REPLACE_WITH_TYPED_PLACEHOLDER
REDACT_CITATION_TARGET
```

Every transformation must declare its input evidence/span, output span or
placeholder, reason class, policy version, exact material-manifest reference,
authority-manifest fingerprint and resulting fingerprint. `DROP_EVIDENCE` has
no output span or placeholder; every other transformation must provide exactly
one output span or typed placeholder, with the replacement kind requiring a
typed placeholder.

Undeclared summarization, paraphrase or model-generated rewriting is not a
redaction primitive. If used, it requires a separate typed derivation and
must not be presented as the original evidence.

## 5. Semantic-obligation impact

Redaction MUST evaluate its effect on every obligation carried by the source
artifact, including:

- conflict preservation;
- qualifier and uncertainty preservation;
- current-state completeness;
- historical meaning;
- citation traceability;
- source/version identity;
- authorization and classification lineage;
- safety-critical exclusions or warnings.

The impact vocabulary is:

```text
PRESERVED
PRESERVED_WITH_CONSTRAINT
WEAKENED
UNSATISFIABLE
INVALIDATED
NOT_APPLICABLE
```

Rules:

- `PRESERVED` may continue if all other D1/D2 checks pass;
- `PRESERVED_WITH_CONSTRAINT` requires the constraint to remain visible;
- `WEAKENED` requires an explicit constrained or review disposition; it must
  not be represented by an undefined `DEGRADED` action;
- `UNSATISFIABLE` or `INVALIDATED` requires recompile, replan or deny;
- `NOT_APPLICABLE` must include a typed reason, never silently omit the field.

Each array item MUST record `required_action` from the canonical action enum,
its typed `reason_class` and its item-level `constraint_refs`. Every
`PRESERVED_WITH_CONSTRAINT`, `WEAKENED`, `UNSATISFIABLE` or `INVALIDATED` item
MUST have at least one corresponding typed constraint in both the item-level
and artifact-level `constraint_refs`; the constraint must name its visible
disposition and updated citation map. `PRESERVED` requires `ALLOW`, reason
`NONE`, visible semantics and no constraints. `NOT_APPLICABLE` requires a
non-`NONE` typed reason and no constraints. The obligation impact is evidence
about semantic preservation; it is not itself a permission.

## 6. Conflict and qualifier rules

If one side of a conflict is excluded, the result cannot be formatted as an
ordinary complete answer unless the conflict obligation remains satisfied by
an explicit typed disposition.

If a qualifier, date, scope, uncertainty marker or exception is removed, the
compiler must either:

1. preserve the semantic obligation in the transformed output;
2. emit `ALLOW_WITH_CONSTRAINTS` or `REQUIRE_REVIEW` with a visible typed
   constraint; or
3. deny the external emission.

Budget pressure is not permission to silently remove the only qualifier or
the only conflicting evidence.

## 7. Citation and provenance rules

After a transformation:

- citations may point only to included or explicitly redacted spans;
- stale offsets cannot be reused after reorder/truncation/transformation;
- an excluded source cannot remain represented as if it were included;
- a placeholder cannot claim to be a verbatim source span;
- the constrained citation map must be fingerprinted with the output.

The provider receives only the constrained citation map and material that the
destination policy admits.

## 8. No hidden retrieval or resurrection

The constrained compiler MUST NOT:

- call retrieval to replace omitted evidence;
- inspect denied evidence to improve the provider output;
- use a provider wrapper to recover excluded content;
- interpret a locator, cache or continuation handle as permission;
- promote a redacted result to a complete result.

If the admitted material cannot satisfy the requested semantic obligations,
the artifact MUST record `UNSATISFIABLE` or `INVALIDATED` and the final
`action_result` MUST be `DENY` or `REQUIRE_REVIEW` according to the obligation
policy. `DEGRADED` and `UNSATISFIABLE` are not action-result enum values.

## 9. Exit criteria

D2-03 is design-complete only when all transformations have typed impacts,
citation/provenance remapping is explicit, and adversarial cases cover
conflict, qualifier, current-state, historical and budget-pressure failures.

This candidate does not declare D2 accepted.
