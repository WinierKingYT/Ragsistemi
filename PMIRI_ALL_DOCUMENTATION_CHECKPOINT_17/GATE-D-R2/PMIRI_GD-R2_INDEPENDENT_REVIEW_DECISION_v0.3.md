# PMIRI Gate D Round 2 — Independent Review Decision v0.3

```yaml
review_id: PMIRI-GD-R2-INDEPENDENT-REVIEW-DECISION-003
reviewer_role: independent documentary reviewer
review_basis: current_frozen_bundle_only
review_started_at: "2026-09-11T19:43:56Z"
manifest: PMIRI_GD-R2_AUTHORITY_BUNDLE_MANIFEST_v0.1.json
candidate_correction_revision: "0.3"
manifest_fingerprint: 6ef51cfbbba57477a59f0b033f0a062c4e2681830b844fc297c3230cf982ed7f
candidate_member_count: 40
independence_status: INDEPENDENT
authoring_context_used_as_evidence: false
prior_decisions_used_as_evidence: false
prior_decisions_used_for_historical_reassessment: true
input_files_modified_during_review: false
implementation_authorization: NOT_GRANTED
runtime_authorization: NOT_GRANTED
```

## Independence and anti-anchoring record

This is a fresh review of the files present at the frozen current state. The
manifest, its canonical bytes, each candidate-member digest, the current D2
artifacts, and direct cross-document comparisons were treated as the evidence
base. Authoring assertions and prior summaries were not treated as evidence.
The prior independent decisions and closure reports were read only after the
current artifacts were examined, to map historical finding IDs to the current
state. No provider, connector, DNS, network, parser, ingestion, migration,
production, or runtime action was performed.

## Frozen manifest and hash evidence

- The declared manifest fingerprint is
  `6ef51cfbbba57477a59f0b033f0a062c4e2681830b844fc297c3230cf982ed7f`.
- Recomputed canonicalization followed the manifest's declared scope:
  remove `manifest_fingerprint`, serialize the remaining JSON object with
  sorted object keys, compact separators, UTF-8 encoding, declared array order,
  and no trailing newline. The canonical byte length was `13765`; the SHA-256
  was exactly
  `6ef51cfbbba57477a59f0b033f0a062c4e2681830b844fc297c3230cf982ed7f`.
- All `40/40` current candidate members were read and individually SHA-256
  verified. Mismatches: `0`.
- The accepted Gate-C source archive hash matched, and all `10/10` declared
  Gate-C archive members matched. The accepted D1 source archive hash matched,
  and all `14/14` declared D1 archive members matched.
- The manifest's declared authority scope is therefore integrity-consistent at
  the file/archive/member level. This does not establish semantic correctness
  of the candidate contract.

## Review coverage and mechanical checks

Inspected the complete current candidate set: all D2 contracts and schemas for
D2-01 through D2-07; the three current matrices; the integrated decision model;
the candidate index; the independent hard-recheck protocol and reports; the
cross-field validation rules v0.3; corrective closure v0.3; commission v0.3;
and prior independent decisions v0.1 and v0.2.

The following current-state checks passed:

- All 15 current D2 schemas parse as JSON.
- The 15 current D2 schema IDs are unique, and the schema revisions are
  consistently `0.2` where schema revision is defined; the vocabulary schema
  consistently declares vocabulary version `0.2`.
- All `108/108` local filename-plus-JSON-Pointer references resolve under the
  bundle's explicit filename/path lookup. No missing local file or pointer was
  found.
- No duplicate JSON object keys were found. The cleaned outbound lifecycle
  fields are present once; redaction `constraint_refs` at artifact and item
  scope are distinct nested fields, not duplicate same-level fields.
- The adversarial matrix contains `34` scenarios: `17` positive and `17`
  adversarial. All have explicit blocked reasons, `fixture_id: null`, exact
  top-level expected fields, and no textual alternative outcome.
- Canonical operation, purpose, action, state, lifecycle, reason, and
  obligation vocabularies are closed in the vocabulary schema and current
  cross-field rules. The residual open values identified below are
  dimension-specific evidence payloads, not canonical action/state enums.

The local path check is not equivalent to standards-complete JSON Schema
resolution. The custom `pmiri://` schema IDs and relative filename references
still require a declared resource registry or equivalent base-URI rule; see
IR-D2-21.

## Reassessment of IR-D2-01 through IR-D2-15

| Finding | Current status | Independent reassessment |
|---|---|---|
| IR-D2-01 | STRUCTURALLY_ADDRESSED | Gate-C/D1 lineage references and fingerprints are required in the integrated model and bound to the manifest; no runtime proof. |
| IR-D2-02 | STRUCTURALLY_ADDRESSED | Integrated downstream fingerprints, operation, purpose, validity, and epoch fields are present; exact record resolution remains subject to IR-D2-17 and IR-D2-21. |
| IR-D2-03 | STRUCTURALLY_ADDRESSED | Redaction, typed constraints, egress artifact fields, and artifact/item constraint scopes are structurally present; no transformation execution was performed. |
| IR-D2-04 | STRUCTURALLY_ADDRESSED | Constrained egress lineage and obligation fields are present with closed impact vocabulary; cross-record equality remains documentary. |
| IR-D2-05 | STRUCTURALLY_ADDRESSED | Operation and purpose are closed and carried through current records; the profile identity defect is separately reported as IR-D2-16. |
| IR-D2-06 | STRUCTURALLY_ADDRESSED | Capability and policy epochs, fingerprints, freshness fields, and invalidation fields are present; the freshness hash contradiction remains open. |
| IR-D2-07 | STRUCTURALLY_ADDRESSED | Current connection/outbound schemas and v0.3 cross-rules state selected target, TLS, destination, and epoch bindings; residual network defects are IR-D2-18 and IR-D2-19. |
| IR-D2-08 | STRUCTURALLY_ADDRESSED | Trust/capability/integrated schemas and v0.3 rules contain explicit state-to-action prohibitions and an intersection rule; enforcement is not proven. |
| IR-D2-09 | STRUCTURALLY_ADDRESSED | Outbound decisions now require content-bearing lifecycle reference/fingerprint and forbid them for provider calls; the final-envelope binding gap is IR-D2-17. |
| IR-D2-10 | STRUCTURALLY_ADDRESSED | Lifecycle schema plus v0.3 rules define start, terminal, sequence, continuity, event, and no-post-terminal constraints; no lifecycle validator or replay was run. |
| IR-D2-11 | STRUCTURALLY_ADDRESSED | Nested operation/purpose references, closed vocabulary, operation-scope membership, and field-name alignment are present; equality enforcement remains documentary. |
| IR-D2-12 | FIX_REQUIRED | The required freshness profile ID is present, but its declared fingerprint does not hash to the declared canonical payload. See IR-D2-16. |
| IR-D2-13 | FIX_REQUIRED | The intended exact selected-target/TLS/destination equality is stated, but mixed-address fail-closed behavior and exact canonicalization/epoch formulas remain unresolved. See IR-D2-18 and IR-D2-19. |
| IR-D2-14 | FIX_REQUIRED | Expected outcomes are structured and alternatives are prohibited, but evidence-state objects have no closed expected-outcome schema or complete vocabulary binding. See IR-D2-20. |
| IR-D2-15 | STRUCTURALLY_ADDRESSED | Current IDs/revisions are consistent and duplicate JSON fields are absent; standards URI resolution remains a separate deterministic-loader issue in IR-D2-21. |

`STRUCTURALLY_ADDRESSED` means that the documentary contract now states the
constraint and/or supplies a structural representation. It does not mean that
future implementation enforcement has been demonstrated.

## Current independent findings

### IR-D2-16 — Freshness profile fingerprint contradicts its canonical payload

- **Severity:** BLOCKER
- **Status:** OPEN
- **Area:** freshness-profile identity and fingerprint
- **Evidence:** `PMIRI_GD-R2-07_PROVIDER_POLICY_AUTHORITY_MATRIX.json` declares
  ID `D2-POLICY-FRESHNESS-001` and fingerprint
  `cb842b8fec2c8b9278c48833de0c6f6396e27125312c74f7686e485e743d6154` at
  `/freshness_profile_id`, `/freshness_profile_fingerprint`, and `/dimensions`.
  The contract's canonicalization claim is at §4, lines 78–85. The v0.3
  cross-field rule repeats the same exact-hash claim at §11, lines 295–305.
  Recomputing SHA-256 over compact UTF-8 JSON of
  `{freshness_profile_id,dimensions}` produced
  `604dd146196571cf7dd5d25eec7d8db066cebbeca07814ccfe647c9edd267d41` with
  sorted keys and
  `4c1a154779df420df722176c8b7118f62dc5ea81476969a0c191d5b1c15e02a3` with
  declared object insertion order. Neither equals the declared value.
- **Impact:** The required exact identity cannot be verified. Provider-policy
  observations and every derived or cached decision that carries this profile
  can be rejected as mismatched, or different validators can bind different
  payloads under the same profile identity. This directly prevents a
  deterministic freshness decision.
- **Required action:** Recompute the profile fingerprint from one explicitly
  specified canonical payload, correct the matrix and all dependent contract
  declarations, refresh the manifest member digest, and add a documentary
  self-check that recomputes the value before any future decision review.
- **Runtime boundary:** No provider policy was queried; no cache, epoch, or
  freshness evaluator was executed. This finding authorizes no implementation
  or runtime activity.

### IR-D2-17 — Integrated external envelope lacks an exact typed network/lifecycle binding

- **Severity:** BLOCKER
- **Status:** OPEN
- **Area:** external emission chain and content-bearing lifecycle identity
- **Evidence:** The integrated schema requires only opaque
  `network_binding_fingerprint` and `constrained_artifact_fingerprint` fields
  for `emission_mode: EXTERNAL` (`PMIRI_GD-R2-05_INTEGRATED_DECISION_ENVELOPE.schema.json`,
  lines 31–35 and 48–58). It does not define a typed reference to the exact
  outbound network decision, connection binding, or fetched-content lifecycle.
  The integrated contract at lines 68–84 requires referenced-record equality,
  but does not define how the generic network fingerprint resolves to a record
  type. The v0.3 rules bind the outbound decision's lifecycle at lines 236–244,
  while the integrated envelope itself carries neither a lifecycle reference nor
  lifecycle fingerprint.
- **Impact:** A final external envelope can contain a generic network hash while
  leaving the exact content-bearing outbound/lifecycle record and its
  operation/purpose/epoch chain implicit. The outbound rule may be correct in
  isolation, yet the final emission record is not deterministically bound to
  that proof. This leaves an emission-relevant ambiguity at the last contract
  boundary.
- **Required action:** Add exact typed references and fingerprints for the
  outbound decision and, where applicable, its connection and fetched-content
  lifecycle, or define an immutable typed record-resolution rule for the
  existing fields. Require the integrated validator to compare the resolved
  records' operation, purpose, destination, lifecycle, fingerprints, and epochs
  before external emission.
- **Runtime boundary:** No external emission, network decision, lifecycle
  resolution, or record lookup was performed.

### IR-D2-18 — Mixed DNS answer policy is contradictory and not fail-closed

- **Severity:** BLOCKER
- **Status:** OPEN
- **Area:** selected target, address-set policy, and SSRF boundary
- **Evidence:** The network contract states that every returned address must be
  checked and that one denied address among multiple answers is not safe merely
  because another answer is public (`PMIRI_GD-R2-04_EXTERNAL_FETCH_SSRF_NETWORK_BOUNDARY_CONTRACT_v0.1.md`,
  lines 50–65). The connection schema permits `resolved_addresses` entries
  with `DENIED_PRIVATE`, `DENIED_RESERVED`, or `DENIED_UNALLOWLISTED` policy
  statuses while separately permitting a selected public entry
  (`PMIRI_GD-R2-04_CONNECTION_BINDING.schema.json`, lines 15–62). The v0.3
  selected-target rules require only that the selected entry be public and that
  selected fields equal that entry (`PMIRI_GD-R2_CROSS_FIELD_VALIDATION_RULES_v0.3.md`,
  lines 188–197); they do not require the whole returned set to pass or encode a
  set-level denial.
- **Impact:** A record containing a denied answer and a public selected answer
  can satisfy the current structural and cross-field selected-target rules,
  despite the prose contract requiring denial. The matrix's exact SSRF outcome
  cannot therefore be enforced consistently from the current contract.
- **Required action:** Specify one exact set-level rule: either every returned
  address must be allowlisted public before any selection is eligible, or the
  connection record must carry a typed denial state that makes all allow actions
  impossible. Bind the matrix expected outcome to that rule.
- **Runtime boundary:** No DNS lookup, address parser, socket, connection, or
  network request was performed.

### IR-D2-19 — Network canonicalization and epoch equality are not exact enough

- **Severity:** HIGH
- **Status:** OPEN
- **Area:** network identity normalization and continuous revalidation
- **Evidence:** The network contract requires one pinned URL parser and
  normalized authority (`PMIRI_GD-R2-04_EXTERNAL_FETCH_SSRF_NETWORK_BOUNDARY_CONTRACT_v0.1.md`,
  lines 30–48), but does not identify the parser/version or fully specify IDNA,
  Unicode, default-port, IPv6 textual, authority, and SNI canonicalization.
  The v0.3 rules require normalized-authority comparison “after pinned
  canonicalization” and say the final revalidation event/epoch must be
  “consistent with the current binding” (`PMIRI_GD-R2_CROSS_FIELD_VALIDATION_RULES_v0.3.md`,
  lines 204–234). They do not define exact equality formulas between the final
  event epochs and the connection/outbound epochs, nor event-specific epoch
  transitions for reuse, retry, redirect, authority, or policy-epoch changes.
- **Impact:** Two conforming documentary validators can normalize the same
  target differently or accept different epoch histories while reaching
  different external-allow results. The intended selected IP/family/TLS/epoch
  fence is stated but not fully deterministic.
- **Required action:** Name the pinned canonicalization algorithm and version,
  define all relevant URL/authority/address/SNI normalization rules, and define
  exact event result/state/epoch transition equations. Require the terminal
  connection and outbound epochs to equal the current validated binding values,
  with a new binding after each listed invalidation trigger.
- **Runtime boundary:** No parser, DNS, redirect, retry, connection reuse, TLS,
  or epoch race test was performed.

### IR-D2-20 — Matrix evidence states are structured but not closed or schema-typed

- **Severity:** MEDIUM
- **Status:** FIX_REQUIRED
- **Area:** exact adversarial-matrix expected outcomes
- **Evidence:** The matrix declares exact required fields and prohibits
  alternatives at `/expected_outcome_contract`, lines 1266–1280. The 34
  scenario objects do contain those fields. However, `/scenarios/*/expected/evidence_state`
  is an unconstrained object with scenario-specific keys and values such as
  `policy_status`, `citation_status`, `retrieval_status`, `network_status`,
  `race_status`, `cache_status`, and `teardown_status`. The canonical vocabulary
  schema defines closed trust, capability, obligation, action, lifecycle,
  operation, purpose, reason, hash, reference, and timestamp definitions, but no
  closed schema for these matrix evidence-state objects
  (`PMIRI_GD-R2-06_DECISION_VOCABULARY.schema.json`, lines 12–57).
- **Impact:** The expected outcome is syntactically structured but not a
  machine-comparable closed contract. A future checker can accept different
  evidence keys or values while still claiming the same exact scenario result.
- **Required action:** Publish a matrix expected-outcome schema or an explicit
  closed union for evidence-state dimensions and values, bind every scenario's
  expected object to it, and distinguish diagnostic annotations from
  acceptance-bearing fields.
- **Runtime boundary:** No fixture, replay, parser, or scenario execution was
  performed; all 34 fixtures remain blocked/documentary-only.

### IR-D2-21 — Local path resolution passes, but standards URI resolution is undeclared

- **Severity:** HIGH
- **Status:** OPEN
- **Area:** JSON Schema `$ref` resource identity
- **Evidence:** All `108/108` relative filename-plus-pointer references resolve
  when the bundle loader explicitly maps the filename to a local file. The
  schemas instead declare custom `pmiri://` `$id` values and use relative
  filename references such as the vocabulary reference in
  `PMIRI_GD-R2-05_INTEGRATED_DECISION_ENVELOPE.schema.json`, lines 3 and
  12–46. The independent hard-recheck protocol's local-resolution requirement
  does not declare a JSON Schema resource registry/base-URI mapping for those
  custom IDs.
- **Impact:** File existence is proven, but a standards-compliant resolver can
  resolve the same relative reference against the custom `pmiri://` base rather
  than the filesystem filename unless an undocumented registry is supplied.
  Validator behavior is therefore not deterministic across conforming tooling.
- **Required action:** Declare and test the resource registry/base-URI mapping
  for every schema, or use a consistent URI strategy whose relative references
  resolve by the standard rules. Re-run a standards-complete validator over all
  108 references and record the result.
- **Runtime boundary:** No implementation validator or runtime action was
  executed. This is a documentary resolver correction only.

### IR-D2-22 — Provider-policy observation values have no per-dimension type

- **Severity:** MEDIUM
- **Status:** FIX_REQUIRED
- **Area:** closed policy evidence vocabulary
- **Evidence:** `PMIRI_GD-R2-07_PROVIDER_POLICY_OBSERVATION.schema.json` leaves
  `/properties/observed_value` as `{}` (line 14), while the provider-policy
  contract defines ten independent dimensions and says one dimension's evidence
  cannot satisfy another (§3, lines 53–76). The matrix supplies age, authority,
  and action requirements but does not supply a per-dimension value schema.
- **Impact:** An observation can be structurally valid with an arbitrary value
  whose semantics are not comparable or closed for the selected dimension. The
  policy algorithm can therefore receive an emission-relevant value without a
  deterministic documentary interpretation.
- **Required action:** Define per-dimension schemas and closed value vocabularies
  (or an explicitly versioned tagged union) for `observed_value`, then bind the
  selected dimension to the corresponding value type and fingerprint it.
- **Runtime boundary:** No provider policy, observation, registry, or cache was
  queried or evaluated.

## Documentary disposition

The current revision materially closes the previously identified structural
areas for state/action mapping, outbound lifecycle fields, lifecycle continuity,
nested operation/purpose scope, selected-target/TLS equality statements, schema
revision consistency, and duplicate-field cleanup. Those are documentary
improvements, not runtime evidence. The current bundle still contains the
freshness identity contradiction and several emission-relevant ambiguities that
must be corrected and independently rechecked. No implementation or runtime
authorization is granted.

## Verdict

FIX-FIRST
