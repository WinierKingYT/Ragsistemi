# PMIRI — Gate D Round 2
# Corrective Closure Report v0.5

**Status:** `STRUCTURAL CORRECTION COMPLETE / INDEPENDENT RECHECK REQUIRED`
**Prior independent decisions:** `FIX-FIRST` (v0.1, v0.2, v0.3 and v0.4)
**Implementation authorization:** `NOT GRANTED`
**Runtime authorization:** `NOT GRANTED`

## 1. Purpose

This report records the documentary corrections made in response to the
independent findings `IR-D2-01` through `IR-D2-30`. It does not replace a new
independent review and does not grant D2 acceptance.

The corrected candidate schemas use schema revision `0.2` or `0.3` in their
`$id` and `schema_version` fields while retaining the stable bundle filenames.
The schema identifiers and declared versions are authoritative. This
correction revision is `0.5`; prior closure reports and the v0.4 independent
decision remain historical evidence.

## 2. Closure disposition

| Finding | Severity | Current disposition | Documentary correction |
|---|---|---|---|
| IR-D2-01 | BLOCKER | `STRUCTURALLY_ADDRESSED` | Egress and integrated records now require exact Gate-C lineage, EvidenceSet, ContextIntent, epistemic-ceiling and semantic-obligation refs/fingerprints. |
| IR-D2-02 | BLOCKER | `STRUCTURALLY_ADDRESSED` | Integrated envelope now binds operation, purpose, invalidation epoch and emission mode; external mode requires non-null constrained-artifact and network fingerprints; local-only is an explicit non-egress branch. |
| IR-D2-03 | BLOCKER | `STRUCTURALLY_ADDRESSED` | Obligation impacts now require typed reasons and item constraints; impact/action/visibility combinations are conditional; transformations bind material and authority and enforce output/placeholder rules. |
| IR-D2-04 | BLOCKER | `STRUCTURALLY_ADDRESSED` | Operation and purpose vocabularies are closed; `other` escape hatches were removed from affected schemas and unknown values are an internal contract error. |
| IR-D2-05 | HIGH | `STRUCTURALLY_ADDRESSED` | Capability decisions now bind material/profile fingerprints, require observations except for explicit `MISSING`, and policy observations require invalidation epochs. |
| IR-D2-06 | HIGH | `STRUCTURALLY_ADDRESSED` | Connection records now bind a selected resolution entry and allowlisted-public status; proxy/TLS/terminal lifecycle conditions are explicit; cross-record equality rules are normative. |
| IR-D2-07 | HIGH | `STRUCTURALLY_ADDRESSED` | Fetched-content lifecycle now requires state-specific admission evidence, typed-data proof, visibility mapping and an explicit legal transition graph. |
| IR-D2-08 | BLOCKER | `STRUCTURALLY_ADDRESSED` | Trust, capability and integrated schemas now enforce the exhaustive state-to-action matrix; disallowed evidence states cannot pair with either allow action, and conditional trust cannot produce unrestricted `ALLOW`. |
| IR-D2-09 | BLOCKER | `STRUCTURALLY_ADDRESSED` | Content-bearing outbound operations now require an exact fetched-content lifecycle reference and fingerprint; cross-field rules compare state, visibility, origin, destination and lifecycle fingerprint. |
| IR-D2-10 | BLOCKER | `STRUCTURALLY_ADDRESSED` | Lifecycle records now declare start/terminal states and sequenced transitions; the cross-field validator requires continuous ordered history and terminal-state/event equality. |
| IR-D2-11 | HIGH | `STRUCTURALLY_ADDRESSED` | Capability prose now matches `subject_binding`; nested capability purpose and lifecycle explicit operation use the canonical closed vocabulary and exact enclosing-operation equality is normative. |
| IR-D2-12 | HIGH | `STRUCTURALLY_ADDRESSED` | Policy observations and all derived/cached D2 decisions now carry the exact freshness-profile ID and fingerprint. |
| IR-D2-13 | BLOCKER | `STRUCTURALLY_ADDRESSED` | Connection and outbound records now carry destination identity, selected IP/family, TLS identity fingerprint and epochs; exact target/TLS/authority/revalidation equalities are normative. |
| IR-D2-14 | MEDIUM | `STRUCTURALLY_ADDRESSED` | Every matrix scenario now has one exact structured expected outcome with explicit operation, purpose, evidence state, lifecycle, reason, bindings and blocked runtime status; alternatives are prohibited. |
| IR-D2-15 | LOW | `STRUCTURALLY_ADDRESSED` | Remaining schema identifiers are aligned to revision 0.2 and the duplicate artifact-level redaction `constraint_refs` declaration is removed. |
| IR-D2-16 | BLOCKER | `STRUCTURALLY_ADDRESSED` | The freshness profile fingerprint is recomputed from the explicitly sorted canonical payload, corrected in the authority matrix and pinned by a self-check document. |
| IR-D2-17 | BLOCKER | `STRUCTURALLY_ADDRESSED` | The integrated envelope now requires typed outbound-network decision refs/fingerprints and content-bearing lifecycle refs/fingerprints, with provider-call null lifecycle conditions. |
| IR-D2-18 | BLOCKER | `STRUCTURALLY_ADDRESSED` | Connection and outbound records now carry typed resolution-set status; `DENIED_MIXED` is fail-closed and a validated binding requires every returned address to be allowlisted public. |
| IR-D2-19 | HIGH | `STRUCTURALLY_ADDRESSED` | The versioned network canonicalization profile defines host, port, IPv6, SNI and rejection rules; exact revalidation epoch equations bind event history to connection and outbound records. |
| IR-D2-20 | `MEDIUM` | `STRUCTURALLY_ADDRESSED` | A closed expected-outcome schema and per-scenario schema reference now type the matrix evidence-state union, action, lifecycle, reason and binding names. |
| IR-D2-21 | HIGH | `STRUCTURALLY_ADDRESSED` | All root D2 schema refs are absolute PMIRI URIs and a normative URI resource registry maps each schema ID to one bundled file with verification requirements. |
| IR-D2-22 | `MEDIUM` | `STRUCTURALLY_ADDRESSED` | Provider-policy observations now use a per-dimension tagged value union and the enclosing dimension/tag equality is normative. |
| IR-D2-23 | `BLOCKER` | `STRUCTURALLY_ADDRESSED` | Same-resource expected-outcome and provider-policy `$ref` fragments are now absolute PMIRI URIs rooted at their owning schema; registry IDs were advanced to schema revision 0.3. |
| IR-D2-24 | `BLOCKER` | `STRUCTURALLY_ADDRESSED` | `expected_schema_ref` is now required by the expected-outcome schema, and all 34 matrix outcomes are rechecked against that closure. |
| IR-D2-25 | `BLOCKER` | `STRUCTURALLY_ADDRESSED` | Lifecycle records now carry operation, purpose and terminal response fingerprint; outbound/integrated records carry explicit origin, destination, admission, visibility, terminal-state and terminal-response projections with exact equality rules. |
| IR-D2-26 | `BLOCKER` | `STRUCTURALLY_ADDRESSED` | Outbound decisions now copy binding status and final revalidation sequence/result; allow actions require `VALIDATED`, `MATCHED`, all-public resolution and matching epochs. |
| IR-D2-27 | `BLOCKER` | `STRUCTURALLY_ADDRESSED` | All-denied DNS results use the typed `selected_target=null` / `NO_APPROVED_SELECTION` branch and the adversarial matrix binds the explicit `denied_resolution_set`. |
| IR-D2-28 | `HIGH` | `STRUCTURALLY_ADDRESSED` | The network profile now pins output scheme, RFC3986 path normalization, empty-path, percent-encoding, query ordering and the separate exact request-target binding; the profile fingerprint is refreshed. |
| IR-D2-29 | `MEDIUM` | `STRUCTURALLY_ADDRESSED` | Capability observations now use a closed versioned key/value union with exact key/tag compatibility and a typed value fingerprint requirement. |
| IR-D2-30 | `LOW` | `STRUCTURALLY_ADDRESSED` | Trust decisions now fix `content_lifecycle=NOT_APPLICABLE` in the schema and current contract. |

`STRUCTURALLY_ADDRESSED` means that the contract and schema requirements are
present. It does not mean that an implementation enforces them.

## 3. Validation performed after correction

The following documentary checks passed:

```text
all D2 JSON files parse
schema IDs remain unique
closed operation/purpose definitions are present
34 adversarial scenarios remain present with exact structured expected outcomes
expected outcomes validate against a closed schema and bind per-scenario schema refs
all D2 schema refs use the declared absolute PMIRI URI resource registry
freshness profile self-check recomputes the declared fingerprint
17 required scenario classes remain covered
manifest candidate references remain resolvable after refresh
```

Cross-field rules that JSON Schema cannot express alone are centralized in
`PMIRI_GD-R2_CROSS_FIELD_VALIDATION_RULES_v0.5.md`. The relevant future
validator must resolve refs, recompute fingerprints and compare exact values;
it may not accept a displayed fingerprint as proof by itself.

## 4. Remaining not-proven items

- A new independent reviewer has not yet confirmed this correction revision.
- A standards-complete JSON Schema validator is not available in this current
  documentary environment.
- No provider, connector, network, DNS, TLS, parser, credential, teardown or
  race execution has occurred.
- Gate-C executable replay remains unclosed: R-FC is still 0/17, preflight is
  still BLOCKED and runtime isolation attestation is still unverified.
- No production implementation, ingestion, migration or external emission is
  authorized.

## 5. Required next step

Run a new independent hard recheck against the corrected candidate bundle.
The reviewer must recompute the new manifest fingerprint, verify all updated
member hashes, inspect the corrected schemas and cross-field rules, and return:

```text
D2 ACCEPTED — DOCUMENTARY CONTRACT ONLY
FIX-FIRST
RETHINK
```

Any remaining emission-relevant ambiguity returns the package to `FIX-FIRST`.
