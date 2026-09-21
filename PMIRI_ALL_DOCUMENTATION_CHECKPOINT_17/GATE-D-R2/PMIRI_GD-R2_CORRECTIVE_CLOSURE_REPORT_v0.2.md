# PMIRI — Gate D Round 2
# Corrective Closure Report v0.2

**Status:** `STRUCTURAL CORRECTION COMPLETE / INDEPENDENT RECHECK REQUIRED`
**Prior independent decision:** `FIX-FIRST`
**Implementation authorization:** `NOT GRANTED`
**Runtime authorization:** `NOT GRANTED`

## 1. Purpose

This report records the documentary corrections made in response to the
independent findings `IR-D2-01` through `IR-D2-07`. It does not replace a new
independent review and does not grant D2 acceptance.

The corrected candidate schemas use schema revision `0.2` in their `$id` and
`schema_version` fields while retaining the stable bundle filenames. The
schema identifiers and declared versions are authoritative.

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

`STRUCTURALLY_ADDRESSED` means that the contract and schema requirements are
present. It does not mean that an implementation enforces them.

## 3. Validation performed after correction

The following documentary checks passed:

```text
all D2 JSON files parse
schema IDs remain unique
closed operation/purpose definitions are present
34 adversarial scenarios remain present
17 required scenario classes remain covered
manifest candidate references remain resolvable after refresh
```

Cross-field rules that JSON Schema cannot express alone are centralized in
`PMIRI_GD-R2_CROSS_FIELD_VALIDATION_RULES_v0.2.md`. The relevant future
validator must resolve refs, recompute fingerprints and compare exact values;
it may not accept a displayed fingerprint as proof by itself.

## 4. Remaining not-proven items

- A new independent reviewer has not yet confirmed these corrections.
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

