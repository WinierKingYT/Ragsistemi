# PMIRI — Gate D Round 2 — Independent Hard Recheck Protocol

**Version:** 0.1  
**Status:** `READY FOR INDEPENDENT REVIEW`  
**Gate:** D2  
**Implementation authorization:** `NOT GRANTED`

## 1. Purpose

This protocol defines the next authorized documentary task: an independent
review of the D2 candidate after blocker and HIGH/MEDIUM structural fixes. The
reviewer must be separate from the author/operator who produced the candidate
fixes and must not edit the package while reviewing it.

The protocol can produce `FIX-FIRST` or `DOCUMENTARY-READY`; it cannot itself
grant D2 acceptance, runtime permission, provider permission or network
permission.

## 2. Immutable review inputs

The reviewer MUST start from:

1. `PMIRI_GD-R2_AUTHORITY_BUNDLE_MANIFEST_v0.1.json`
2. `PMIRI_GD-R2_CANDIDATE_INDEX_v0.1.md`
3. `PMIRI_GD-R2_BLOCKER_CLOSURE_RECHECK_REPORT_v0.1.md`
4. `PMIRI_GD-R2_HARD_CONTRACT_REVIEW_FINDINGS_v0.1.json`
5. every D2 member listed by the authority manifest;
6. the exact accepted Gate-C and D1 R1 archive/member hashes listed by that
   manifest.

The reviewer MUST record the manifest fingerprint and verify all candidate
member hashes before interpreting content.

## 3. Review passes

### Pass A — Identity and lineage

- Recompute the authority manifest fingerprint with its own fingerprint field
  omitted.
- Verify every Gate-C and D1 R1 source archive/member hash.
- Verify every D2 candidate member hash and ensure no local candidate file is
  unlisted.
- Confirm D2 consumes rather than rewrites Gate-C/D1 authority.

### Pass B — Schema and serialization

- Parse every JSON file.
- Check every `$ref` resolves to an exact local file or declared schema scope.
- Check schema IDs and record-type constants are unique and versioned.
- Confirm all fingerprint-bearing records follow the shared canonical
  serialization rule.
- Confirm decision records bind the authority-manifest fingerprint.

### Pass C — Vocabulary and fail-closed behavior

- Confirm trust state, capability state, obligation impact, action result,
  content lifecycle and reason class are non-overlapping.
- Search all normative D2 text and matrices for state values incorrectly used
  as `action_result` values.
- Check every missing, stale, revoked, contradictory, mismatched and
  unproven condition maps to a canonical action and reason.

### Pass D — Cross-round compatibility

- Compare D2 outputs with accepted Gate-C egress/emission-fence contracts.
- Compare subject, purpose, classification, destination and validity references
  with accepted D1 R1 contracts.
- Confirm no D2 rule widens an earlier authorization, classification or
  destination boundary.

### Pass E — Adversarial coverage

- Verify the matrix has 17 required classes.
- Verify each class has one positive and one adversarial scenario.
- Verify all 34 scenarios have exact schema/matrix references and either a
  fixture identifier or explicit blocked reason.
- Confirm D3 exclusions are explicit.

### Pass F — Status and authorization

- Confirm every D2 document says candidate/design-only where applicable.
- Confirm implementation, ingestion, migration, provider calls and network
  execution remain blocked.
- Confirm no runtime `PASS`, provider truth or D2 acceptance is inferred from
  hash/schema/documentary results.

## 4. Finding format

Each finding MUST include:

```yaml
finding_id: <stable id>
severity: BLOCKER|HIGH|MEDIUM|LOW
status: OPEN|FIX_REQUIRED|STRUCTURALLY_ADDRESSED|NOT_PROVEN
area: <review area>
evidence_refs: [<exact file and section or JSON path>]
impact: <what remains ambiguous or unsafe>
required_action: <smallest corrective documentary action>
runtime_boundary: <what remains untested>
```

`STRUCTURALLY_ADDRESSED` means the contract exists; it does not mean the
runtime behavior is proven.

## 5. Decision rule

The independent reviewer returns:

```text
FIX-FIRST
```

if any BLOCKER remains open, any required schema/lineage reference is missing,
or any action/state/lifecycle ambiguity can change an emission decision.

The reviewer may return:

```text
DOCUMENTARY-READY / D2 ACCEPTANCE DECISION PENDING
```

only when the documentary package is internally deterministic. A separate
authority decision is still required before D2 acceptance, and runtime
evidence remains a later task.

## 6. Forbidden reviewer shortcuts

- Do not treat a hash match as proof of behavior.
- Do not treat a schema parse as proof of enforcement.
- Do not mark a scenario PASS without executable evidence or its documented
  blocked reason.
- Do not use provider documentation or caller claims to bypass authority
  precedence.
- Do not execute provider, connector or network calls.
- Do not modify production code, ingestion, migration or runtime configuration.
