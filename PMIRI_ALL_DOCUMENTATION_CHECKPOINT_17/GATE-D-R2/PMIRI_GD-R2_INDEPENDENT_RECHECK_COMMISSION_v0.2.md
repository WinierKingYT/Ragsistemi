# PMIRI — Gate D Round 2
# Independent Recheck Commission v0.2

**Target bundle:** D2 candidate correction revision `0.2`
**Prior decision:** `FIX-FIRST` (`IR-D2-01` through `IR-D2-07`)
**Current package claim:** `CORRECTION COMPLETE / INDEPENDENT RECHECK REQUIRED`
**Implementation authorization:** `NOT GRANTED`
**Runtime authorization:** `NOT GRANTED`

## 1. Commission

Perform a new independent documentary hard recheck of the corrected D2
candidate. Do not edit, replace or downgrade the prior decision. The new
decision must be a separate versioned record.

Use these inputs:

```text
PMIRI_GD-R2_AUTHORITY_BUNDLE_MANIFEST_v0.1.json
PMIRI_GD-R2_CANDIDATE_INDEX_v0.1.md
PMIRI_GD-R2_CORRECTIVE_CLOSURE_REPORT_v0.2.md
PMIRI_GD-R2_CROSS_FIELD_VALIDATION_RULES_v0.2.md
PMIRI_GD-R2_INDEPENDENT_HARD_RECHECK_PROTOCOL_v0.1.md
PMIRI_GD-R2_INDEPENDENT_REVIEWER_BRIEF_v0.1.md
PMIRI_GD-R2_INDEPENDENT_REVIEW_DECISION_v0.1.md
every manifest-listed D2 member
exact accepted Gate-C and D1 R1 members bound by the manifest
```

## 2. Required sequence

1. Record reviewer identity and independence status.
2. Recompute the manifest fingerprint and verify every bound hash.
3. Review the corrected schemas and cross-field rules against the seven prior
   findings.
4. Produce your own preliminary findings before reading the prior fresh-pass
   report or corrective closure report.
5. Compare with prior records only after your own findings are recorded.
6. Do not perform provider, connector, network, DNS, parser, migration,
   ingestion or runtime actions.

## 3. Closure questions

The reviewer MUST specifically test whether:

- Gate-C lineage refs and fingerprints are required and resolvable;
- external integrated envelopes cannot omit constrained/network proof;
- obligation impacts and transformation outputs are conditionally complete;
- operation/purpose values have a closed-world fail-closed mapping;
- capability observations and policy epochs are mechanically bound;
- selected network targets, proxy identity, TLS identity and terminal
  lifecycle are cross-field deterministic;
- fetched-content admission, visibility and transitions are deterministic.

## 4. Required output

Create exactly one new file:

```text
PMIRI_GD-R2_INDEPENDENT_REVIEW_DECISION_v0.2.md
```

The file MUST include:

```yaml
review_id: <stable id distinct from v0.1 review>
reviewer_identity: <identity>
independence_status: INDEPENDENT|NON_INDEPENDENT_SECONDARY_REVIEW
manifest_fingerprint: <verified current value>
package_modified_during_review: false
decision: FIX-FIRST|DOCUMENTARY-READY|RETHINK
acceptance_status: PENDING_AUTHORITY_DECISION
implementation_authorization: NOT_GRANTED
runtime_authorization: NOT_GRANTED
```

Every finding must include severity, status, exact evidence references,
impact, required action and runtime boundary. Do not call the package accepted,
production-ready or runtime-verified.

