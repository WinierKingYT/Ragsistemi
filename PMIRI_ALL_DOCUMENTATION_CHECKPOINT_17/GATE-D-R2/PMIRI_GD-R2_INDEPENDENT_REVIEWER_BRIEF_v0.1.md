# PMIRI — Gate D Round 2
# Independent Reviewer Brief v0.1

**Purpose:** commission a genuinely separate documentary decision over the D2 candidate
**Review status:** `READY FOR INDEPENDENT REVIEW`
**Implementation authorization:** `NOT GRANTED`
**Runtime authorization:** `NOT GRANTED`

## 1. Reviewer mandate

You are the independent reviewer for PMIRI Gate D Round 2. Your task is to
decide whether the D2 documentary bundle is internally deterministic enough to
leave `FIX-FIRST`, or whether an open blocker or ambiguity remains.

You are not an implementer, co-author, or acceptance rubber stamp. Do not
modify any PMIRI file while reviewing. Do not infer behavior that is not
supported by an exact document, schema, hash, or executable result.

The review is documentary only. Provider calls, connector calls, external
fetches, DNS tests, migrations, ingestion, production changes, and runtime
execution are forbidden.

## 2. Review identity and independence

Before starting, record:

```yaml
review_id: <unique id>
reviewer_role: independent documentary reviewer
reviewer_identity: <model/person/system identity>
authoring_context_available: <true|false>
package_modified_during_review: false
review_started_at: <UTC RFC3339>
```

If you authored or materially edited the D2 candidate, you may perform a
secondary review but MUST NOT label the result `INDEPENDENT ACCEPTANCE`.
Use `NON-INDEPENDENT SECONDARY REVIEW` instead.

## 3. Anti-anchoring sequence

Use this order:

1. Read the protocol, authority manifest, candidate index, accepted Gate-C/D1
   authority inputs, and every D2 contract/schema/matrix member.
2. Recompute and record the authority manifest fingerprint.
3. Verify every listed member hash and detect unlisted candidate files.
4. Write a preliminary verdict and findings before reading the authoring
   team's fresh-pass report.
5. Read `PMIRI_GD-R2_INDEPENDENT_HARD_RECHECK_REPORT_v0.1.md` only to compare
   conclusions, never to replace your own evidence trail.
6. Resolve disagreements by exact evidence references, not by majority vote.

The preliminary report is non-authoritative and cannot upgrade the package.

## 4. Mandatory review questions

### Identity and lineage

- Does the manifest fingerprint recompute exactly under its declared
  canonicalization?
- Are all Gate-C and D1 R1 hashes the exact accepted authority inputs?
- Is every D2 member listed, hash-bound, and locally present?
- Is any D2 text attempting to widen or redefine earlier authority?

### Schemas and serialization

- Does every referenced schema resolve exactly?
- Are required, optional, nullable, enum, and version semantics deterministic?
- Are fingerprint inputs and exclusions identical across all relevant records?
- Does every decision record bind the authority-manifest fingerprint?
- Is any result dependent on an unstated normalization or ordering rule?

### State, action, lifecycle, and fail-closed behavior

- Are trust state, capability state, obligation impact, action result,
  content lifecycle, and reason class distinct?
- Can missing, stale, revoked, contradicted, invalid, out-of-scope, or
  unproven input reach an allow action without an explicit justified path?
- Can a redaction or transformation silently weaken an obligation?
- Can quarantined or fetched content become canonical truth or unrestricted
  retrieval content without typed admission?

### Cross-round compatibility

- Does D2 preserve Gate-C truth, authority, retrieval, disclosure, and
  emission-fence ceilings?
- Does D2 preserve D1 subject, purpose, classification, destination, material,
  policy-epoch, and validity bindings?
- Can a cached or stale decision widen an earlier boundary?

### Adversarial coverage

- Are all 17 required classes present?
- Does each class have one positive and one adversarial scenario?
- Does every scenario reference the exact schemas/matrices it exercises?
- Does every blocked scenario have an explicit blocked reason?
- Are D3 exclusions explicit and non-leaky?

### Status and authorization

- Does every result distinguish documentary structure from runtime proof?
- Are implementation, ingestion, migration, provider, connector, and network
  permissions still denied?
- Is Gate-C executable incompleteness preserved rather than overwritten by D2
  documentary results?

## 5. Required deliverable

Create a separate file named:

```text
PMIRI_GD-R2_INDEPENDENT_REVIEW_DECISION_v0.1.md
```

It MUST contain:

```yaml
review_id: <stable id>
reviewer_identity: <identity>
independence_status: INDEPENDENT|NON_INDEPENDENT_SECONDARY_REVIEW
manifest_fingerprint: <verified value>
package_modified_during_review: false
decision: FIX-FIRST|DOCUMENTARY-READY|RETHINK
acceptance_status: PENDING_AUTHORITY_DECISION
implementation_authorization: NOT_GRANTED
runtime_authorization: NOT_GRANTED
```

Then include a finding table. Every finding MUST contain:

```yaml
finding_id: <stable id>
severity: BLOCKER|HIGH|MEDIUM|LOW
status: OPEN|FIX_REQUIRED|STRUCTURALLY_ADDRESSED|NOT_PROVEN
area: <area>
evidence_refs: [<exact file and section or JSON path>]
impact: <specific consequence>
required_action: <smallest documentary correction or proof needed>
runtime_boundary: <what remains untested>
```

The decision rules are strict:

```text
FIX-FIRST
  if a blocker remains open, a required reference is missing, or an ambiguity
  can change an emission decision.

DOCUMENTARY-READY
  only if the documentary package is internally deterministic; this is not
  D2 acceptance and does not authorize implementation or runtime execution.

RETHINK
  if the core model cannot be made deterministic by a small documentary fix.
```

## 6. Prohibited conclusions

Do not conclude any of the following from this review alone:

```text
D2 ACCEPTED
PRODUCTION READY
RUNTIME ENFORCEMENT VERIFIED
PROVIDER TRUST VERIFIED
CREDENTIAL ISOLATION VERIFIED
NETWORK / SSRF DEFENSE VERIFIED
GATE C RUNTIME PASS
```

The independent reviewer may recommend `DOCUMENTARY-READY`; formal D2
acceptance remains a separate authority decision.

