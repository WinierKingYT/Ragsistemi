# PMIRI — V1-S0 Vertical Slice Acceptance Contract

**Version:** 0.1  
**Status:** `DESIGN-ONLY / FUTURE IMPLEMENTATION ACCEPTANCE`  
**Slice:** Local text → evidence → bounded context → typed local output  
**Execution:** Not performed

## 1. Acceptance objective

The slice is accepted only if a future implementation can take a small,
synthetic, local Markdown corpus and return a bounded, provenance-preserving
result without external access or canonical mutation.

## 2. Synthetic corpus

The fixture corpus must contain at least:

```text
project-alpha/source-a.md       relevant evidence
project-alpha/source-b.md       second relevant or conflicting evidence
project-beta/source-c.md        same vocabulary, wrong project
project-alpha/source-d.md       unrelated evidence
```

Each source must have a stable source ID, version ID, project ID and content
fingerprint. The fixture content must be synthetic and must not contain real
personal data, credentials or external identifiers.

## 3. Mandatory acceptance cases

| ID | Scenario | Required result | Failure condition |
|---|---|---|---|
| VS-01 | Register one local source | Source identity, version and SHA-256 are retained | Bytes or lineage are silently replaced or lost |
| VS-02 | Repeat registration of identical bytes | The normalized identity is deterministic and no false new content is created | Same bytes produce unstable identity |
| VS-03 | Query relevant text inside `project-alpha` | Returned EvidenceItems belong to the requested project and include anchors | Wrong-project or anchorless evidence is returned |
| VS-04 | Query with a foreign project locator | Access remains bounded by the trusted request envelope | Locator changes authorization or crosses project boundary |
| VS-05 | Query with no supporting evidence | Typed output is empty, unknown or partial according to the declared result vocabulary | The system fabricates an answer or citation |
| VS-06 | Compile a result under a fixed context budget | Output stays within the bound and retains citation lineage | Truncation drops the only citation or silently changes meaning |
| VS-07 | Supply two conflicting synthetic evidence items | Conflict metadata survives retrieval and compilation, or the result explicitly degrades/denies | One side disappears silently |
| VS-08 | Reorder source files without changing bytes | Structured output remains semantically and fingerprint-wise deterministic | Ordering changes the result without a declared reason |
| VS-09 | Repeat the same query twice | Normalized structured result and evidence references are equivalent | Result varies without an injected variable |
| VS-10 | Provide malformed UTF-8 or malformed structured input | The operation fails closed with a typed validation error | Partial parse is treated as valid evidence |
| VS-11 | Attempt external network/provider access | No external call occurs; the operation remains local | Any external call or credential use is observed |
| VS-12 | Execute all S0 operations and compare canonical state | Read-only operations leave canonical/user-domain state unchanged | Cache, log or wrapper changes semantic truth |

## 4. Required output shape

Every accepted query must expose, directly or through a stable structured
reference:

```yaml
request:
  request_id: <stable id>
  project_constraint: <declared constraint>
result:
  disposition: <typed disposition>
  coverage: <complete|partial|unknown|not_applicable>
evidence:
  - source_id: <id>
    version_id: <id>
    anchor: <stable anchor>
    fingerprint: <sha256 or equivalent>
lineage:
  authorization_ref: <server-derived request basis>
  evidence_refs: [<refs>]
context:
  artifact_kind: CompiledContextArtifact
  bound: <declared limit>
  citation_refs: [<refs>]
```

The exact implementation schema may add fields, but it may not remove the
semantic obligations above or replace typed state with prose.

## 5. Evidence required from a future implementation

For each mandatory case, the AI must provide:

- test identifier and input fixture fingerprint;
- normalized request fingerprint;
- structured actual result;
- output/citation fingerprints;
- canonical-state before/after fingerprint for VS-12;
- external-access observation for VS-11;
- a short failure explanation for every negative case;
- test command and environment declaration.

The implementation must not label these artifacts as Gate-C R-FC evidence
unless the GC-C1 replay workflow and independent-review requirements are also
satisfied.

## 6. Hard rejection rules

Reject the slice if any of the following occurs:

- a test passes only because an assertion is weakened;
- a citation points to a mutable position without a stable source/version
  identity;
- an unknown or partial result is rendered as complete;
- a locator or cursor is treated as authorization;
- a conflict is removed without an explicit disposition;
- a provider or network call occurs;
- a read-only operation mutates canonical or user-domain semantics;
- tests rely on unstated ambient files, credentials, clocks or ordering;
- the AI expands S0 without a recorded scope decision.

## 7. Acceptance status vocabulary

```text
DESIGNED       Contract exists; no implementation run.
RECORDED       Future test produced an artifact, pending review.
ACCEPTED       S0 acceptance review accepted the complete case set.
REJECTED       A hard criterion failed.
BLOCKED        Required environment, fixture or authority is unavailable.
```

`ACCEPTED` here is local S0 acceptance only. It is not Gate-C acceptance, R-FC
`PASS` or production authorization.

