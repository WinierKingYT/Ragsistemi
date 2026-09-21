# PMIRI — Gate D Round 2
# Independent Recheck Commission v0.4

**Status:** `COMMISSIONED / DOCUMENTARY ONLY`
**Candidate correction revision:** `0.4`
**Manifest fingerprint:** The reviewer MUST use the current value declared in
`PMIRI_GD-R2_AUTHORITY_BUNDLE_MANIFEST_v0.1.json` at review start.
**Implementation authorization:** `NOT GRANTED`
**Runtime authorization:** `NOT GRANTED`

## 1. Commission

Perform a fresh independent hard review of the current Gate D Round 2
candidate. Freeze the current manifest and verify every declared member hash
before assessing semantics. Do not rely on authoring claims or prior review
conclusions as evidence.

The review may return exactly one of:

```text
D2 ACCEPTED — DOCUMENTARY CONTRACT ONLY
FIX-FIRST
RETHINK
```

## 2. Mandatory recheck points

At minimum inspect:

- freshness-profile canonical payload, corrected fingerprint and self-check;
- typed outbound network and fetched-content lifecycle bindings in the final
  integrated envelope;
- mixed-DNS `resolution_set_status` and fail-closed action mapping;
- the versioned URL/authority/IPv6/SNI canonicalization profile;
- exact connection revalidation event epoch equations;
- closed expected-outcome schema and per-scenario bindings;
- absolute schema URI resource registry and all `$ref` pointers;
- per-dimension provider-policy `observed_value` tagged union and dimension
  equality;
- all previous IR-D2-01..22 findings, Gate-C lineage bindings and deferred
  D3 boundary.

No provider, connector, DNS, network, parser, ingestion, migration,
production, external emission or runtime operation is authorized. Structural
documentary closure is not runtime proof.

## 3. Required output

Write only the separate decision file:

`PMIRI_GD-R2_INDEPENDENT_REVIEW_DECISION_v0.4.md`

Include the review identity, frozen manifest fingerprint, complete member/hash
verification, independence and anti-anchoring record, findings with severity,
evidence and required action, reassessment of IR-D2-01..22, final verdict and
explicit `NOT_GRANTED` implementation/runtime authorization.
