# PMIRI — Gate D Round 2 Candidate Index

**Version:** 0.5  
**Status:** `D2 CANDIDATE / FIX-FIRST / CORRECTION REVISION 0.5 / INDEPENDENT RECHECK REQUIRED`  
**Candidate correction revision:** `0.5`  
**Implementation authorization:** `NOT GRANTED`

## Scope

This candidate package covers:

```text
D2-01 Provider / connector trust registry
D2-02 Capability freshness / invalidation
D2-03 Redaction / constrained egress
D2-04 External fetch / SSRF / network boundary
D2-05 Cross-cutting integrated decision and emission-fence race review
```

Deferred to D3:

```text
encryption and key domains
forensic retention
```

## Documents

1. `PMIRI_GD-R2-01_PROVIDER_CONNECTOR_TRUST_REGISTRY_CONTRACT_v0.1.md`
2. `PMIRI_GD-R2-02_CAPABILITY_FRESHNESS_INVALIDATION_CONTRACT_v0.1.md`
3. `PMIRI_GD-R2-03_REDACTION_CONSTRAINED_EGRESS_CONTRACT_v0.1.md`
4. `PMIRI_GD-R2-04_EXTERNAL_FETCH_SSRF_NETWORK_BOUNDARY_CONTRACT_v0.1.md`
5. `PMIRI_GD-R2-05_INTEGRATED_DECISION_MODEL_AND_ADVERSARIAL_MATRIX_v0.1.md`
6. `PMIRI_GD-R2-05_ADVERSARIAL_SCENARIO_MATRIX.json`
7. `PMIRI_GD-R2-06_DECISION_VOCABULARY_v0.1.md`
8. `PMIRI_GD-R2-07_PROVIDER_POLICY_AUTHORITY_AND_FRESHNESS_CONTRACT_v0.1.md`
9. `PMIRI_GD-R2-07_PROVIDER_POLICY_AUTHORITY_MATRIX.json`
10. `PMIRI_GD-R2_AUTHORITY_BUNDLE_MANIFEST_v0.1.json`
11. `PMIRI_GD-R2_BLOCKER_CLOSURE_RECHECK_REPORT_v0.1.md`
12. `PMIRI_GD-R2_INDEPENDENT_HARD_RECHECK_PROTOCOL_v0.1.md`
13. `PMIRI_GD-R2_INDEPENDENT_HARD_RECHECK_REPORT_v0.1.md`
14. `PMIRI_GD-R2_INDEPENDENT_REVIEWER_BRIEF_v0.1.md`
15. `PMIRI_GD-R2_INDEPENDENT_REVIEW_DECISION_v0.1.md`
16. `PMIRI_GD-R2_CORRECTIVE_CLOSURE_REPORT_v0.2.md`
17. `PMIRI_GD-R2_CROSS_FIELD_VALIDATION_RULES_v0.2.md`
18. `PMIRI_GD-R2_INDEPENDENT_RECHECK_COMMISSION_v0.2.md`
19. `PMIRI_GD-R2_INDEPENDENT_REVIEW_DECISION_v0.2.md`
20. `PMIRI_GD-R2_CORRECTIVE_CLOSURE_REPORT_v0.3.md`
21. `PMIRI_GD-R2_CROSS_FIELD_VALIDATION_RULES_v0.3.md`
22. `PMIRI_GD-R2_INDEPENDENT_RECHECK_COMMISSION_v0.3.md`
23. `PMIRI_GD-R2_INDEPENDENT_REVIEW_DECISION_v0.3.md`
24. `PMIRI_GD-R2_CORRECTIVE_CLOSURE_REPORT_v0.4.md`
25. `PMIRI_GD-R2_CROSS_FIELD_VALIDATION_RULES_v0.4.md`
26. `PMIRI_GD-R2_INDEPENDENT_RECHECK_COMMISSION_v0.4.md`
27. `PMIRI_GD-R2_CORRECTIVE_CLOSURE_REPORT_v0.5.md`
28. `PMIRI_GD-R2_CROSS_FIELD_VALIDATION_RULES_v0.5.md`
29. `PMIRI_GD-R2_INDEPENDENT_RECHECK_COMMISSION_v0.5.md`
30. `PMIRI_GD-R2-01_PROVIDER_CONNECTOR_TRUST_REGISTRY_CONTRACT_v0.2.md`
31. `PMIRI_GD-R2-05_INTEGRATED_DECISION_MODEL_AND_ADVERSARIAL_MATRIX_v0.2.md`
32. `PMIRI_GD-R2-04_EXTERNAL_FETCH_SSRF_NETWORK_BOUNDARY_CONTRACT_v0.2.md`
33. `PMIRI_GD-R2_INDEPENDENT_REVIEW_DECISION_v0.4.md`

## Machine-readable schemas

1. `PMIRI_GD-R2-01_TRUST_ASSERTION.schema.json`
2. `PMIRI_GD-R2-01_TRUST_DECISION.schema.json`
3. `PMIRI_GD-R2-01_CONNECTOR_CREDENTIAL_BOUNDARY.schema.json`
4. `PMIRI_GD-R2-02_CAPABILITY_OBSERVATION.schema.json`
5. `PMIRI_GD-R2-02_CAPABILITY_DECISION.schema.json`
6. `PMIRI_GD-R2-03_REDACTION_TRANSFORMATION.schema.json`
7. `PMIRI_GD-R2-03_TYPED_CONSTRAINT.schema.json`
8. `PMIRI_GD-R2-03_EGRESS_CONSTRAINED_CONTEXT_ARTIFACT.schema.json`
9. `PMIRI_GD-R2-04_CONNECTION_BINDING.schema.json`
10. `PMIRI_GD-R2-04_OUTBOUND_NETWORK_DECISION.schema.json`
11. `PMIRI_GD-R2-04_RESOURCE_LIMITS_PROFILE.schema.json`
12. `PMIRI_GD-R2-04_FETCHED_CONTENT_LIFECYCLE.schema.json`
13. `PMIRI_GD-R2-05_INTEGRATED_DECISION_ENVELOPE.schema.json`
14. `PMIRI_GD-R2-06_DECISION_VOCABULARY.schema.json`
15. `PMIRI_GD-R2-07_PROVIDER_POLICY_OBSERVATION.schema.json`
16. `PMIRI_GD-R2-05_EXPECTED_OUTCOME.schema.json`

## Normative decision matrices

1. `PMIRI_GD-R2-03_OBLIGATION_TRANSFORMATION_DECISION_MATRIX.json`
2. `PMIRI_GD-R2-05_ADVERSARIAL_SCENARIO_MATRIX.json`
3. `PMIRI_GD-R2-07_PROVIDER_POLICY_AUTHORITY_MATRIX.json`
4. `PMIRI_GD-R2-04_NETWORK_CANONICALIZATION_PROFILE.json`
5. `PMIRI_GD-R2_SCHEMA_RESOURCE_REGISTRY_v0.1.json`
6. `PMIRI_GD-R2-07_FRESHNESS_PROFILE_SELF_CHECK_v0.1.md`

## Boundary preserved

- Gate A, B and C accepted semantics are not redefined.
- Accepted D1 security/authorization core is consumed, not rewritten.
- No provider, connector or network call was made.
- No encryption/key or forensic-retention design was introduced.
- No production implementation, ingestion or migration was authorized.
- No D2 `PASS` or acceptance claim is made.
- The independent documentary reviewers returned `FIX-FIRST`; findings
  `IR-D2-01` through `IR-D2-22` were structurally addressed in correction
  revision `0.4`, while `IR-D2-23` through `IR-D2-30` were identified in the
  v0.4 independent pass and are addressed in correction revision `0.5`.
  The v0.4 decision remains a historical `FIX-FIRST` result; a new
  independent recheck is required. This is not an acceptance claim.
- The canonical decision vocabulary separates evidence state, action result,
  content lifecycle and obligation impact.
- Provider-policy authority precedence and freshness are defined, but no real
  provider assertion has been verified.
- The matrix provides positive/adversarial coverage for all 17 required D2
  classes; runtime fixtures remain explicitly blocked.

## Next review

The corrective closure is recorded in
`PMIRI_GD-R2_CORRECTIVE_CLOSURE_REPORT_v0.5.md`; the cross-field rules are
recorded in `PMIRI_GD-R2_CROSS_FIELD_VALIDATION_RULES_v0.5.md`. The next task
is a new independent decision over these corrections. The prior independent
decisions are recorded in
`PMIRI_GD-R2_INDEPENDENT_REVIEW_DECISION_v0.1.md`,
`PMIRI_GD-R2_INDEPENDENT_REVIEW_DECISION_v0.2.md` and
`PMIRI_GD-R2_INDEPENDENT_REVIEW_DECISION_v0.3.md`,
`PMIRI_GD-R2_INDEPENDENT_REVIEW_DECISION_v0.4.md`; the fresh pass that
preceded them is recorded in
`PMIRI_GD-R2_INDEPENDENT_HARD_RECHECK_REPORT_v0.1.md`.

The new review must follow
`PMIRI_GD-R2_INDEPENDENT_RECHECK_COMMISSION_v0.5.md` and produce a separate
`PMIRI_GD-R2_INDEPENDENT_REVIEW_DECISION_v0.5.md`.

The corrective work must continue to use the protocol in
`PMIRI_GD-R2_INDEPENDENT_HARD_RECHECK_PROTOCOL_v0.1.md`:

The reviewer must use
`PMIRI_GD-R2_INDEPENDENT_REVIEWER_BRIEF_v0.1.md` for anti-anchoring,
independence, evidence and decision-output requirements.
against:

- accepted Gate-C egress and emission-fence contracts;
- accepted Gate-D R1 subject, trust-zone, classification and validity objects;
- this D2 scenario matrix;
- canonical schemas and vocabulary;
- provider-policy authority/freshness matrix;
- credential boundary, resource-limit and fetched-content lifecycle schemas;
- redaction obligation/transformation decision matrix;
- cross-document vocabulary, fingerprint and fail-closed behavior.

The recheck must be allowed to return `FIX-FIRST`. Structural blocker closure
does not constitute D2 acceptance or runtime authorization.
