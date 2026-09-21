# Security Composition and Derived Sensitivity Contract

## SecurityLineage

Every material derived evidence/context unit carries lineage to relevant source/canonical
security bindings and derivations. Missing material lineage makes external
disclosure/egress `INDETERMINATE` and therefore fail-closed.

## DerivedSensitivityAssessment

```text
DerivedSensitivityAssessment
- assessment_id
- derived artifact/span ref
- input security lineage refs[]
- aggregation/transform semantics ref
- policy bundle/epoch
- findings[]
- result:
    NO_NEW_RESTRICTION_IDENTIFIED
    ADDITIONAL_RESTRICTION_REQUIRED
    INDETERMINATE
- required security bindings/constraints[]
```

This is not ordinal label comparison. It captures mosaic/inference effects where
individually disclosable items combine into a newly sensitive aggregate.

## SecurityCompositionDecision

Multi-evidence disclosure/egress explicitly evaluates:
- every material security lineage;
- the aggregate sensitivity assessment;
- purpose;
- destination;
- current access bindings;
- current policy epoch.

`max(label)`, `min(label)` and numeric label ordering are non-conformant.
