# Security Classification Binding and Change Contract

Labels remain non-ordinal:
`PUBLIC | CLOUD_OK | RESTRICTED | LOCAL_ONLY`.

## SecurityClassificationBinding

```text
SecurityClassificationBinding
- binding_id
- target_kind
- target_id
- classification
- scope/purpose applicability?
- valid_from
- valid_to?
- recorded_at / canonical commit
- assigning_authority_ref
- policy_basis_ref
- reason
- provenance_ref
```

Classification is temporal, attributable and auditable.
A public URL or public origin does not automatically create a PUBLIC binding.

## Unknown classification

`CLASSIFICATION_UNKNOWN` remains an explicit epistemic state. It is not rewritten as a
historical `LOCAL_ONLY` classification.

For external disclosure/egress, unknown classification is fail-closed and receives
effective behavior no less restrictive than the accepted LOCAL_ONLY external rule until
a valid classification exists.

## ClassificationChangeDecision

```text
ClassificationChangeDecision
- target ref
- prior binding refs
- requested new binding
- authorized actor/service ref
- policy basis/version
- result: ACCEPT | DENY | INDETERMINATE
- reason codes
- recorded_at
```

Models, prompts, parsers, retrieval systems and transforms cannot authorize
classification changes. Declassification is never an incidental transform side effect.
