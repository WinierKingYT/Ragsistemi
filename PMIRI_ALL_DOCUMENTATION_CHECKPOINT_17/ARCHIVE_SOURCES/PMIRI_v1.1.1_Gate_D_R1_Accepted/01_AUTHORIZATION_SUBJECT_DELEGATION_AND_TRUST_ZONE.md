# Authorization Subject, Delegation and Trust-Zone Contract

## AuthorizationSubjectChain

```text
AuthorizationSubjectChain
- human_principal_ref?
- service_principal_ref
- workload_principal_ref?
- delegation_grant_refs[]
- originating_trust_zone_attestation_ref
- operation_ref
- purpose_binding_ref
- effective_authority_fingerprint
```

Effective authority is the **intersection** of every applicable human/service/workload
delegation and restriction. It is never the union of privileges.

A missing/invalid delegation component yields `DENY` or `INDETERMINATE`, never elevation.

## TrustZoneAttestation

```text
TrustZoneAttestation
- attestation_id
- workload/service identity ref
- zone_id/class
- environment/runtime evidence refs
- issuer/security-control ref
- issued_at
- valid_until / invalidation condition
- fingerprint
```

Trust-zone identity is derived by a trusted security boundary. Client parameters,
model output and source text cannot self-assert a trusted zone. Physical locality alone
is not sufficient trust evidence.

## PurposeBinding

Purpose is derived from the accepted semantic operation/workflow. A caller may request
or narrow behavior but cannot relabel an egress action as `RETRIEVAL_USE` to obtain a
weaker policy.

```text
PurposeBinding
- purpose_binding_id
- operation/workflow ref
- policy-recognized purpose
- caller requested purpose/narrowing?
- derivation/policy ref
- fingerprint
```
