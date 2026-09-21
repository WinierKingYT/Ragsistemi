# Request Authorization and Security Decision Validity

## RequestAuthorizationBinding

Gate C's object is concretized by Gate D and binds:
- authenticated principal;
- AuthorizationSubjectChain;
- TrustZoneAttestation;
- PurposeBinding;
- requested operation/narrowing;
- allowed-domain basis;
- SecurityPolicyBundle;
- applicable SecurityPolicyEpoch coverage;
- issuance/validity and integrity provenance.

It is server/trusted-boundary derived.

## Scope-aware SecurityPolicyEpoch

```text
SecurityPolicyEpoch
- security_domain/scope
- epoch
- canonical/policy commit token
- changed_policy_domains[]
- generated_at
```

Relevant restrictive changes advance the applicable epoch/equivalent invalidation state.

## SecurityDecisionValidity

Every access/disclosure/egress decision binds:
- authorization-subject/delegation fingerprint;
- trust-zone attestation fingerprint;
- purpose;
- exact target or material-manifest fingerprint;
- operation;
- policy bundle/version;
- applicable SecurityPolicyEpoch coverage;
- destination binding where relevant;
- validity conditions.

Reuse is allowed only while every material dimension still matches.
A cache key, prior allow, object ID or previous successful request is never authority.
