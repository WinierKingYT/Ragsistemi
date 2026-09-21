# PMIRI — Gate D Round 2 — Provider and Connector Trust Registry Contract

**Version:** 0.2  
**Status:** `CANDIDATE / DESIGN-ONLY`  
**Gate:** D2  
**Implementation authorization:** `NOT GRANTED`

## 1. Mission

Define the authoritative trust inputs used before PMIRI sends material to an
external provider, invokes a connector or fetches a remote resource.

This contract does not define encryption/key domains, forensic retention or
production networking. Those remain D3 or implementation work.

## 2. Trust is destination- and purpose-specific

PMIRI MUST NOT represent provider trust as one global boolean or one ordinal
score. A destination may be trusted for one purpose and disallowed for another.

The effective trust question is:

```text
Is this exact destination
trusted for this exact purpose,
material class, feature and time window?
```

The following are separate subjects:

```text
ProviderOrganization
ProviderService
ProviderModel
ProviderFeature
ConnectorService
ConnectorEndpoint
FetchedResourceOrigin
Subprocessor
```

An assertion about a parent subject does not automatically authorize a child
subject. A provider-level assertion cannot silently authorize an unregistered
model, feature, endpoint or subprocessor.

## 3. Trust registry authority

The trust registry is a policy input, not canonical user knowledge. The
machine-readable record contract is
`PMIRI_GD-R2-01_TRUST_ASSERTION.schema.json`; the YAML below is explanatory
and MUST remain isomorphic to that schema. Every record MUST have:

```yaml
trust_assertion_id: <stable id>
subject:
  subject_type: <provider|service|model|feature|connector|endpoint|origin|subprocessor>
  subject_id: <exact provider/destination identity>
  parent_subject_ref: <optional exact parent binding>
purpose: <retrieval|context_delivery|external_fetch|attachment_import|provider_call>
allowed_material_classes: [<class bindings>]
allowed_features: [<exact feature ids>]
allowed_zones: [<trust zones>]
issuer: <trusted registry authority>
evidence_refs: [<evidence refs>]
policy_version: <version>
observed_at: <UTC timestamp>
valid_until: <UTC timestamp or explicit non-expiring policy basis>
revocation_ref: <optional revocation ref>
assertion_fingerprint: <sha256>
status: ACTIVE|EXPIRED|REVOKED|SUPERSEDED|INVALID
```

An assertion with missing issuer, evidence, policy version, validity boundary
or fingerprint is not usable for external disclosure.

Unknown purposes are rejected at schema validation. There is no `other`
escape hatch: an operation or purpose outside the canonical vocabulary is an
internal contract error and must map to `action_result=DENY` or
`REQUIRE_REVIEW` before any external disclosure.

## 4. Trust decision vocabulary

The exact trust-state, action-result, lifecycle and reason enums are defined by
`PMIRI_GD-R2-06_DECISION_VOCABULARY.schema.json` and
`PMIRI_GD-R2-06_DECISION_VOCABULARY_v0.1.md`. This contract does not create a
second result vocabulary.

The registry may produce only these destination trust states:

```text
TRUSTED_FOR_BOUND_PURPOSE
CONDITIONALLY_TRUSTED
UNTRUSTED
UNKNOWN
EXPIRED
REVOKED
CONTRADICTED
INVALID
```

`TRUSTED_FOR_BOUND_PURPOSE` is not a general provider endorsement. It means
that the exact recorded subject satisfies the exact recorded trust assertions
for the requested purpose and validity window.

`UNKNOWN`, `EXPIRED`, `REVOKED`, `CONTRADICTED` and `INVALID` are fail-closed
for external disclosure unless a more restrictive local-only path is selected.

## 5. Provider policy dimensions

The authority precedence and freshness rules for these dimensions are defined
by `PMIRI_GD-R2-07_PROVIDER_POLICY_AUTHORITY_AND_FRESHNESS_CONTRACT_v0.1.md`
and its machine-readable matrix. The observation record is
`PMIRI_GD-R2-07_PROVIDER_POLICY_OBSERVATION.schema.json`.

Trust evaluation MUST keep these dimensions separate:

- data retention period and deletion behavior;
- provider training/use of submitted material;
- subprocessor set and subprocessor purpose;
- region or processing-location constraints;
- model/feature capability claims;
- structured-output and attachment behavior;
- logging and diagnostic material handling;
- connector-origin and fetched-content trust;
- destination authentication identity;
- policy and assertion freshness.

Missing information in one dimension cannot be filled by a positive result in
another dimension. A trusted provider identity does not prove a permitted
training policy.

## 6. D1 integration

The D2 trust result consumes, but does not redefine, D1 objects:

```text
AuthorizationSubjectChain
TrustZoneAttestation
PurposeBinding
SecurityClassificationBinding
DerivedSensitivityAssessment
SecurityCompositionDecision
DestinationSecurityBinding
SecurityDecisionValidity
```

The final destination decision is bounded by the intersection of:

```text
subject-chain authority
∩ purpose binding
∩ current security classification/composition decision
∩ destination trust assertion
∩ capability freshness decision
∩ egress policy
```

No D2 trust assertion may widen D1 authorization or classification.

## 7. Connector trust boundary

A connector is not trusted merely because PMIRI owns its credentials or because
it is used to obtain a provider result.

The credential boundary record is
`PMIRI_GD-R2-01_CONNECTOR_CREDENTIAL_BOUNDARY.schema.json`. A credential
binding MUST be scoped to one connector process, exact destination and exact
operation set. It MUST specify its injection channel, validity interval,
rotation/revocation references and credential epoch. The secret value itself
is never a PMIRI evidence field. The primary operation and every item in the
operation set use the closed-world canonical operation vocabulary; no catch-all
or free-form operation is valid.

Each connector MUST declare:

- exact service identity;
- allowed operation set;
- allowed destination/origin set;
- allowed material classes;
- credential scope reference, without exposing the secret;
- response content types and size limits;
- redirect and DNS policy;
- attachment handling policy;
- revocation and disable path;
- audit/evidence reference.

The credential boundary MUST additionally prohibit the secret value from being
visible to the provider/model, fetched content, caller content, logs, error
payloads and canonical artifacts. Rotation or revocation changes the
credential epoch and invalidates all cached decisions bound to the prior
epoch. A missing, over-scoped, unexpectedly visible or stale boundary yields
`action_result=DENY` with `CREDENTIAL_SCOPE_INVALID` or
`CREDENTIAL_VISIBILITY_RISK`.

Connector output enters PMIRI as untrusted external material until it passes
the applicable validation, provenance and classification boundaries.

## 8. Trust decision output

The output is a derived decision serialized by
`PMIRI_GD-R2-01_TRUST_DECISION.schema.json`:

```yaml
destination_trust_decision:
  decision_id: <stable id>
  destination_binding_ref: <exact destination binding>
  purpose_binding_ref: <purpose>
  material_manifest_ref: <D1 egress material manifest>
  trust_assertion_refs: [<assertions>]
  capability_decision_ref: <D2 capability decision>
  authority_manifest_fingerprint: <accepted authority bundle fingerprint>
  trust_state: TRUSTED_FOR_BOUND_PURPOSE|CONDITIONALLY_TRUSTED|UNTRUSTED|UNKNOWN|EXPIRED|REVOKED|CONTRADICTED|INVALID
  action_result: ALLOW|ALLOW_WITH_CONSTRAINTS|DENY|REQUIRE_REVIEW|REQUIRE_REVALIDATION|LOCAL_ONLY
  content_lifecycle: NOT_APPLICABLE
  reason_class: <canonical typed reason>
  validity_ref: <SecurityDecisionValidity>
  decision_fingerprint: <sha256>
```

`action_result` is the only permission-bearing field. `trust_state` is an
evidence classification and MUST NOT be placed in `action_result`. If
`ALLOW_WITH_CONSTRAINTS` is emitted, the decision MUST name the exact
constrained egress artifact, allowed features, redaction profile and validity
window. It cannot be a vague warning state.

## 9. Fail-closed rules

External disclosure is denied or held when:

- the exact destination cannot be identified;
- the trust assertion is missing, expired, revoked, contradicted or invalid;
- a child feature/model/endpoint is not covered by the assertion;
- a required provider-policy dimension is unknown;
- the subprocessor set is unknown where the policy requires it;
- the material's derived sensitivity exceeds the destination binding;
- the destination proof does not match the material/profile fingerprint;
- the capability or trust validity window has elapsed.
- the connector credential boundary is missing, over-scoped, stale, revoked or
  exposes the secret value across a prohibited boundary.

## 10. Exit criteria

D2-01 is design-complete only when the registry schema, canonical decision
vocabulary, destination identity rules, provider-policy authority/freshness
contract and fail-closed mapping are independently reviewed against the
adversarial matrix.

This candidate does not declare D2 accepted.
