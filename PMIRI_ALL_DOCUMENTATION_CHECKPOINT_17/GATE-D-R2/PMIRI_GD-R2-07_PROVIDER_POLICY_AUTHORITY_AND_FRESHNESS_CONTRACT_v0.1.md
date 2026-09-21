# PMIRI — Gate D Round 2 — Provider Policy Authority and Freshness Contract

**Version:** 0.2  
**Status:** `CANDIDATE / BLOCKER-CLOSURE`  
**Gate:** D2  
**Implementation authorization:** `NOT GRANTED`

## 1. Purpose

Define which source may establish a provider/connector policy fact, how
conflicts are resolved, which dimensions are mandatory for each operation and
when an observation is stale.

This contract does not verify any real provider. It defines the future
decision boundary.

## 2. Authority classes and precedence

The canonical source classes are ordered from strongest to weakest:

```text
LOCAL_HARD_POLICY
NETWORK_OR_CONNECTOR_ATTESTATION
SIGNED_PROVIDER_DECLARATION
AUTHORITATIVE_REGISTRY
DIRECT_RUNTIME_OBSERVATION
PROVIDER_DOCUMENTATION
CALLER_CLAIM
```

Precedence rules:

1. D1 classification, authorization, destination and local hard restrictions
   are never widened by provider evidence.
2. A lower-authority source cannot override a higher-authority source for the
   same exact subject, dimension, purpose, material class and policy epoch.
3. A conflict between two observations of the same authority class produces
   `CONTRADICTED`; it does not choose the newest observation silently.
4. A restrictive local policy wins a conflict even when the provider claims a
   broader capability.
5. `CALLER_CLAIM` is never sufficient for external disclosure.

Each observation MUST use the machine-readable
`PMIRI_GD-R2-07_PROVIDER_POLICY_OBSERVATION.schema.json` schema. The corrected
schema revision is `0.2` and requires a non-negative
`invalidation_epoch`. It also requires the exact `freshness_profile_id` and
`freshness_profile_fingerprint` from the authority matrix. The profile
fingerprint covers the immutable age boundaries and revalidation triggers.
The epoch and profile identity are part of the observation fingerprint and
must be compared with the current policy epoch/profile before the observation
can be used.

## 3. Policy dimensions

The required dimension matrix is maintained in:

```text
PMIRI_GD-R2-07_PROVIDER_POLICY_AUTHORITY_MATRIX.json
```

The dimensions are independent:

```text
destination_identity
retention_deletion
training_use
subprocessors
processing_region
feature_capability
structured_output_attachment
logging_diagnostics
credential_operation_scope
redirect_fetch_behavior
```

Evidence for one dimension cannot satisfy another dimension.

`observed_value` is a closed tagged union in
`PMIRI_GD-R2-07_PROVIDER_POLICY_OBSERVATION.schema.json`. The tag
`value_type` MUST equal the enclosing `policy_dimension` exactly, and each
dimension has its own typed fields: destination identity, retention/deletion,
training use, subprocessors, processing region, feature capability,
structured output/attachment, logging/diagnostics, credential operation
scope, and redirect/fetch behavior. An untyped value or a value tagged for a
different dimension is `INTERNAL_CONTRACT_INVALID`.

## 4. Freshness profile

The baseline profile is versioned as `D2-POLICY-FRESHNESS-001`. Its exact
profile fingerprint is
`604dd146196571cf7dd5d25eec7d8db066cebbeca07814ccfe647c9edd267d41` and is
the SHA-256 of the canonical compact JSON payload
`{freshness_profile_id,dimensions}` from the authority matrix, encoded as
UTF-8 with no trailing newline:

| Dimension | Maximum age | Revalidation boundary |
|---|---:|---|
| destination_identity | 5 minutes | every request, redirect or authority change |
| credential_operation_scope | 5 minutes | every operation and credential epoch change |
| redirect_fetch_behavior | 15 minutes | every redirect, retry or endpoint change |
| subprocessors | 1 hour | policy epoch or subprocessor-set change |
| processing_region | 1 hour | region/endpoint change |
| structured_output_attachment | 1 hour | feature/profile change |
| feature_capability | 24 hours | model/feature/policy-version change |
| retention_deletion | 24 hours | provider policy-version change |
| training_use | 24 hours | provider policy-version change |
| logging_diagnostics | 24 hours | provider policy-version change |

An authority may shorten a window but may not lengthen it without a new
accepted policy version. The observation is stale when `now > valid_until`,
when the maximum-age window is exceeded, or when the relevant invalidation
epoch changes.

## 5. Required decision algorithm

For the exact subject, purpose, material class, feature profile and time:

1. collect all observations for required dimensions;
2. discard observations that are out of scope, malformed, revoked or invalid;
3. apply authority precedence and detect same-authority contradictions;
4. require the matrix minimum authority for every required dimension;
5. evaluate age, `valid_until`, policy version and invalidation epoch;
6. emit a canonical evidence state and final action result;
7. bind all selected observation fingerprints into the decision fingerprint.

Missing, stale or contradictory required policy yields no external permission.

An operation or purpose not present in the canonical vocabulary has no
implicit dimension set. It is an `INTERNAL_CONTRACT_INVALID` condition and
maps to `DENY` or `REQUIRE_REVIEW` before external disclosure. This is the
closed-world default for policy coverage.

## 6. Fail-closed mapping

```text
required dimension missing       → evidence UNKNOWN / action DENY or LOCAL_ONLY
required dimension stale          → evidence STALE / action REQUIRE_REVALIDATION
revoked observation               → evidence REVOKED / action DENY
same-authority conflict           → evidence CONTRADICTED / action REQUIRE_REVIEW
lower authority only              → evidence UNKNOWN / action DENY
exact subject mismatch            → evidence INVALID / action DENY
all dimensions fresh and covered → continue to D2 egress evaluation
```

`ALLOW` is possible only after the D1 intersection, exact trust/capability
checks and all required dimensions pass. A provider's positive statement does
not bypass local classification or the final emission fence.

## 7. Historical and cache rules

An observation is immutable evidence. A policy update creates a new
observation and invalidation epoch; it does not mutate the old record.

A cached policy decision MUST bind:

```text
subject binding
purpose
material class/profile
selected observation set
policy version
freshness profile ID and fingerprint
invalidation epoch
validity interval
```

Any mismatch requires re-evaluation.

Every derived or cached D2 decision that depends on provider-policy freshness
MUST carry the same profile ID and fingerprint, including trust decisions,
capability decisions, outbound network decisions and the integrated decision
envelope. A missing or mismatched profile identity is
`INTERNAL_CONTRACT_INVALID` and cannot authorize external disclosure.

## 8. Acceptance boundary

This contract closes the documentary definition of authority precedence and
freshness, but it does not prove provider truth, runtime enforcement or D2
acceptance. Those remain future review/evidence work.
