# PMIRI — Gate D Entry Contract

**Status:** AUTHORIZED NEXT DESIGN GATE / NOT IMPLEMENTATION AUTHORIZATION

## Mission

Gate D defines the concrete security, privacy, authorization, disclosure and provider-egress policy layer consumed by accepted Gate-B/Gate-C interfaces.

## Required topics

### D-01 — Principal / trust-zone / service identity policy
Define authoritative authentication-to-principal and trust-zone policy inputs for `RequestAuthorizationBinding`.

### D-02 — Security-label and canonical-access joins
Define how PUBLIC / CLOUD_OK / RESTRICTED / LOCAL_ONLY and canonical record/source access bindings produce purpose/destination-specific decisions without treating labels as a numeric ladder.

### D-03 — EgressDecision policy
Define provider/model/feature allow/constraint/deny rules, validity/freshness and policy-version semantics.

### D-04 — ExternalReadDisclosureProjection
Define leak-safe caller projections for all read-only operations, including nonexistence vs inaccessible-existence indistinguishability.

### D-05 — Provider capability freshness authority
Define trusted capability sources, freshness windows, invalidation and fail-closed behavior for fit-critical provider/model facts.

### D-06 — Redaction / constrained-egress policy
Define allowed destination-specific removals/transforms and when they require `EgressConstrainedContextArtifact`, degrade, deny or new retrieval.

### D-07 — Encryption / key / storage-domain policy
Define encryption-at-rest/in-transit, key-domain separation and secrets handling.

### D-08 — Trace / forensic retention
Define opt-in raw query/context/candidate capture policy, encryption, TTL, access and deletion.

### D-09 — Connector/provider boundary security
Define connector credentials, provider trust assumptions, SSRF/content-fetch boundaries and external resource access controls.

### D-10 — Security hard review
Attack existence leaks, confused-deputy flows, stale authorization, cross-project enumeration, capability substitution, provider leakage and forensic-trace misuse.

## Constraints

Gate D MUST NOT redefine Gate-B truth/current-state semantics or Gate-C retrieval relevance/context semantics.

Production implementation remains blocked.
