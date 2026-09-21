# PMIRI — Gate D Round 2 — Hard Contract Review Report

**Version:** 0.1  
**Review status:** `FIX-FIRST`  
**Reviewer role:** documentation hard review; not independent acceptance  
**Implementation authorization:** `NOT GRANTED`  
**Review date:** 2026-09-11

## 1. Executive verdict

The D2 candidate package is **not ready for acceptance**. The security
direction is appropriate, but the package is still a prose-level design with
multiple cross-document ambiguities. The largest blocker is the absence of
canonical machine-readable contracts for the records that are supposed to be
fingerprinted, validated and consumed at the final emission fence.

Current disposition:

```text
D2 candidate package = FIX-FIRST
D2 acceptance         = NOT GRANTED
implementation        = NOT GRANTED
runtime evidence      = NOT PRESENT / NOT REQUESTED
```

This review does not change Gate A, B or C status. It also does not convert the
existing Gate-C semantic acceptance into executable closure evidence.

## 2. Review scope and method

The review compared the D2-01 through D2-04 candidate contracts, the
integrated model and adversarial matrix against:

- `PMIRI_ALL_DOCUMENTATION_CHECKPOINT_15/SOURCE_AUTHORITY/00_DOCUMENTATION_AUTHORITY.md`;
- `PMIRI_ALL_DOCUMENTATION_CHECKPOINT_15/SOURCE_AUTHORITY/08_GATE_D_ENTRY_CONTRACT.md`;
- the D2 package's own cross-object bindings, state/action vocabulary,
  fail-closed rules and scenario requirements.

The test was contractual rather than operational: can a future producer emit a
single canonical record, can a validator reject an invalid record, and can an
independent reviewer trace the decision to exact accepted authority inputs?
No provider, connector, DNS, network or runtime action was performed.

## 3. Finding summary

| ID | Severity | Area | Disposition |
|---|---|---|---|
| F-D2-01 | BLOCKER | Canonical machine-readable contracts | Add schemas, canonical serialization and schema fingerprints |
| F-D2-02 | BLOCKER | Decision vocabulary | Separate state, action, lifecycle and reason enums |
| F-D2-03 | BLOCKER | Authority and lineage | Add exact accepted D1/Gate-C authority refs and hashes |
| F-D2-04 | BLOCKER | Provider-policy authority/freshness | Define source precedence, required dimensions, TTL and conflict rules |
| F-D2-05 | HIGH | Connector credentials | Add typed secret-use and isolation boundary |
| F-D2-06 | HIGH | DNS/connection/TLS evidence | Bind policy decision to actual connection identity |
| F-D2-07 | HIGH | Redirect/resource limits | Add versioned deterministic limit and hop records |
| F-D2-08 | HIGH | Redaction determinism | Add obligation × transformation decision matrix |
| F-D2-09 | HIGH | Fetched-content lifecycle | Define quarantine, admission and downstream visibility |
| F-D2-10 | HIGH | Adversarial coverage | Expand to traceable positive/adversarial fixture coverage |
| F-D2-11 | MEDIUM | D2 scope taxonomy | Align D2-05 naming and declared scope |

The machine-readable details are in
`PMIRI_GD-R2_HARD_CONTRACT_REVIEW_FINDINGS_v0.1.json`.

## 4. What is good enough at the documentary level

The following parts are directionally correct and should be preserved during
the next revision:

- provider trust is destination-, purpose-, material- and time-specific;
- parent provider trust does not automatically authorize a model, feature,
  endpoint or subprocessor;
- capability freshness and invalidation are treated as security inputs;
- the constrained egress artifact is separated from the provider-neutral
  compiled context;
- network access defaults to deny, redirects are revalidated, private/local
  addresses are denied and fetched attachments are quarantined;
- hidden retrieval and evidence resurrection are explicitly prohibited;
- later D2 stages are not allowed to widen earlier authority, purpose,
  classification or destination bindings;
- all reviewed files preserve candidate-only status and do not authorize
  implementation.

These are design intentions, not proof of enforcement.

## 5. Critical findings

### F-D2-01 — No canonical machine-readable D2 contracts

The YAML blocks in D2-01, D2-02, D2-03 and D2-04 describe useful fields, but
they are not schemas and do not define required/optional semantics, enum
domains, nullability, canonical ordering, normalization or fingerprint input.
The adversarial matrix is the only machine-readable D2 artifact and it does not
validate the records it expects.

This is a release blocker because the D2 design repeatedly relies on exact
fingerprints and independently reviewable decisions.

Required closure: add versioned schemas and canonical serialization for trust
assertions, capability observations/decisions, constrained artifacts and
transformation impacts, network decisions, credentials and the final integrated
decision envelope.

### F-D2-02 — State and action outputs are still mixed

The integrated document correctly recognizes the distinction between state and
action, but the component documents and matrix do not consistently apply it.
`STALE`, `FRESH`, `DEGRADED`, `UNSATISFIABLE`, `QUARANTINE` and `bounded abort`
appear alongside authorization results such as `ALLOW` and `DENY`.

Required closure: use separate typed fields for evidence state, final action,
content lifecycle and reason class. A final emission fence must consume one
canonical action result; component state must be input to that result, not a
substitute for it.

### F-D2-03 — Accepted authority lineage is named but not bound

D2-01 lists D1 object names and D2-05 lists required fingerprints, but there is
no exact authority bundle identifying the accepted versions and SHA-256 hashes
of the Gate-C emission-fence/egress contracts and D1 R1 objects consumed by
the candidate.

Required closure: publish the exact authority bundle and bind its fingerprint
into the D2 candidate manifest, schemas, matrix and decision envelope.

### F-D2-04 — Provider policy freshness is not deterministic

The policy dimensions are listed, but the candidate does not decide which
authority wins when a provider policy, registry assertion and connector
observation disagree. It also does not define dimension-specific freshness
windows or the minimum observation set required for each operation and material
class.

Required closure: specify authority precedence, required dimensions, freshness
profiles, contradiction handling, revocation and fail-closed outputs.

## 6. High-priority findings

F-D2-05 through F-D2-10 prevent a reliable security implementation even after
the blockers are fixed:

- the credential boundary does not define secret injection, visibility,
  operation binding, rotation or log/output exclusion;
- the DNS/network contract does not create a verifiable attestation linking
  resolver result, selected socket target, proxy path and TLS identity;
- redirect and resource limits have no exact versioned policy profile;
- redaction impact does not deterministically map an obligation to an action;
- fetched content has quarantine intent but no enforceable admission lifecycle;
- the matrix does not yet satisfy its own positive-plus-adversarial coverage
  requirement and lacks fixture/schema traceability.

Each item is detailed in the findings JSON and must be closed before a D2
recheck can recommend acceptance.

## 7. Scope issue

The integrated artifact is named and numbered D2-05 and contains a D2-05-A
race scenario, while the candidate index and matrix declare only D2-01 through
D2-04. This must be made explicit as either a cross-cutting integration
artifact or a separately governed D2-05 workstream. The ambiguity is currently
medium severity, but it must be resolved before the package is frozen.

## 8. Proven versus not proven

Documentarily present:

- candidate-only status and implementation block;
- fail-closed intent for missing, stale, revoked, contradicted and invalid
  policy inputs;
- non-widening integration principle;
- default-deny network and no-hidden-retrieval intent.

Not proven:

- runtime enforcement or provider/connector behavior;
- credential isolation or secret non-disclosure;
- DNS rebinding, redirect, TLS, IPv4/IPv6 or SSRF enforcement;
- canonical D2 serialization and replayable fixtures;
- D2 acceptance or production readiness.

## 9. Recheck exit criteria

The next review may reconsider `FIX-FIRST` only after:

1. all four blocker findings are closed;
2. high findings have deterministic schemas, mappings and matrix coverage;
3. state/action/lifecycle vocabularies are canonical and non-overlapping;
4. exact accepted D1 and Gate-C authority fingerprints are bound;
5. a separate independent reviewer can validate the documentary package
   without resolving ambiguities by personal interpretation.

Until then, Gate D2 remains an open candidate design gate and production
implementation, ingestion, migration and external access remain blocked.
