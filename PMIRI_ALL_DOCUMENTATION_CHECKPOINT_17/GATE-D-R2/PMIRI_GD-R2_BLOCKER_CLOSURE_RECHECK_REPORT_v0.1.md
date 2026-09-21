# PMIRI — Gate D Round 2 — Blocker-Closure Structural Recheck

**Version:** 0.1  
**Status:** `STRUCTURAL CLOSURE / INDEPENDENT RECHECK REQUIRED`  
**Gate:** D2  
**Implementation authorization:** `NOT GRANTED`

## 1. Review boundary

This is an author/operator documentary recheck of the prior
`PMIRI_GD-R2_HARD_CONTRACT_REVIEW_REPORT_v0.1.md` and its 11 findings. It is
not an independent acceptance review, runtime test, provider verification or
Gate-C replay.

The active lineage manifest is
`PMIRI_GD-R2_AUTHORITY_BUNDLE_MANIFEST_v0.1.json`. Its fingerprint binds the
accepted Gate-C and Gate-D R1 archives and the D2 candidate member set.

## 2. Structural disposition

| Finding | Structural disposition | Evidence added or changed | Runtime limitation |
|---|---|---|---|
| F-D2-01 | ADDRESSED | Versioned schemas for trust assertion/decision, capability observation/decision, redaction transformation/artifact, typed constraint, connection binding, network decision, lifecycle and integrated envelope; matrix schema refs | No producer validation or replay fixture executed |
| F-D2-02 | ADDRESSED | Canonical vocabulary separates trust/capability state, obligation impact, action result, content lifecycle and reason class | No runtime emission-fence execution |
| F-D2-03 | ADDRESSED | Exact Gate-C/D1 authority members and hashes in authority manifest; decision schemas bind manifest fingerprint | Hash identity does not prove semantic or runtime enforcement |
| F-D2-04 | ADDRESSED | Provider-policy authority precedence, dimension matrix, freshness windows, contradiction and fail-closed rules | No real provider policy was verified |
| F-D2-05 | ADDRESSED | Typed connector credential boundary with operation/audience scope, injection channel, visibility prohibitions, epoch and rotation/revocation refs | No secret injection or isolation test performed |
| F-D2-06 | ADDRESSED | Connection binding records resolver/address/IPv4/IPv6/selected target/proxy/TLS and revalidation events | No DNS, socket, proxy or TLS test performed |
| F-D2-07 | ADDRESSED | Versioned resource-limit profile with exact baseline values and typed terminal mapping | No network request or limit fixture executed |
| F-D2-08 | ADDRESSED | Typed constraint schema plus obligation/transformation impact-action matrix | No redaction implementation or citation replay |
| F-D2-09 | ADDRESSED | Fetched-content lifecycle schema, quarantine states, typed-data admission predicate and retrieval visibility boundary | No attachment fetch, parser or quarantine runtime executed |
| F-D2-10 | ADDRESSED | 17 required classes × positive/adversarial cases = 34 traceable documentary scenarios with schema refs and blocked reasons | All fixture IDs remain null by design |
| F-D2-11 | ADDRESSED | D2-05 explicitly declared as a cross-cutting integrated decision/emission-fence race artifact | It creates no new implementation scope |

## 3. Consistency assertions

- `action_result` is the only permission-bearing field in D2 decision records.
- `STALE`, `UNKNOWN`, `CONTRADICTED`, `INVALID`, `UNSATISFIABLE` and
  `QUARANTINED` are not action-result values.
- Each D2 decision/artifact that can authorize or constrain a downstream
  operation binds `authority_manifest_fingerprint`.
- Provider-policy observations cannot widen D1 authorization or classification.
- Fetched external content is data; it cannot become PMIRI control text.
- A manifest/hash match is identity evidence only and cannot be reported as a
  runtime PASS.

## 4. Recheck result

The prior 4 BLOCKER and 7 HIGH/MEDIUM findings are structurally addressed in
the candidate documentation set. The package remains `CANDIDATE`; an
independent reviewer must verify the exact hashes, schema semantics, matrix
coverage and cross-round references before any D2 acceptance decision.

Still not proven:

- Gate-C replay/clean-room closure;
- runtime schema validation against producers;
- provider-policy truth;
- connector credential isolation;
- DNS/SSRF/TLS/redirect/resource-limit enforcement;
- fetched-content quarantine behavior;
- D2 acceptance, production readiness or implementation authorization.
