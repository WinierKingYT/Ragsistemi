# PMIRI — GC-C1-01 Gate C Evidence Matrix

**Version:** 0.1  
**Status:** \`DRAFT / EVIDENCE DESIGN ONLY\`  
**Gate:** C.1 — Closure Evidence Hardening  
**Implementation authorization:** \`NOT GRANTED\`

## 1. Purpose

This matrix converts the Gate-C final cross-round claims \`R-FC-01\` through
\`R-FC-17\` into replayable evidence obligations.

This document does not re-open Gate-C semantics, authorize Gate D, or declare
any check \`PASS\`. Every row begins as \`UNVERIFIED\` until the evidence contract
in Section 4 is complete and an independent replay succeeds.

## 2. Scope boundary

Allowed in GC-C1-01:

- define evidence records;
- define adversarial fixtures and expected outcomes;
- map each R-FC check to required artifacts;
- identify missing replay, hashing, privacy, and independent-review data;
- record package and authority dependencies.

Forbidden in GC-C1-01:

- production implementation;
- production ingestion or migration;
- Gate-D policy design;
- retrieval, ranking, compiler, or provider changes;
- changing Gate-B truth/current-state semantics;
- converting a prose assertion into \`PASS\` without replay evidence.

## 3. Evidence status vocabulary

\`\`\`text
UNVERIFIED       Matrix obligation exists; no acceptable replay evidence yet.
READY_FOR_REPLAY Fixture and oracle are defined; runner is not yet accepted.
PASS             Replay passed and independent review accepted the evidence.
FAIL             Replay contradicted the oracle or exposed a contract defect.
BLOCKED          Required authority, fixture, runner, or dependency is missing.
\`\`\`

\`PASS\` is not permitted when only a Markdown conclusion exists.

## 4. Required evidence record

Every replay result MUST produce one evidence record with all required fields:

\`\`\`yaml
evidence_id: <stable unique id>
check_id: R-FC-01..R-FC-17
matrix_version: 0.1
authority_refs:
  - <exact immutable Gate-C source ref/hash>
fixture:
  fixture_id: <stable id>
  input_fingerprint: <hash>
  privacy_class: <classification>
action_trace:
  - step: <number>
    operation: <operation>
    input_ref: <artifact ref>
    state_change_or_fault: <fault injection or state transition>
oracle:
  expected_disposition: <typed expected result>
  forbidden_dispositions: [<result>]
actual:
  disposition: <typed actual result>
  output_artifact_ref: <artifact ref>
  output_fingerprint: <hash>
lineage:
  authorization_lineage_ref: <ref>
  evidence_refs: [<ref>]
  citation_refs: [<ref>]
replay:
  runner_id: <immutable runner id>
  runner_version: <version>
  command_or_workflow_ref: <replay ref>
  environment_fingerprint: <hash>
review:
  primary_reviewer: <identity>
  independent_reviewer: <different identity>
  review_result: <accepted|rejected|blocked>
  review_evidence_ref: <ref>
captured_at: <UTC timestamp>
status: <UNVERIFIED|READY_FOR_REPLAY|PASS|FAIL|BLOCKED>
\`\`\`

A redacted report may hide sensitive payload values, but it MUST retain stable
fingerprints and enough structure to independently verify the disposition.

## 5. Gate-C recheck matrix

| ID | Adversarial fixture / action | Required oracle | Required evidence | Replay status |
|---|---|---|---|---|
| **R-FC-01** | Create a request with a narrow \`ConstraintEnvelope\`; rewrite it wider; reuse a reference or cursor from another domain. | The rewritten envelope cannot widen access. A reference, cursor, URI, or artifact ID cannot authorize access. The final decision remains bounded by the trusted request authorization lineage. | Original and rewritten envelopes; server-derived binding; lineage chain; denial or bounded-result decision; fingerprints proving the later reference did not alter authorization. | \`UNVERIFIED\` |
| **R-FC-02** | Mix stale, partial, or degraded retrieval partitions and pass them to context packing/provider formatting. | Inherited epistemic coverage ceiling propagates unchanged or becomes weaker. Packing and formatting cannot claim complete evidence coverage. | Retrieval coverage record; mixed-input fixture; inherited ceiling refs at each stage; final context/provider disposition. | \`UNVERIFIED\` |
| **R-FC-03** | Omit candidates from a current-state universe or mark the universe partial/unknown, then request a current answer. | The result remains partial/unknown or is denied. No later layer may present it as a complete current state. | Candidate-universe completeness flag; omitted-candidate fixture; resolution result; context and external projection outputs. | \`UNVERIFIED\` |
| **R-FC-04** | Inject correction, retraction, restriction, or semantic invalidation between retrieval, compilation, handoff, and emission. | The applicable fence blocks, revalidates, or reprojects the output. A previously valid internal result cannot bypass the last boundary check. | Stage-by-stage epoch/state trace; fence decisions; timing/order evidence; blocked or revalidated output fingerprint. | \`UNVERIFIED\` |
| **R-FC-05** | Supply conflicting evidence and remove or hide one side during ranking, budget packing, or destination constraint. | Conflict survives, or the result becomes explicitly degraded, unsatisfiable, or denied. Silent one-sided conflict removal is forbidden. | Conflict fixture; both evidence refs; omission/constrained artifact; obligation disposition; final external result. | \`UNVERIFIED\` |
| **R-FC-06** | Reorder, truncate, transform, and destination-alias cited spans. | Canonical anchor → \`EvidenceItem\` → compiled span → constrained span → provider alias remains traceable without stale positional reuse. | Anchor IDs; span offsets/fingerprints; transform map; constrained citation map; final alias map. | \`UNVERIFIED\` |
| **R-FC-07** | Ask destination fitting or constrained recompilation to recover omitted, denied, or restricted evidence. | The constrained compiler can only select/transform admitted evidence. It cannot retrieve, resurrect, or revive excluded evidence. | Source \`EvidenceSet\`; allowed/excluded refs; constrained artifact; retrieval-call trace proving no implicit retrieval; final disposition. | \`UNVERIFIED\` |
| **R-FC-08** | Substitute provider, model, feature, destination, payload, or profile after producing a destination proof. | Destination binding, payload fingerprint, and profile fingerprint mismatch causes revalidation or denial. Proof substitution cannot succeed. | Original and substituted bindings; proof fingerprints; decision records; denial/revalidation evidence. | \`UNVERIFIED\` |
| **R-FC-09** | Request historical semantics for a record whose current access or restriction state has changed. | Recorded-time meaning remains pinned, but current access/restriction emission checks still apply. Historical state cannot bypass present safety. | Historical cut/recorded-time refs; current restriction epoch; projection/fence result; caller-visible typed result. | \`UNVERIFIED\` |
| **R-FC-10** | Tamper with, widen, replay, or cross-domain a continuation cursor/handle. | Integrity failure, revalidation, or denial occurs. Continuation state never widens constraints and never acts as authorization. | Original constraint descriptor; serialized continuation; integrity proof; tampered/replayed variants; final decisions. | \`UNVERIFIED\` |
| **R-FC-11** | Exercise every declared external read operation: search, fetch, current-state, history, timeline, explain, and status. | Each operation follows internal result → disclosure projection → external typed result → final emission fence. No operation is exempt merely because it is read-only. | Operation inventory; per-operation typed result; projection record; fence record; negative disclosure cases. | \`UNVERIFIED\` |
| **R-FC-12** | Send semantically identical requests through MCP and the protocol-neutral API, including stateless continuation use. | Both adapters use the same server-derived per-request authorization semantics and produce equivalent domain dispositions. Hidden connection-local state cannot affect correctness. | Canonical request; adapter inputs; normalized outputs; authorization bindings; parity diff; stateless replay evidence. | \`UNVERIFIED\` |
| **R-FC-13** | Make MCP prose contradict the structured safety-critical result or provide malformed structured content. | Typed structured state is authoritative. Invalid structured content is rejected; prose cannot override a typed deny, uncertainty, or degraded state. | MCP payload; schema/version; validator output; prose/structured contradiction fixture; transport-neutral comparison. | \`UNVERIFIED\` |
| **R-FC-14** | Attempt canonical/user-domain semantic mutation through a read-only operation, cache, log, wrapper, or provider action. | No canonical or user-domain semantic mutation occurs. Operational traces/caches cannot grant authority or change canonical truth. | Before/after canonical fingerprints; mutation attempt trace; cache/log state; provider action trace; read-only result. | \`UNVERIFIED\` |
| **R-FC-15** | Revoke access or change policy after retrieval but before a direct API/MCP response is emitted. | \`AuthorizationValidityDecision\` plus \`ExternalReadEmissionFence\` blocks or safely reprojects the result. Stale authorization cannot escape. | Pre-retrieval and post-revocation bindings; policy/access epochs; projection/fence decisions; caller-visible output. | \`UNVERIFIED\` |
| **R-FC-16** | Pass a provider-specific constrained artifact into a provider-neutral context path or relabel it as \`CompiledContextArtifact\`. | Type separation or validation rejects the substitution. Provider-specific constraints remain in \`EgressConstrainedContextArtifact\`. | Type/schema identifiers; source artifact refs; attempted substitution; validator output; accepted/denied path. | \`UNVERIFIED\` |
| **R-FC-17** | Put instruction-like, policy-like, or control-like text inside retrieved evidence and pass it through wrappers/transforms. | Evidence remains data with its original trust/content class. Retrieved text cannot become trusted control through context or provider wrapping. | Original class; transformed class; wrapper metadata; control-boundary decision; final provider envelope. | \`UNVERIFIED\` |

## 6. Mandatory negative coverage

The replay set is incomplete unless it contains, at minimum:

- one positive and one adversarial case for every R-FC row;
- stale/revoked state between retrieval and emission;
- partial and unknown coverage states;
- conflicting evidence with one-sided omission pressure;
- tampered continuation and substituted destination proof;
- MCP/API parity under stateless execution;
- malformed structured output and prose contradiction;
- evidence/control-class confusion;
- privacy-safe reporting of inaccessible existence;
- clean-room replay with no hidden session state.

## 7. Current blockers to a real PASS

The following must be resolved before any row can become \`PASS\`:

1. Exact immutable authority references for the accepted R1/R2/R3 contracts.
2. A machine-readable schema registry for the named artifacts and dispositions.
3. A replay runner or workflow with a pinned version and environment fingerprint.
4. Explicit semantics for the currently ambiguous optional fields:
   \`SemanticResolutionEpoch coverage?\` and \`continuation integrity ref?\`.
5. An explicit fail-closed rule for \`INDETERMINATE\`.
6. A complete external-boundary inventory, including errors, pagination,
   streaming, cache, and continuation paths.
7. Atomic or otherwise bounded fence validity semantics for the final emission
   race.
8. An independent reviewer and review artifact for each accepted replay.
9. A complete package manifest that allows the authority chain to be rebuilt.

## 8. GC-C1-01 exit criteria

GC-C1-01 may close only when:

- all 17 rows have at least one accepted positive and one accepted adversarial
  fixture;
- every evidence record contains the required fields in Section 4;
- every replay is reproducible in a clean environment;
- no safety-critical field remains semantically optional or marked with \`?\`;
- \`INDETERMINATE\` behavior is explicitly fail-closed or otherwise normatively
  bounded;
- the independent reviewer is separate from the author/operator;
- the full authority and dependency package is hash-verifiable;
- the final disposition is supported by artifacts, not only prose.

Until then, Gate C remains semantically accepted but closure evidence is
\`NOT YET HARDENED\`.

