# PMIRI implementation plan

This implementation is deliberately staged. The documentation archive is kept
unchanged under `PMIRI_ALL_DOCUMENTATION_CHECKPOINT_17/`.

## Stage 0 — V1-S0 (implemented in this workspace)

1. Immutable/content-addressed local source registration.
2. Project-bounded deterministic lexical retrieval.
3. Evidence items with source/version/anchor lineage.
4. Conflict and coverage preservation through bounded context compilation.
5. Typed local output and deterministic rendering.
6. Twelve VS-01..VS-12 acceptance tests.

## Stage 1 — GC-C1 execution boundary (implemented as fail-closed tooling)

1. Pinned runner identity and SHA-256 declaration checks.
2. Preflight record with all PF-01..PF-16 checks.
3. Isolation attestation normalization; declarations are not treated as proof.
4. Case-scoped artifact sealing and manifest generation.
5. Schema-shaped blocked evidence inventory for all 17 R-FC obligations.
6. Replay orchestration remains blocked unless an external clean-room attestation
   and independent reviewer identities are supplied.
7. Local subprocess handoff adapter with fresh roots, deterministic environment,
   Windows Job Object limits, bounded wall time and teardown inspection; this
   adapter cannot self-attest the required clean-room boundary.
8. Attested R-FC candidate runner for all 34 declared cases, with per-case
   handler dispatch, digest-bound handler-module manifest verification, oracle
   comparison, evidence-schema validation, persisted sealing and no automatic
   PASS promotion.
9. PMIRI-backed local synthetic handler suite for all 34 declared cases, kept
   separate from the attested runner and independently checked as local-only
   candidate evidence.
10. Standalone digest-bound 34-case handler manifest materialized for handoff
    and checked against the catalog and source fingerprint by readiness.

## Stage 2 — Gate-D decision boundaries (runtime enforcement core)

1. Closed operation/purpose/action/lifecycle vocabulary.
2. Fail-closed trust, capability, lifecycle and network decision validation.
3. Exact subject/delegation intersection, purpose binding and non-ordinal
   classification/derived-sensitivity rules.
4. HTTPS canonicalization and private/mixed-DNS denial logic.
5. Final epoch/fingerprint emission fence and schema-valid integrated envelope.
6. Deterministic in-memory provider/connector transport seam; no real external
   transport is enabled by default.
7. Local synthetic execution of all 34 D2 fixture scenarios with oracle
   comparison; documented runtime blocking remains unchanged.
8. Leak-safe caller disclosure projection for authorized/unauthorized reads.
9. Opt-in encrypted trace retention with role access and TTL purge; raw
   capture remains disabled by default.
10. Trusted-boundary request authorization for API/MCP reads: principal and
    trust-zone binding, exact scope/purpose/epoch checks, replay protection,
    rate limiting and existence-safe disclosure.
11. Server-derived request authorization binding carried through the Gate-D
    integrated envelope and revalidated against the exact authorization request
    before provider/connector transport.
12. Optional durable policy epoch shared by Gate-D invalidation and request
    authorization workers, with transactional epoch bump semantics.
13. Read-only deployment-readiness report with a closed profile contract,
    SQLite/control-plane health probes, candidate-artifact checks and explicit
    external hard blockers.
14. Local deployment/recovery smoke harness covering fixture ingest, query,
    fingerprint-verified backup/restore and control-plane bootstrap.

## Stage 3 — Controlled runtime and production hardening (in progress)

1. Release reproducibility and candidate operations: exact runtime/build
   dependency lock, stdlib-only lock verification, explicit setuptools package
   discovery, canonical-epoch deterministic SPDX SBOM/supply-chain verification,
   direct candidate SBOM audit, offline wheel
   smoke, a stdlib-only hash-pinned mirror verifier and deterministic
   hash-lock builder, CI verification and an
   operations runbook are implemented. The release helper now verifies the
   selected interpreter against the exact lock before sealing and can install
   only from an explicitly supplied offline mirror. Deployment artifacts are
   re-sealed
   automatically before the local smoke readiness probe, preventing stale-
   manifest false negatives. The actual trusted package-mirror lock remains an
   explicit deployment input. Case sealing excludes analysis caches, build
   metadata, live runtime audit output and derived handoff transfer trees so
   the evidence inventory stays scoped to candidate artefacts, and ignores
   symlinks so a case cannot hash content outside its root. A signed
   candidate audit also checks the installed runtime against the exact lock,
   while the GC-C1 launcher resolves Windows venv redirectors to their recorded
   base interpreter so a strict one-process Job Object remains enforceable. A
   signed external-evidence verifier now provides
   the fail-closed input path for EXT-01..EXT-06 without fabricating local
   deployment observations.
   The PMIRI-backed local R-FC handler suite now executes all 34 declared cases
   and records oracle matches without changing the external attestation/review
   boundary.
   A bounded `review-package` artifact now consolidates the local acceptance
   inventory and external-review checklist with fingerprints, without making
   any external readiness or acceptance claim.
   Its closure matrix now makes the remaining work explicit in one ordered
   artifact: local release/candidate/security/verification work is separated
   from EXT-01..EXT-06 deployment prerequisites and FA-01..FA-06 final
   acceptance actions; blocked entries retain their next handoff action.
   CI now repeats the fresh candidate bootstrap and verifies the expected
   external-only readiness block, source-bound review package and in-project
   handoff manifest in the same smoke → readiness → review → handoff order as
   the operations runbook. Review-package construction also rejects a preflight
   record unless its PF-01..PF-16 contract is complete and ordered.
   The CI workflow gate sequence is also asserted by an automated contract
   test so locked install, package smoke, fail-closed readiness, review,
   handoff and integrity gates cannot silently disappear from the workflow.
   The workflow fixes `SOURCE_DATE_EPOCH` and compares two independently built
   wheel hashes so package reproducibility is an enforced gate, not only a
   local observation. It installs the selected wheel into a clean target,
   exports that target through `GITHUB_ENV`, and performs the first import from
   outside the checkout so later workflow steps cannot silently fall back to
   the source tree. Runtime CLI steps execute from the runner temp directory
   with absolute workspace and artifact output paths, while the test runner
   keeps the repository cwd for relative authority/fixture contracts and
   removes the empty `sys.path[0]` entry so the installed wheel remains first.
   A separate `final-acceptance` gate now follows readiness and requires a
   controlled signed assertion set for D2 acceptance, R-FC 17/17 PASS,
   migration/restore/failover, independent review and operations approval;
   local CI asserts the exact FA-01..FA-06 blocked state. The
   `create_release_candidate.ps1` helper provides the equivalent local release
   order: bootstrap handoff, full tests, fresh seal, final immutable handoff
   and exact candidate audit.
2. The closed deployment profile now binds the read-server transport, loopback
   host, port, request limit and project-local audit path. Loopback-only
   authenticated HTTP read boundary is implemented over the
   shared seven-operation service with bounded JSON input, generic error
   responses, operation binding, low-sensitivity metrics and loopback-only
    construction. A packaged `serve-local` assembly consumes this profile and
    wires SQLite storage, control-plane, audit and metrics. Its
    `ServerAuthorizationAdapters` seam also accepts deployment-owned
    identity/revocation and distributed coordination ports plus an optional
   blob-cipher adapter, validates their method surface and current epoch, and
   avoids creating a second local control plane when injected. The registry,
   replay, rate-limit and policy-epoch ports are explicit public Protocols.
   Adapter outages, invalid epochs and malformed blob ciphers fail closed at
   construction. Public hosting, TLS termination and deployed identity remain
   external seams.
3. Redacted, fingerprinted local audit events are implemented for accepted and
   rejected HTTP reads; audit persistence is fsync’d and emission fails closed
   when the configured sink cannot write.
4. A materialized clean-room/review handoff bundle is implemented. It copies
   the synthetic fixture, pinned runner, authority/schema/matrix inputs,
   implementation and verification sources, exact lock/SBOM and candidate
   evidence into a no-overwrite, per-file fingerprinted bundle whose status is
   `HANDOFF_READY_FOR_EXTERNAL_REVIEW`; external attestation and review remain
   explicitly absent.
   The review package validator also re-derives its self-fingerprinted
   inventory from the current candidate reports, preventing a resigned
   package from claiming a different readiness or acceptance state.
   `scripts/build_signed_evidence.py` packages only explicitly supplied,
   reviewer-separated EXT-01..EXT-06 or FA-02..FA-06 observations, self-
   verifies the signature and refuses final packaging against blocked or
   mismatched readiness; it does not observe or fabricate deployment state.
   `scripts/verify_deployment_closure.py` then evaluates both gates in memory
   against the supplied bundles and returns success only for the complete
   `DEPLOYMENT_CLOSURE_READY` state, without rewriting candidate artifacts.
5. Replaceable production storage and migration design; a transactional SQLite
   adapter, JSON/blob history migration, read-only migration dry-run, verified
   no-overwrite restore rehearsal and canary/rollback runbook are implemented,
   while deployment and operational approval remain.
   The request-authorization control plane also has a transactional SQLite
   adapter for local multi-process revocation, epoch, replay and rate-limit
   state.
   SQLite content blobs additionally support an explicit versioned AES-GCM
    cipher adapter; metadata/volume encryption and the real KMS/DPAPI key
    escrow remain deployment decisions. The optional `KeyEscrowAdapter`
    receives only a key fingerprint and must succeed before a rotated version
    becomes active. DPAPI key creation is serialized per domain, trace
    identifiers are format-closed, and SQLite replay/limiter/epoch invariants
    are covered under concurrent workers.
6. Controlled-environment clean-room launcher integration with independently
   verifiable OS/network/filesystem controls; the local subprocess adapter is
   present but does not satisfy this external-observation requirement.
7. Controlled GC-C1 replay and independent review evidence.
8. Provider/connector selection, credential injection and network transport only
   after an explicit authority and deployment decision.
9. Gate-D R2 independent recheck and controlled D2/R-FC execution.
10. Replace the local authentication registry with the deployed identity and
   revocation integration, and replace local SQLite coordination with a
   distributed control plane, after their authority and operational contracts
   are approved.
11. Execute the readiness report in the target deployment, supply independently
   verifiable identity/key/clean-room/review evidence, then perform controlled
   migration, backup/restore and Gate-D/R-FC rechecks. Produce the separately
   signed final-acceptance evidence and pass the FA-01..FA-06 gate only after
   those claims have been independently observed and approved.

## Stage 4 — External closure sequence (remaining work)

This stage is intentionally a handoff plan, not a local simulation. The
workspace must remain fail-closed until each result below is independently
observed in the authorized deployment and bound into the signed evidence
bundle.

1. **Transfer and freeze the candidate.** Transfer the latest immutable
   `handoff-release-vN` bundle to the authorized clean-room. Verify its
   manifest, payload fingerprints, profile fingerprint, authority fingerprint,
   lock and SBOM before execution; do not rebuild or edit the bundle in place.
2. **Prove the execution boundary (EXT-01).** Run PF-01..PF-16 with the
   controlled launcher and obtain an independently signed OS/filesystem/network
   isolation attestation. Bind the attestation to the exact profile, authority,
   runner package and case fingerprints.
3. **Bind deployment-owned security services (EXT-02..EXT-04).** Inject the
   approved identity/revocation gateway, distributed control-plane and
   KMS/DPAPI/key-escrow adapters. Exercise revocation, replay, rate-limit,
   policy-epoch failover, metadata/volume encryption, key rotation/escrow and
   encrypted restore; record signed observations and operational ownership.
4. **Authorize real transport (EXT-05).** Only after the previous gates pass,
   perform the approved provider/connector run. Capture resolver results,
   selected-address pinning, TLS identity, revalidation, credential boundary,
   response limits and teardown evidence. Any mismatch must stop the run and
   leave readiness blocked.
5. **Execute controlled acceptance (FA-02..FA-05 / EXT-06).** Run all 34 D2
   scenarios and all 17 R-FC obligations with the pinned handlers and clean-room
   records. Obtain separate independent Gate-D R2 and D2/R-FC reviewer records;
   R-FC may be reported as `PASS` only when all 17 obligations are accepted by
   the independent reviewer.
6. **Promote only at final acceptance (FA-01, FA-04, FA-06).** Re-run
   readiness against the signed external evidence, repeat deployment-owned
   migration/backup/restore/failover checks, obtain operations-owner approval,
   and run `final-acceptance`. The only acceptable terminal state is
   `DEPLOYMENT_READY` plus `FINAL_ACCEPTANCE_READY`; otherwise preserve the
   blocker, evidence references and next handoff action.

## Explicit non-claims

This workspace does not claim Gate-C R-FC PASS, D2 acceptance, production
readiness, final acceptance, OS-level sandboxing or external provider authorization. Those claims
require the controlled replay and independent review described by the archive.
