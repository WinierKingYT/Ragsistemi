# PMIRI implementation status

**Current status:** `S0_IMPLEMENTED / D2_STANDARD_SCHEMA_VALIDATOR_IMPLEMENTED / GATE-D_RUNTIME_CORE_IMPLEMENTED / GATE-D_TRANSPORT_ADAPTER_IMPLEMENTED / GATE-D_REQUEST_AUTH_IMPLEMENTED / GATE-D_EMISSION_BINDING_IMPLEMENTED / GATE-D_DURABLE_CONTROL_PLANE_IMPLEMENTED / GATE-D_SHARED_EPOCH_IMPLEMENTED / GATE-D_STORAGE_ENCRYPTION_IMPLEMENTED / KEY_ESCROW_ADAPTER_IMPLEMENTED / GATE-D_NETWORK_CANONICALIZATION_ENFORCED / GATE-D_CONNECTION_BINDING_ENFORCED / GATE-D_TYPED_OBSERVATIONS_AND_LIFECYCLE_ENFORCED / GC-C1_LAUNCHER_ADAPTER_IMPLEMENTED / GC-C1_R-FC_CANDIDATE_RUNNER_IMPLEMENTED / GC-C1_LOCAL_R-FC_HANDLERS_IMPLEMENTED / GC-C1_HANDLER_MANIFEST_PINNING_IMPLEMENTED / GC-C1_PREFLIGHT_PACKAGE_HARDENED / SIGNED_DEPLOYMENT_EVIDENCE_VERIFIER_IMPLEMENTED / SIGNED_DEPLOYMENT_EVIDENCE_CONTRACT_HARDENED / SIGNED_EVIDENCE_BUILDER_IMPLEMENTED / UNSIGNED_EXTERNAL_OBSERVATION_VALIDATOR_IMPLEMENTED / DEPLOYMENT_CLOSURE_VERIFIER_IMPLEMENTED / HASH_PINNED_LOCK_BUILDER_IMPLEMENTED / DEPLOYMENT_READINESS_CANDIDATE_IMPLEMENTED / FINAL_ACCEPTANCE_GATE_IMPLEMENTED / LOCAL_DEPLOYMENT_RECOVERY_SMOKE_IMPLEMENTED / LOCAL_SERVER_ASSEMBLY_IMPLEMENTED / SERVER_ADAPTER_INJECTION_IMPLEMENTED / SERVER_ADAPTER_PORT_CONTRACT_IMPLEMENTED / HOST_DEPLOYMENT_ADAPTER_LAUNCHER_IMPLEMENTED / HOST_ADAPTER_ORIGIN_AND_FINGERPRINT_BINDING_IMPLEMENTED / HOST_DEPLOYMENT_SMOKE_IMPLEMENTED / API_PROFILE_CONTRACT_IMPLEMENTED / CLEAN_ROOM_HANDOFF_BUNDLE_IMPLEMENTED / EXTERNAL_REVIEW_PACKAGE_IMPLEMENTED / EXTERNAL_REVIEW_PACKAGE_SOURCE_BINDING_HARDENED / EXTERNAL_REVIEW_PACKAGE_PREFLIGHT_CONTRACT_HARDENED / REVIEW_CLOSURE_MATRIX_IMPLEMENTED / REPRODUCIBLE_DEPENDENCY_LOCK_IMPLEMENTED / SBOM_SUPPLY_CHAIN_CHECK_IMPLEMENTED / HASH_PINNED_MIRROR_VERIFIER_IMPLEMENTED / PRIVACY_KEY_RACE_HARDENED / CONTROL_PLANE_CONCURRENCY_VERIFIED / CASE_SEAL_SCOPE_HARDENED / CASE_SEAL_SYMLINK_HARDENED / CASE_SEAL_RUNTIME_AUDIT_SCOPE_HARDENED / PACKAGE_BUILD_SMOKE_IMPLEMENTED / CI_CANDIDATE_READINESS_HANDOFF_VERIFIED / CI_VERIFICATION_DEFINED / CI_WORKFLOW_CONTRACT_TESTED / OPERATIONS_RUNBOOK_IMPLEMENTED / GC-C1_PREFLIGHT_BLOCKED`

**External closure status:** The local candidate and its latest immutable handoff are
verified with zero local audit failures. The remaining closure sequence is
documented in Stage 4 of `IMPLEMENTATION_PLAN.md` and in the external-evidence
contract section of `OPERATIONS_RUNBOOK.md`. EXT-01..EXT-06, followed by
FA-01..FA-06, remain blocked until the authorized deployment supplies
independent observations, signed evidence and reviewer-separated acceptance;
this workspace does not fabricate those inputs. `EXTERNAL_CLOSURE_CHECKLIST.md`
is the operator-facing handoff sequence and evidence inventory.

## Implemented

| Documentation boundary | Implementation |
|---|---|
| V1-S0 local text boundary | `pmiri.store.LocalStore` |
| Transactional storage/migration/backup/restore adapter | `pmiri.store.SQLiteStore` with WAL, full synchronous commits, busy-timeout concurrency, JSON/blob history migration, read-only migration dry-run, verified snapshot backup and safe no-overwrite restore |
| Source/version/provenance | SHA-256 content-addressed records and stable anchors |
| Bounded local retrieval | `pmiri.retrieval.Retriever` |
| EvidenceSet and typed output | `pmiri.models`, `pmiri.runtime` |
| Context bound and citation lineage | `pmiri.context.ContextCompiler` |
| GC-C1 preflight record | `pmiri.preflight` with PF-01..PF-16 |
| S0 acceptance evidence | `pmiri.acceptance` with VS-01..VS-12 |
| Isolation handoff boundary | `pmiri.clean_room` and `pmiri.replay` |
| Isolation attestation artifact | `pmiri.attestation` |
| Attestation digest/status loader | `pmiri.attestation.load_attestation` |
| Artifact sealing | `pmiri.sealing` |
| D2 schema registry | `pmiri.schema.SchemaRegistry` |
| Standards-complete D2 schema validation | `jsonschema` Draft 2020-12 with a PMIRI URI resource registry; subset backend is explicit-only |
| D2 decision/lifecycle rules | `pmiri.decisions` |
| D2 URL/DNS/resource deny boundary | `pmiri.network`, `pmiri.policy` |
| D2 canonical URL and connection binding | `pmiri.network` canonicalization profile, IDNA2008/UTS46 hostname dependency, resolved-address/TLS/proxy/revalidation binding and tamper validation |
| D2 typed capability/policy observations | `pmiri.gate_d`, `pmiri.policy` exact value unions, scope, epoch and fingerprint validation |
| D2 fetched-content lifecycle binding | `pmiri.decisions`, `pmiri.gate_d` exact lifecycle fields, transitions, admission predicate and outbound projection checks |
| D2 constrained redaction | `pmiri.policy.constrained_redact` |
| D2 matrix harness and cache invalidation | `pmiri.d2`, `pmiri.cache` |
| Gate-D R1 subject/classification/egress rules | `pmiri.security` |
| Gate-D runtime decision/emission enforcement | `pmiri.gate_d` |
| Gate-D HTTPS provider/connector transport seam | `pmiri.transports` with explicit full connection binding, selected-address TCP pinning, hostname/SNI preservation, deployment TLS-context handoff, response limits and opaque credential injection; transport/boundary tests prove pinned socket/SNI behavior, duplicate/hop redirect rejection and each response-limit/content-type deny branch, while Gate-D tests prove TLS identity and final DNS-rebinding revalidation mismatches deny before a target is selected |
| Protocol-neutral read projection and API/MCP parity | `pmiri.read_projection` shared server handler with stateless continuation fingerprints |
| Universal external read-operation registry and final emission fence | `pmiri.read_operations` registers all seven documented read operations, binds operation-specific cursors, emits typed results and validates the final fence |
| Loopback authenticated read server | `pmiri.http_api.LocalReadHTTPServer` plus `pmiri.server.build_local_read_server` and `serve-local` CLI assembly with loopback-only bind, SQLite control-plane wiring, server-side auth requirement, bounded JSON requests, generic errors, operation binding and low-sensitivity `/metrics` counters; startup emits the active profile ID/fingerprint and effective storage/control-plane paths; `tests/test_cli_serve_local.py` exercises the real CLI process lifecycle |
| Deployment adapter injection seam | `pmiri.server.ServerAuthorizationAdapters` accepts deployment-owned identity/revocation and coordination ports, with public `Protocol` contracts for registry, replay, rate-limit and policy-epoch adapters; the builder validates their complete method surface and current policy epoch, maps adapter outages to configuration failures, and accepts an optional `BlobCipher` only after method-surface validation without creating local control-plane state when injected adapters are supplied; the server integration test now proves injected authentication and revocation through the HTTP read path |
| Redacted local audit sink | `pmiri.audit.JsonlAuditSink` and `ReadAuditEvent` with fsync’d JSONL, event fingerprint validation and fail-closed HTTP emission integration |
| Gate-D request authentication/authorization boundary | `pmiri.request_auth` trusted authentication registry, principal/trust-zone binding, purpose/scope/epoch checks, replay guard and per-principal rate limit |
| Gate-D emission authority binding | `pmiri.gate_d` requires a server-derived `RequestAuthorizationBinding` for allowed external emission and rechecks its exact envelope fields before transport |
| Gate-D durable local control plane | `pmiri.control_plane` SQLite/WAL principal registry with revocation, shared policy epoch, replay guard and rate limiter |
| Gate-D shared invalidation epoch | `GateDDecisionEngine(policy_epoch_store=...)` reads and atomically bumps the durable policy epoch used by authorization workers |
| Gate-D encrypted storage boundary | `pmiri.storage_crypto.AesGcmBlobCipher` with versioned AES-256-GCM blobs, key-domain separation, SQLite integration and optional `KeyEscrowAdapter` rotation hook that receives no raw key material |
| Gate-D caller disclosure projection | `pmiri.disclosure` leak-safe authorized/unauthorized result projection |
| Gate-D encrypted trace/privacy boundary | `pmiri.privacy` opt-in AES-GCM trace retention, Windows DPAPI per-domain keys, role access and TTL purge |
| Deterministic local runtime smoke artifact | `pmiri.d2_runtime`, `gate-d-smoke` |
| Connector credential boundary | `pmiri.credentials` |
| Case-scoped replay/sealing wrapper | `pmiri.controlled_replay` |
| GC-C1 subprocess handoff adapter | `pmiri.gc_c1_launcher` with fresh case roots, scrubbed environment, Windows Job Object limits and teardown checks |
| Deployment-readiness audit | `pmiri.readiness` closed profile, read-only local probes, candidate-artifact verification and explicit external hard blockers; `readiness` CLI; `scripts/verify_candidate.py` independently loads the in-project active profile and compares its canonical fingerprint with readiness |
| Final acceptance gate | `pmiri.final_acceptance` and `final-acceptance` CLI keep deployment readiness separate from D2 acceptance, R-FC 17/17 PASS, recovery/failover, independent review and operations approval; signed final evidence is required |
| Signed evidence packaging and keyless pre-validation | `scripts/build_signed_evidence.py` signs only strict, explicitly supplied EXT-01..EXT-06 or FA-02..FA-06 observations, self-verifies the output, refuses overwrite and rejects final packaging against blocked readiness; `validate external` and `validate final` run the same observation contract without a signing key and write no evidence |
| Deployment closure verification | `scripts/verify_deployment_closure.py` performs a read-only, single-command readiness/final-acceptance evaluation against supplied signed evidence and returns success only for the complete closure state |
| Shared local control-plane bootstrap | `init-control-plane` initializes the four SQLite/WAL authorization tables without changing network policy |
| Local deployment/recovery smoke | `pmiri.deployment_smoke` and `deployment-smoke` prove fixture ingest, query parity after restore, canonical fingerprints and control-plane bootstrap without external I/O |
| Release reproducibility and package build | `requirements.lock`, `scripts/verify_reproducibility.py`, explicit setuptools package discovery and offline wheel smoke; `scripts/create_release_candidate.ps1` now fail-fast verifies the installed lock before sealing and can install only from an explicitly supplied offline mirror; `scripts/verify_candidate.py` also rejects an exact-lock runtime drift |
| SBOM and supply-chain inventory | `scripts/generate_sbom.py` emits deterministic SPDX 2.3 for the exact lock, enforces the canonical CI epoch and verifies package/version/purl inventory; the candidate audit checks the tracked SBOM directly; `scripts/verify_supply_chain.py` verifies a deployment-supplied hash-pinned lock and offline mirror artefacts without downloading; distribution hashes remain an explicit mirror responsibility |
| Offline hash-lock packaging | `scripts/build_hash_pinned_lock.py` computes a deterministic exact-version hash lock from a deployment-supplied offline mirror, verifies every matching archive, refuses overwrite and never contacts a package index |
| CI verification workflow | `.github/workflows/pmiri.yml` repeats locked installation, fixed-epoch two-build wheel reproducibility/hash verification, installs the selected wheel into an isolated target and persists that target through subsequent steps, runs the installed CLI from a runner-temp cwd with absolute workspace/output paths, compiles/tests, performs deployment smoke, fresh local SQLite/control-plane bootstrap, expected external-only readiness and final-acceptance blocking, source-bound review package validation, in-project handoff verification, explicit-manifest read-only release-candidate audit and integrity checks; `scripts/create_release_candidate.ps1` provides the equivalent local bootstrap-handoff → tests → seal → final-handoff → audit sequence |
| Candidate operations runbook | `OPERATIONS_RUNBOOK.md` defines bootstrap, migration canary, recovery, stop conditions and promotion evidence |
| Migration safety rehearsal | `migration_plan` reports source fingerprint/counts without writes; `tests/test_cli_migration.py` exercises the CLI dry-run → canary migration → query → backup → restore chain and proves the no-overwrite rollback guard; the runbook defines the same evidence |
| Clean-room/review handoff bundle | `pmiri.handoff`, `handoff` CLI and `scripts/create_handoff.ps1` materialize selected payload files into the next unused immutable release directory, run the read-only candidate audit against that exact manifest and the current source tree, and enforce per-file SHA-256, no-overwrite protection and explicit external action inventory; candidate-root seal and reduced transfer manifest scopes are documented separately |
| External review package | `pmiri.review_package` and `review-package` CLI consolidate bounded local evidence summaries, fingerprints, acceptance counts, the final-acceptance gate, a local/external/final closure matrix and the six external review actions without promoting readiness |
| Read-server deployment profile | `deployment-profile.example.json` and `pmiri.readiness.validate_profile` bind HTTP loopback host, port, request limit and project-local audit path; `serve-local --profile` consumes API, SQLite storage, control-plane and audit paths (with explicit overrides preserved), and the release audit rejects profile/readiness drift |
| Host-native deployment adapter seam | `pmiri.deployment_server`, `serve-deployment` and `scripts/smoke_host_deployment.py` require an explicit deployment-owned adapter builder, validate adapter origin and SHA-256 fingerprint before socket creation, keep the server loopback-only, and prove health/metrics/401-redaction/audit/teardown; these are local host checks and do not claim external closure |
| Windows VM deployment seam | `deployment/vm/serve_vm.py` requires an explicit deployment-owned authorization adapter module, optionally a blob-cipher adapter, resolves the approved profile paths, rejects missing/invalid adapters before socket creation and preserves the loopback-only server boundary; `deployment/vm/local_candidate_adapters.py` provides an explicitly local-only SQLite adapter for the isolated candidate smoke path; `deployment/vm/Test-PmiriVMIsolation.ps1` provides a read-only host preflight for running state, Secure Boot, zero NICs and Guest Service Interface and fails closed on drift; `deployment/vm/Stage-PmiriVMCandidate.ps1` stages the host-controlled smoke helper over Guest Service Interface and reports its SHA-256; `deployment/vm/Invoke-PmiriVMCandidateSmoke.ps1` composes isolation, staging, guest hash verification and credential-scoped PowerShell Direct execution without persisting credentials; `deployment/vm/Start-PmiriVMCandidateSmoke.ps1` requests UAC elevation when needed and delegates to that same fail-closed orchestrator; `deployment/vm/Smoke-PmiriVMCandidate.ps1` starts the VM server, checks `/healthz`, unauthenticated read denial, metrics and redacted audit, and guarantees child-process teardown; `deployment/vm/Provision-PmiriVM.ps1` copies install media into the VM root without overwriting the source, prepares a fresh Generation 2 VM with explicit DVD-first firmware order, removes and asserts zero virtual NICs, disables automatic checkpoints, and refuses reuse; `deployment/vm/Install-PmiriVM.ps1` verifies the staged Python 3.12.10 installer hash, installs it, and invokes the offline bootstrap; `deployment/vm/Invoke-PmiriVMBootstrap.ps1` obtains guest credentials locally and invokes that helper through isolated PowerShell Direct only; `deployment/vm/Bootstrap-PmiriVM.ps1` validates the installed VM, offline dependencies, profile and store without creating external evidence; `deployment/vm/README.md` defines the VM topology and remaining external prerequisites |
| 34-case local D2 candidate harness | `pmiri.d2_runtime`, `d2-runtime` |
| 17-case R-FC blocked evidence inventory | `pmiri.r_fc`, `rfc-status` |
| Attested R-FC candidate runner | `pmiri.r_fc.run_r_fc_candidate`, `rfc-run`; per-case attestation, digest-bound handler manifest, handler execution, output persistence and sealing |
| PMIRI-backed local R-FC handler suite | `pmiri.r_fc_handlers`, `rfc-local`; all 34 declared cases execute against fresh synthetic PMIRI state and compare to the fixture oracle without external I/O |
| Replaceable technology decision log | `TECHNOLOGY_DECISIONS.md` |

## Verified locally

- The base host Python interpreter is intentionally excluded from candidate
  release execution because eight globally installed distributions drift from
  `requirements.lock`; the lock checker also detects missing dependencies that
  the current test paths might not import.
- A clean isolated exact-lock validation environment is materialized under
  `.venv-pmiri-exact`. Its lock checker passes, and the release-candidate
  pipeline completes the full suite with `Ran 216 tests ... OK`.
- The default host environment mismatch is explicit: `attrs`, `cffi`,
  `cryptography`, `jsonschema`, `rpds-py`, `setuptools`, `typing-extensions`,
  and `wheel` do not match the locked versions. Candidate release commands
  now auto-select `.venv-pmiri-exact` when it is present; an approved offline
  mirror installation remains the alternative when that environment is not
  available. The selected interpreter is still checked against the lock.
- The latest immutable local handoff is resolved from the read-only candidate
  audit rather than copied into a fixed documentation version. The audit
  reports `LOCAL_CANDIDATE_VERIFIED`, `local_failure_count=0` and a verified
  handoff manifest. External closure remains intentionally pending.
- The deterministic SPDX 2.3 SBOM contains exactly the 12 locked packages plus
  PMIRI and rejects version/purl inventory drift; it deliberately leaves
  distribution hashes as `NOASSERTION` until a trusted package mirror supplies
  hash-pinned acquisition.
- `scripts/verify_supply_chain.py` now provides the missing fail-closed
  boundary: it rejects a deployment lock with missing/extra packages, version
  drift, absent or malformed SHA-256 hashes, and offline mirror artefacts that
  are missing or do not match a supplied hash. No local package artefacts were
  available to justify inventing those hashes.
- The package builds as both a wheel and editable distribution with only the
  `pmiri` package discovered; the prior flat-layout packaging ambiguity is
  closed.
- The release helper refuses to seal or hand off when the selected Python
  environment is missing or drifting from `requirements.lock`; offline
  installation is opt-in and uses `--no-index` with an explicit mirror.
- The loopback HTTP candidate serves an authenticated read through the shared
  API projection and rejects missing authentication, path/body operation
  substitution, non-loopback construction and unauthenticated service wiring.
- The loopback `/metrics` surface exposes only thread-safe request, outcome and
  audit-failure counters; it does not include authentication references,
  project names, queries or evidence content.
- The packaged `serve-local` assembly starts only against an initialized SQLite
  content store and wires the local SQLite control plane, audit sink and
  loopback server; an empty control plane cannot authorize a caller.
- The host-native `serve-deployment` assembly requires an explicit deployment-
  owned adapter module, validates its supplied origin and SHA-256 fingerprint
  before opening a socket, and the host smoke proves health, metrics,
  unauthenticated 401 redaction, audit output and child-process teardown.
  This is local host evidence only; it does not promote external readiness.
- The signed-evidence builder exposes keyless `validate external` and
  `validate final` commands. They apply the same strict observation and
  readiness-binding contracts as signing, emit no evidence and do not require
  a signing key, so malformed deployment observations fail before signing.
- `build_local_read_server` also accepts a deployment-owned
  `ServerAuthorizationAdapters` set and optional blob cipher. Contract tests
  confirm that injected objects are used by the authorization/runtime path,
  local control-plane state is not created in that mode, and invalid adapter
  surfaces, unavailable epoch stores, invalid policy epochs or blob ciphers are
  rejected before server construction. The registry, replay, rate-limit and
  epoch ports are explicitly typed Protocols.
- The clean-room handoff bundle contains 232 payload files and verifies its
  manifest plus every copied file fingerprint; its status remains
  `HANDOFF_READY_FOR_EXTERNAL_REVIEW`, with external execution and review not
  supplied.
- The review package inventories 11 local reports, all 16 preflight checks,
  34 D2 scenarios, 17 R-FC obligations and the six external prerequisites; its
  closure matrix explicitly separates locally verified work from external and
  final-acceptance blockers. It is self-fingerprinted and remains
  `READY_FOR_EXTERNAL_REVIEW`.
- The deployment profile rejects remote API binds, invalid ports/request limits
  and audit paths outside the project root; profile-driven `serve-local` was
  smoke-tested with health and metrics on loopback.
- The loopback HTTP boundary rejects an oversized JSON request with a generic
  `413` response before authorization/runtime execution and records only a
  redacted rejection audit event.
- Migration dry-run is read-only, reports source fingerprint/counts and target
  readiness, while an existing SQLite target is rejected rather than merged;
  backup and restore retain canonical fingerprint equality.
- VS-01 through VS-12 are covered.
- All bundled JSON documents parse.
- 21 schema IDs are unique.
- Integrity reports the active schema backend as `standards`; missing the
  declared standards validator is itself a failed integrity condition.
- The default schema backend is standards-complete Draft 2020-12; the
  dependency-free subset is not silently selected when the dependency is
  missing.
- D2 registry files and absolute references resolve.
- 34 D2 scenarios and 17 positive/adversarial classes are present.
- D2 matrix harness validates all 34 declared outcomes while preserving their
  documented `runtime_status=BLOCKED` boundary.
- Preflight record shape is valid, but its result is intentionally `BLOCKED`.
- GC-C1 authority ZIP archives and all declared member hashes are now verified;
  the local pinned-runner declaration and selected `GC-C1-FC01` /
  `GC-C1-FC01-P` case make PF-01 through PF-07 locally `READY`, while
  isolation/review checks remain blocked.
- PF-02/PF-03 runner-package validation now requires the exact three-file
  package inventory, valid source/manifest SHA-256 values, the self-hash
  marker and all deny-by-default package boundary flags.
- `pmiri.deployment_evidence` verifies a deployment-supplied Ed25519 signature,
  trusted key identity, profile/authority bindings, all six EXT checks and
  independent reviewer separation. `readiness` can consume this evidence via
  `--external-evidence` and `--external-public-key`; absent or tampered input
  remains BLOCKED.
- Gate-D smoke execution validates trust, capability, network and integrated
  envelope records against the bundled schemas. One in-memory provider call is
  executed; substitution and post-invalidation calls are stopped before the
  transport.
- The D2 candidate also validates the relevant trust assertion, capability
  observation, credential boundary, redaction/typed-constraint, constrained
  egress and fetched-content lifecycle records against their schemas.
- The network path enforces the documented canonicalization profile and builds
  a tamper-checked connection binding from normalized public resolutions, the
  selected target, proxy mode, TLS identity and revalidation epochs. Outbound
  decisions copy the binding ID/fingerprint, selected resolution reference,
  TLS identity fingerprint and final revalidation event from that binding.
- Hostname canonicalization uses the declared `idna` dependency for
  non-ASCII names and fails closed if the IDNA2008/UTS46 implementation is not
  installed; ASCII A-labels remain deterministic without a hidden fallback.
- Capability and provider-policy observations use closed typed value unions;
  lifecycle records use exact fingerprints, admission predicates, visibility
  projections and legal monotonic transitions. These checks are exercised by
  direct tamper and cross-boundary tests.
- The local D2 candidate harness executes all 34 declared fixture scenarios;
  all 34 oracle comparisons match. This is `LOCAL_SYNTHETIC_ONLY` evidence and
  preserves every documented `runtime_status=BLOCKED` value.
- The PMIRI-backed local R-FC handler suite executes all 34 declared positive
  and adversarial cases with 34/34 oracle matches. This is separate from the
  attested replay runner, remains `LOCAL_SYNTHETIC_ONLY`, performs no external
  I/O and keeps `r_fc_pass=NONE`.
- The current artifact manifest is cryptographically verifiable (`SEALED`),
  while its completeness is explicitly `INCOMPLETE` because environment,
  privacy, independent-review and seal attestations are not supplied.
- All 17 R-FC obligations now have schema-shaped `BLOCKED` evidence records;
  no R-FC callable was invoked and `r_fc_pass` remains `NONE`.
- The R-FC candidate runner can execute selected or all 34 declared cases only
  when every selected case has a `READY_FOR_REPLAY` preflight record bound to
  that exact fixture/case, a digest-valid externally produced `VERIFIED`
  attestation, exact replay fingerprints, a digest-bound manifest matching the
  imported handler module/source/symbols and separated operator/reviewer
  identities. Each case runs in a fresh root, its output is sealed and
  optionally persisted, and the resulting evidence remains `UNVERIFIED`/`FAIL`;
  the runner never assigns `PASS`.
- V1-S0 metadata/blob writes use atomic replacement, `fsync` and a writer lock;
  no migration or multi-user production claim is made.
- The local GC-C1 launcher refuses to start without a digest-valid `VERIFIED`
  attestation, invokes the command without a shell, materializes read-only
  inputs, applies a scrubbed deterministic environment, enforces Windows Job
  Object CPU/memory/process limits, bounds wall time and seals the launch
  evidence. This is local execution evidence, not independent clean-room
  attestation.
- The SQLite adapter preserves the JSON store's canonical source fingerprint,
  historical versions and query surface; concurrent writer, blob-integrity,
  read-only, verified snapshot-backup and no-overwrite restore tests pass. Operational deployment,
  encryption and migration rollout review are still not claimed.
- The protocol-neutral read projection runs API and MCP facades through the
  same server-derived binding; client authorization references cannot widen a
  request and stateless continuation parity is covered by tests.
- All seven documented external read operations are enumerated in one
  server-side registry. Each response carries an operation-bound cursor, a
  typed result, a projection fingerprint and an immutable final emission
  fence; API/MCP parity, cursor substitution and fence tampering are tested.
- The authenticated read path derives `RequestAuthorizationBinding` from a
  server-registered principal and trusted `TrustZoneAttestation`; project and
  purpose scope, policy epoch, request replay and per-principal/operation rate
  limits fail closed. API and MCP share this authorization-to-disclosure path,
  and caller-controlled authorization booleans are rejected.
- The durable control-plane adapter persists principal state and revocation,
  policy epochs, replay IDs and rate-limit windows in one transactional SQLite
  database; tamper detection, cross-worker sharing and revocation integration
  are covered by tests.
- `SQLiteStore(blob_cipher=...)` stores content blobs as authenticated,
  versioned AES-256-GCM ciphertext and supports in-process key-version rotation;
  ciphertext tamper detection and encrypted backup/readback are tested. The
  optional `KeyEscrowAdapter` receives only a key fingerprint during rotation;
  escrow failure leaves the prior active key version unchanged.
- The HTTPS provider/connector adapters are implemented behind explicit
  authorization, outbound-decision and full connection-binding validation.
  Fake-connection tests cover selected-address handoff, target substitution, credential redaction,
  response limits, binding tamper/reference/epoch checks and closed defaults;
  the Gate-D runtime also rejects reuse of an adapter against a different
  connection-binding decision; no real external request has been performed.
- Gate-D external emission now requires a server-derived request-authorization
  binding. The final fence rejects missing, stale, policy/operation/purpose-
  mismatched or envelope-substituted bindings, and requires a trusted
  authorization revalidation immediately before a provider/connector call.
  A durable SQLite policy epoch can be shared by Gate-D and request-
  authorization workers, and its invalidation bump is transactional.
- The Gate-D connector runtime path is integration-tested with a lifecycle
  record and in-memory connector transport; the same binding/revalidation
  fence is used before the connector call.
- The caller disclosure boundary maps unauthorized reads and empty authorized
  reads to the same canonical projection, while authorized evidence retains
  its typed lineage. API/MCP disclosed facades are parity-tested.
- Raw trace capture is disabled by default. When explicitly enabled, the
  privacy boundary encrypts payloads with AES-256-GCM, protects per-domain
  keys with Windows user-scope DPAPI, gates reads by role and enforces TTL
  expiry/purge; plaintext trace payloads are not written. Per-domain key
  creation is serialized across workers and trace reads accept only the
  capture-generated `trace_<32 lowercase hex>` identifier format.
- Concurrent SQLite control-plane checks prove that a replay ID is consumed
  once, a fixed-window limiter never exceeds its configured allowance, and
  policy epoch bumps are unique and monotonic under competing workers.
- Case sealing excludes analysis caches, build metadata, handoff transfer trees
  and the runtime-generated `artifacts/read-audit.jsonl` while retaining
  candidate reports; this keeps the evidence inventory independent of local
  tooling output, live operational state and derived review bundles. Symlinks
  are ignored in both seal and verify passes, preventing outside-root content
  from entering a case inventory.
- The deployment-readiness report validates its own fingerprint and exact
  check shape, confirms local candidate artifacts and default-deny network
  behavior. The workspace SQLite store and local control plane are
  initialized and healthy; six external prerequisites remain hard blockers.
- The final-acceptance gate validates its own fingerprint and fails closed on
  the separate FA-01..FA-06 contract. Without controlled signed final
  evidence it remains `FINAL_ACCEPTANCE_BLOCKED`, even if readiness later
  becomes `DEPLOYMENT_READY`.
- The local deployment/recovery smoke creates isolated SQLite/control-plane
  state, ingests three synthetic sources, verifies two-result query parity
  across backup/restore and returns the expected external-readiness blockers.
- The smoke refreshes the canonical local seal before its readiness probe, so
  changes made by candidate-report commands cannot leave a stale manifest in
  the verified local path.

## Still blocked or not claimed

- Independent OS-level clean-room isolation and attestation. The local adapter
  supervises a subprocess and enforces process limits, but cannot prove that
  its own network/filesystem observations are independent.
- Gate-C R-FC acceptance and any `PASS` result (`0/17` remains the authority
  state). The local handler suite is executable, but the attested candidate
  runner cannot execute here without externally produced per-case clean-room
  attestations and independent review.
- Real provider, connector, DNS, TLS or external network execution.
- A production identity-provider/gateway integration, distributed replay/rate-
  limit coordination or deployed network API server. The durable SQLite
  control plane is local/multi-process, not a distributed control plane.
- Production ingestion, deployment, metadata/volume encryption, key escrow and
  multi-user operation; content-blob encryption, migration, backup and trace-
  encryption adapters exist but have not been exercised against production
  data or approved operationally.
- Gate-D R2 independent recheck and acceptance.
- Real provider/connector execution is not performed here. The HTTPS transport
  adapters exist and are covered by deterministic fake-connection tests, but
  controlled DNS/TLS/network authorization and independent deployment evidence
  are still required before they may run.

The implementation does not edit the documentation authority bundle and does
not promote structural validation into runtime or acceptance evidence.

## Explicit deviations and unresolved decisions

- JSON/blob remains the compatibility backend; SQLite is now the production-
  oriented transactional candidate. The archive leaves final database/object-
  store deployment, metadata/volume encryption and operational migration/key
  management approval open. SQLite content-blob encryption is available as an
  explicit replaceable adapter.
- Retrieval is deterministic lexical retrieval; embeddings, reranking and
  graph memory remain outside S0.
- A dependency-free subset validator remains available only as an explicit
  compatibility backend; production validation uses the declared
  `jsonschema`/`referencing` dependencies and still requires dependency
  supply-chain and deployment review.
- Gate-D runtime records are schema-valid for the exercised trust, capability,
  outbound-network and integrated-envelope paths. The full D2 matrix now has a
  local synthetic candidate run, but it is not an independent clean-room,
  provider, connector or network execution and cannot become D2 acceptance.
- OS sandbox mechanism, provider selection, connector transport, deployment,
  encryption/key management and migration strategy are not specified by the
  authority set and remain open decisions. The SQLite control plane is a
  replaceable local/multi-process adapter; production identity, key management,
  and distributed control-plane choices still require deployment authority.
