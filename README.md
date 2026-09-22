# PMIRI

PMIRI is a local-first, provenance-preserving evidence and retrieval runtime.
The implementation follows the documentation archive in
`PMIRI_ALL_DOCUMENTATION_CHECKPOINT_17/` and keeps its fail-closed boundaries.
Implementation choices are recorded in `TECHNOLOGY_DECISIONS.md`; the archive
itself is not modified.

## Run the local slice

```powershell
$py = (Get-Command python -ErrorAction Stop).Source
& $py -m unittest discover -s tests -v
& $py -m pmiri.cli --help
& $py -m pip install --requirement requirements.lock
& $py scripts/verify_reproducibility.py --check-installed
& $py -m pip wheel --no-deps --no-build-isolation . --wheel-dir "$env:TEMP\pmiri-wheel"
```

`requirements.lock` pins the runtime and build distributions used by the
candidate. `scripts/verify_reproducibility.py` checks both the pyproject
contract and the installed environment. The wheel smoke confirms that only
the `pmiri` package is included; the repository fixtures and documentation are
not accidentally packaged. CI repeats these checks in
`.github/workflows/pmiri.yml`. Operational bootstrap, recovery and stop
conditions are documented in `OPERATIONS_RUNBOOK.md`.
The workflow also exports the isolated wheel target to subsequent steps and
imports it from outside the checkout. Runtime CLI checks use absolute artifact
paths, so the candidate checks cannot silently fall back to the source tree or
write evidence into an unrelated working directory.
`requirements.lock` is also materialized as a deterministic SPDX 2.3 SBOM by
`scripts/generate_sbom.py`; package distribution hashes remain a deployment
package-mirror responsibility and are not invented locally. Before external
promotion, the deployment must supply a second, hash-pinned lock and verify it
against its offline package mirror:

```powershell
& $py scripts/verify_supply_chain.py `
  --lock C:\controlled-mirror\requirements.hashes.lock `
  --artifact-dir C:\controlled-mirror\packages
```

The repository SBOM uses the canonical reproducibility epoch
`SOURCE_DATE_EPOCH=946684800` (2000-01-01T00:00:00Z); a different epoch is
rejected so a local artifact cannot be deterministic yet disagree with CI.
`scripts/create_release_candidate.ps1` sets and verifies this value before
sealing the candidate.

The checker requires the exact repository package/version inventory, at least
one SHA-256 hash per distribution, and a matching local wheel or source
archive; it never downloads from a public index.

To create that second lock from the supplied offline mirror, use the
deterministic builder; it refuses missing packages and existing output files:

```powershell
& $py scripts/build_hash_pinned_lock.py `
  --artifact-dir C:\controlled-mirror\packages `
  --output C:\controlled-mirror\requirements.hashes.lock
```

The release-candidate helper can enforce that hash-pinned mirror before
installing dependencies by passing `-HashPinnedLockPath` together with
`-InstallDependencies` and `-OfflinePackageDir`.

Example:

```powershell
& $py -m pmiri.cli init .pmiri
& $py -m pmiri.cli add-dir .pmiri project-alpha fixtures/s0/project-alpha
& $py -m pmiri.cli query .pmiri project-alpha "release status"
# SQLite backend and history-preserving migration
& $py -m pmiri.cli init .pmiri-sqlite --backend sqlite
& $py -m pmiri.cli migrate-json-to-sqlite .pmiri .pmiri-sqlite --dry-run
& $py -m pmiri.cli migrate-json-to-sqlite .pmiri .pmiri-sqlite
& $py -m pmiri.cli query .pmiri-sqlite project-alpha "release status" --backend sqlite
& $py -m pmiri.cli backup-sqlite .pmiri-sqlite .pmiri-sqlite-backup
& $py -m pmiri.cli restore-sqlite .pmiri-sqlite-backup .pmiri-sqlite-restored
& $py -m pmiri.cli acceptance .
& $py -m pmiri.cli preflight . --identity-file artifacts/local-runner-identity.json --fixture-id GC-C1-FC01 --case-id GC-C1-FC01-P
& $py -m pmiri.cli d2-matrix .
& $py -m pmiri.cli gate-d-smoke .
& $py -m pmiri.cli d2-runtime .
& $py -m pmiri.cli rfc-status .
& $py -m pmiri.cli init-control-plane .pmiri-control/control.db
& $py -m pmiri.cli deployment-smoke .
& $py -m pmiri.cli readiness . --profile deployment-profile.example.json
& $py -m pmiri.cli final-acceptance . --readiness artifacts/deployment-readiness-report.json
& $py -m pmiri.cli review-package .
& .\scripts\create_handoff.ps1 -ProjectRoot . -PythonPath $py
# Loopback-only candidate server; stop with Ctrl+C
& $py -m pmiri.cli serve-local --profile deployment-profile.example.json
```

For a reproducible local release-candidate handoff, run the helper below. It
creates a bootstrap handoff for the workspace integration test, runs the full
test suite, then refreshes the canonical seal, creates the final immutable
handoff and performs the exact read-only candidate audit. Use `-SkipTests` only
when the same workspace test run has already been recorded.

```powershell
& .\scripts\create_release_candidate.ps1 -ProjectRoot . -PythonPath $py
```

The helper prints two handoff paths when tests are enabled: the first is a
bootstrap manifest needed by the dirty-workspace integration test, while the
last is the final release candidate. Use only the last `handoff_manifest=` line
for external transfer, because tests may refresh generated candidate evidence.

The CLI has no provider or network path. External access is explicitly denied
by default. Preflight produces a truthful `BLOCKED` result unless all required
isolation and review evidence is supplied.

An authorized deployment may attach a separately supplied Ed25519-signed
external-evidence bundle to readiness:

```powershell
& $py -m pmiri.cli readiness . --profile deployment-profile.example.json `
  --external-evidence C:\controlled\deployment-evidence.json `
  --external-public-key C:\controlled\deployment-authority.pub
```

The verifier binds the bundle to the active profile and authority fingerprint,
checks EXT-01..EXT-06 and requires a distinct independent reviewer. Missing,
unsigned or tampered evidence leaves readiness blocked; the workspace does not
contain such evidence.

For the authorized deployment, `scripts/build_signed_evidence.py` packages
explicitly supplied observations into a self-verified signed bundle. It is
not an observer, refuses output overwrite, keeps the private key out of the
artifact, and rejects final-acceptance packaging until the readiness report
is `DEPLOYMENT_READY`.

Once both signed bundles exist, `scripts/verify_deployment_closure.py` runs
the complete read-only readiness and final-acceptance check, returning
`DEPLOYMENT_CLOSURE_READY` only for the fully closed state.

When `--profile` is supplied, `serve-local` derives the SQLite store,
control-plane and audit paths from the profile file when explicit overrides are
omitted; relative paths resolve beside that profile. Explicit store and
`--control-plane` arguments remain supported for controlled overrides.

The selected deployment path is host-native adapter injection through the
installed package. `serve-deployment` requires a deployment-owned adapter
module, refuses the local SQLite authorization fallback, and remains
loopback-only. It does not claim VM/OS isolation, distributed failover, KMS,
gateway or independent acceptance evidence:

```powershell
& $py -m pmiri.cli serve-deployment `
  --profile deployment-profile.example.json `
  --adapter-module company_pmiri_adapters `
  --adapter-dir C:\controlled\pmiri\adapters `
  --adapter-config C:\controlled\pmiri\adapter-config.json
```

Probe the same host-native assembly without leaving a long-running process:

```powershell
& $py scripts/smoke_host_deployment.py `
  --profile C:\controlled\pmiri\profile.json `
  --adapter-module company_pmiri_adapters `
  --adapter-dir C:\controlled\pmiri\adapters `
  --adapter-config C:\controlled\pmiri\adapter-config.json
```

The smoke must report `HOST_NATIVE_DEPLOYMENT_SMOKE_PASS`, `401` for the
unauthenticated read, and `REJECTED_401_REDACTED` in the audit result. It is a
loopback assembly check only; it does not create external deployment evidence.

`gate-d-smoke` exercises the Gate-D decision and final-emission fence using
static DNS/TLS observations and an in-memory provider double. It is useful
runtime enforcement evidence, but it is not external provider authorization,
D2 acceptance, or Gate-C R-FC evidence.

`d2-runtime` executes all 34 D2 cases against explicit synthetic fixture
signals and compares the resulting action, evidence state, lifecycle and
reason with the documented oracle. It is a local candidate report only;
external provider, connector, DNS, TLS and network access remain disabled.

When an independently produced attestation exists, preflight can consume it
with `preflight . --identity-file runner-identity.json --attestation
attestation.json --operator OPERATOR --independent-reviewer REVIEWER`.
Loading an attestation recomputes its digest and status; it does not create
clean-room evidence locally.

`seal` verifies byte-level integrity and records missing GC-C1 roles as
`INCOMPLETE`; a cryptographically valid seal is not an independent review or
an R-FC PASS.

`rfc-status` writes 17 explicit `BLOCKED` evidence records without invoking
R-FC cases. It keeps the authority state at `0/17 PASS` until the required
clean-room and independent-review evidence exists.

`review-package` writes a compact, self-fingerprinted inventory for an external
reviewer. It includes local report fingerprints, PF/D2/R-FC/recovery counts and
an explicit closure matrix separating locally verified candidate work from the
six external prerequisites and FA-01..FA-06 final-acceptance actions. It makes
no external readiness or acceptance claim.

`rfc-local` runs the PMIRI-backed local handler suite for all 34 declared
positive/adversarial cases. It is executable synthetic coverage for the local
runtime, projection, fencing and authorization boundaries; its report remains
`LOCAL_SYNTHETIC_ONLY`, performs no external I/O and never creates an R-FC
`PASS`. It is also checked by deployment readiness as a local candidate
artifact.

`rfc-handler-manifest` produces the standalone digest-bound manifest at
`artifacts/r-fc-handler-manifest.json`; readiness verifies that it covers the
catalog’s 34 cases and matches the current handler source before replay can be
considered.

`pmiri.r_fc.run_r_fc_candidate` and `rfc-run` provide the next execution
boundary for the declared 34 R-FC cases. The command requires one digest-valid
`READY_FOR_REPLAY` preflight record and one digest-valid `VERIFIED` external
attestation per selected case, the seven exact replay fingerprints, a pinned
handler module exposing `HANDLERS`, a digest-bound handler manifest, and
separated operator/reviewer identities. The manifest binds the selected
handler symbols to one source module and SHA-256 source fingerprint; a missing
or mismatched manifest blocks dispatch before the handler is called. Create it
with `rfc-handler-manifest` and pass it to `rfc-run` via `--handler-manifest`.
Use `--case-id` to run a subset; omit it to run all 34. Outputs may be retained
with `--persist-dir`. The runner records oracle matches and sealed artifacts
but never promotes a case to `PASS`; an independent review artifact must do
that outside the runner.

`pmiri.read_projection.ReadProjectionService` exposes local API/MCP-compatible
read facades through one shared server-derived handler. Client authorization
references do not widen access, and continuation values are stateless
fingerprints. The authenticated path uses
`pmiri.request_auth.RequestAuthorizationService`: a server-registered
authentication reference is bound to a principal, trusted trust-zone
attestation, exact project/purpose scope, policy epoch, replay guard and
  per-principal rate limit before disclosure. The in-memory registry/limiters
  are local adapters; the shared SQLite control-plane variant is described
  below. Neither is a deployed identity provider or network server.

`pmiri.read_operations.ReadOperationService` registers the seven documented
external read operations (`search`, `fetch_evidence`, `resolve_current_state`,
`retrieve_history`, `timeline`, `explain`, `status`). Each operation returns
the shared projection, an operation-bound stateless cursor, a typed result and
an `ExternalReadEmissionFence`; API/MCP parity and cursor substitution are
covered by tests. This is the local semantic implementation, not evidence of
independent Gate-C replay or production API hosting.

`pmiri.http_api.LocalReadHTTPServer` is the next local deployment boundary. It
binds only to `127.0.0.1`, requires the server-side authorization service,
accepts the authentication reference only from `X-PMIRI-Authentication-Ref`,
limits JSON request size, rejects operation substitution and returns generic
errors without internal authorization reasons. It is a loopback candidate
adapter, not a deployed identity gateway, TLS terminator or public API.
`/healthz` and `/metrics` are loopback-only operational surfaces; metrics are
limited to thread-safe request/outcome/audit-failure counters and contain no
identity, query, project or evidence fields.
The `serve-local` CLI assembles this boundary with the SQLite store and local
control plane; its startup record includes the active profile ID/fingerprint
and effective storage/control-plane paths; it never enables external
network/provider access. Deployment
code that owns approved identity/revocation and distributed coordination may
instead call `pmiri.server.build_local_read_server` with a
`ServerAuthorizationAdapters` instance and an optional `BlobCipher`. The
builder validates the adapter method surface and current policy epoch, then
fails closed; supplying adapters does not itself authorize public hosting or
network access.

`scripts/create_handoff.ps1` selects the next unused immutable
`artifacts/handoff-release-vN/` directory and invokes `handoff`; the resulting
`handoff-manifest.json` and `payload/` tree are the clean-room/reviewer
transfer bundle. Before returning success, the helper also runs
`verify_candidate.py` against that exact manifest. It includes only the
synthetic fixture, pinned runner, authority inputs, implementation/verification
sources, lock/SBOM and candidate evidence; every payload file is fingerprinted,
the manifest is checked against the current source tree, and the bundle does
not claim external execution or independent approval. A stale handoff is
therefore rejected until a new immutable bundle is created.

`scripts/verify_candidate.py` is a read-only release audit. It verifies the
documentation, the canonical seal, the active profile’s canonical fingerprint
against readiness, review/readiness/final reports, latest handoff and exact
PF-01..PF-16, 34-case D2 and 17-case R-FC candidate inventories before transfer.
CI or a caller holding a temporary handoff can select the profile and manifest
explicitly with `--profile` and `--handoff-manifest`; paths outside the project
root are rejected, and the selected handoff must match both its payload and the
current project source fingerprints.

The optional `pmiri.audit.JsonlAuditSink` records only redacted outcome and
fingerprint fields for that boundary. Successful emissions are audited before
they are returned; if the configured sink cannot persist an event, the HTTP
adapter fails closed. Audit lines are fsync’d and independently fingerprint-
verified, but centralized retention and audit administration remain deployment
responsibilities.

For local multi-process deployment, `pmiri.control_plane` provides a shared
SQLite/WAL registry and transactional revoke, policy-epoch, replay and
rate-limit adapters. It preserves fail-closed behavior across workers but is
not a distributed identity provider.

`SQLiteStore` accepts `blob_cipher=pmiri.storage_crypto.AesGcmBlobCipher(...)`
to store content blobs as authenticated versioned AES-256-GCM ciphertext. The
cipher supports key-version rotation while retaining accepted old versions for
readback. An optional `KeyEscrowAdapter` is notified with only the domain,
version and SHA-256 key fingerprint before a rotated version becomes active;
escrow failure leaves the previous version active. Metadata/volume encryption
and the real KMS/DPAPI escrow implementation remain deployment choices.
`restore-sqlite` restores a backup only into a new destination and compares the
canonical fingerprint before reporting `RESTORE_VERIFIED`.

`pmiri.disclosure.project_query_result` is the caller-facing leak-safe
projection: unauthorized reads and empty authorized reads expose the same
typed empty result without source counts or internal denial reasons. The
disclosed API/MCP methods use this boundary before returning data.

`pmiri.privacy.EncryptedTraceStore` keeps raw trace capture disabled by
default. An explicitly enabled policy encrypts traces with AES-GCM, protects
per-domain keys with Windows DPAPI, restricts access by role and purges expired
records; this does not claim production-wide retention or key-rotation policy.

The D2 registry uses the declared `jsonschema` Draft 2020-12 backend by
default, with PMIRI URI references resolved through `referencing`. The older
dependency-free validator is available only when explicitly requested with
`backend="subset"` and is not a production fallback.

For external Gate-D emission, the same server-derived request binding must
also be supplied to `GateDDecisionEngine.build_integrated_envelope` and
`EnforcedTransportRuntime`. The final fence checks the binding's validity,
operation, purpose, policy version/epoch and exact envelope fields, then calls
the trusted authorization revalidator immediately before any provider or
connector transport can run. A durable `SQLitePolicyEpoch` may be shared
between the authorization service and Gate-D engine.

`pmiri.transports` contains explicit HTTPS provider and connector adapters.
They require a matching Gate-D `ALLOW` decision, a full validated connection
binding and an explicit external authorization flag, pin the selected address
for TLS/SNI, enforce response limits, reject implicit redirects and inject only
opaque credentials. No real external request is enabled by the default runtime.

The public read surface must use `api_authenticated` or `mcp_authenticated`
when a `RequestAuthorizationService` is configured. The legacy raw methods
remain available only for the local semantic compatibility surface and are
rejected by an authenticated service; a caller-provided `authorized` boolean
is never accepted as authority.

`gc-c1-launch` is the local subprocess handoff adapter. It requires an
externally produced, digest-valid `VERIFIED` attestation and exact fingerprint
inputs before starting a command; it then uses a fresh case root, shell-free
argv, a scrubbed environment, read-only inputs, Windows Job Object limits,
bounded wall time, teardown inspection and a sealed launch record. It cannot
create independent clean-room evidence by itself and therefore cannot promote
R-FC or D2 acceptance.

`init-control-plane` initializes the shared local SQLite/WAL authorization
database without enabling network access. `readiness` performs a read-only,
machine-readable deployment-readiness audit and writes
`artifacts/deployment-readiness-report.json`. The command exits non-zero while
any local evidence or external prerequisite is blocked. Its closed profile
contract, including the loopback read-server settings, is documented in
`deployment-profile.example.json`; profile text is
configuration only and cannot assert clean-room, identity, key-escrow,
distributed-control-plane or independent-review evidence.

`final-acceptance` is the final fail-closed promotion boundary after readiness.
It writes `artifacts/final-acceptance-gate.json` and requires readiness plus a
separately trusted signed assertion set for D2 acceptance, R-FC 17/17 PASS,
migration/restore/failover, independent review and operations approval. The
local workspace intentionally produces `FINAL_ACCEPTANCE_BLOCKED`; readiness
must never be read as final acceptance.

`deployment-smoke` runs the local synthetic fixture through SQLite ingest,
query, verified backup, no-overwrite restore, restored query comparison and
control-plane initialization. It returns success only when that local chain
is proven; its readiness sub-result remains blocked for the external
prerequisites and it never performs network/provider I/O. Before probing
readiness it refreshes the canonical local seal, so candidate artifacts cannot
be checked against a stale byte inventory.
