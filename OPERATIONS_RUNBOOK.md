# PMIRI operations runbook

This runbook describes the reproducible local candidate operation. It does
not grant production implementation, external network access, provider
credentials, data migration authority, or Gate-C/Gate-D acceptance.

## 1. Preconditions

Use Python 3.12 and install the exact dependency set:

```powershell
$py = (Get-Command python -ErrorAction Stop).Source
$env:SOURCE_DATE_EPOCH = '946684800'
& $py -m pip install --requirement requirements.lock
& $py scripts/verify_reproducibility.py --check-installed
& $py -m pip wheel --no-deps --no-build-isolation . --wheel-dir "$env:TEMP\pmiri-wheel"
$wheel = Get-ChildItem -LiteralPath "$env:TEMP\pmiri-wheel" -Filter "pmiri-*.whl" | Select-Object -First 1
& $py -m pip install --no-deps --no-index --target "$env:TEMP\pmiri-install" $wheel.FullName
```

The release helper also sets this canonical epoch while regenerating and
checking the tracked SBOM. A different `SOURCE_DATE_EPOCH` is rejected because
it would produce a deterministic artifact that does not match the CI release
contract.

The repository lock fixes versions but intentionally does not claim package
mirror trust. A deployment promotion must provide its independently managed
hash-pinned lock and offline package mirror, then run:

```powershell
& $py scripts/verify_supply_chain.py `
  --lock C:\controlled-mirror\requirements.hashes.lock `
  --artifact-dir C:\controlled-mirror\packages
```

This check is fail-closed for missing packages, version drift, absent hashes,
missing artefacts and hash mismatches. It performs no package download.

If the mirror has not yet supplied a hash lock, create one without contacting
an index:

```powershell
& $py scripts/build_hash_pinned_lock.py `
  --artifact-dir C:\controlled-mirror\packages `
  --output C:\controlled-mirror\requirements.hashes.lock
```

The builder includes every matching exact-version archive hash, verifies the
new lock against the mirror, and refuses missing packages or output overwrite.

For a release-candidate install, pass the resulting lock to the release helper
as well. The helper verifies every mirror archive before invoking pip:

```powershell
& .\scripts\create_release_candidate.ps1 `
  -PythonPath $py `
  -OfflinePackageDir C:\controlled-mirror\packages `
  -HashPinnedLockPath C:\controlled-mirror\requirements.hashes.lock `
  -InstallDependencies
```

The deployment environment must preserve the repository authority bundle and
must not replace the standards validator with the compatibility subset.

## 2. Candidate bootstrap

Initialize a new store and local authorization control plane. Keep production
data outside this workspace until a written migration decision exists.

```powershell
& $py -m pmiri.cli init .pmiri-sqlite --backend sqlite
& $py -m pmiri.cli init-control-plane .pmiri-control/control.db
& $py -m pmiri.cli add-dir .pmiri-sqlite project-alpha fixtures/s0/project-alpha --backend sqlite
```

Run the complete local candidate checks before serving any read surface:

```powershell
& $py -m unittest discover -s tests
& $py -m pmiri.cli integrity .
& $py -m pmiri.cli acceptance .
& $py -m pmiri.cli d2-runtime .
& $py -m pmiri.cli rfc-status .
& $py -m pmiri.cli deployment-smoke .
& $py -m pmiri.cli readiness . --profile deployment-profile.example.json
& $py -m pmiri.cli final-acceptance . --readiness artifacts/deployment-readiness-report.json
& $py -m pmiri.cli review-package .
```

`readiness` is expected to exit non-zero while any `EXT-*` check is blocked.
That is a safety result, not an operational failure to hide.

`final-acceptance` is a separate fail-closed gate. In this local candidate it
is expected to exit non-zero with FA-01..FA-06 blocked. It may report
`FINAL_ACCEPTANCE_READY` only when the target deployment supplies valid,
independently reviewed signed assertions for D2 acceptance, R-FC 17/17 PASS,
migration/restore/failover, independent review and operations approval. A
`DEPLOYMENT_READY` readiness result alone cannot promote final acceptance.

In the authorized deployment, readiness can consume a separately managed
Ed25519-signed evidence bundle. The public key must be trusted out-of-band;
the bundle must bind to the active profile and documentation authority and
contain independent evidence for EXT-01 through EXT-06:

```powershell
& $py -m pmiri.cli readiness . --profile deployment-profile.example.json `
  --external-evidence C:\controlled\deployment-evidence.json `
  --external-public-key C:\controlled\deployment-authority.pub
```

The verifier performs no external observation itself. It only accepts a valid
signature, key identity, fingerprint bindings and distinct reviewer record;
missing, malformed or changed evidence remains blocked.

The deployment evidence producer must emit exactly
`PMIRI-DEPLOYMENT-EXTERNAL-EVIDENCE` version `0.1` with `status=VERIFIED`, the active `profile_id`, the
active profile SHA-256, the documentation `authority_fingerprint`, six ordered
checks `EXT-01` through `EXT-06`, an issuer with role
`deployment_authority`, a distinct accepted reviewer, `payload_sha256` and a
base64 Ed25519 `signature`. Each check must contain its canonical assertion,
`result=READY`, at least one non-empty evidence reference, a non-empty
observation and an `observed_fingerprint` over its unsigned fields. The
signature covers the canonical JSON payload including `payload_sha256`.

The repository provides `scripts/build_signed_evidence.py` for packaging
observations collected by the authorized deployment. It is not an observer
and cannot make a blocked check READY by itself. The operator must supply all
expected IDs and an independent reviewer must approve the review reference:

```json
{
  "issuer_principal_id": "deployment-authority",
  "reviewer_id": "independent-reviewer",
  "review_evidence_ref": "controlled://review/accepted",
  "checks": {
    "EXT-01": {"evidence_refs": ["controlled://evidence/ext-01"], "observation": "..."},
    "EXT-02": {"evidence_refs": ["controlled://evidence/ext-02"], "observation": "..."},
    "EXT-03": {"evidence_refs": ["controlled://evidence/ext-03"], "observation": "..."},
    "EXT-04": {"evidence_refs": ["controlled://evidence/ext-04"], "observation": "..."},
    "EXT-05": {"evidence_refs": ["controlled://evidence/ext-05"], "observation": "..."},
    "EXT-06": {"evidence_refs": ["controlled://evidence/ext-06"], "observation": "..."}
  }
}
```

Keep the deployment-owned Ed25519 private key outside the repository. The
helper refuses to overwrite an existing output, self-verifies the signed
artifact, and never copies the private key into it:

```powershell
& $py scripts/build_signed_evidence.py external `
  --project-root C:\PMIRI\source `
  --profile C:\PMIRI\profile.json `
  --observations C:\controlled\external-observations.json `
  --private-key C:\controlled\deployment-authority.key `
  --output C:\controlled\deployment-evidence.json
```

For final acceptance, run the `final` subcommand only after readiness reports
`DEPLOYMENT_READY`; it binds FA-02..FA-06 to that readiness report fingerprint
and rejects an invalid or blocked report. Do not place generated evidence or
private keys in the source tree unless the deployment retention policy
explicitly requires it.

After both signed bundles are available, the complete read-only closure check
can be run without rewriting candidate artifacts:

```powershell
& $py scripts/verify_deployment_closure.py `
  --project-root C:\PMIRI\source `
  --profile C:\PMIRI\source\deployment-profile.example.json `
  --external-evidence C:\controlled\deployment-evidence.json `
  --external-public-key C:\controlled\deployment-authority.pub `
  --final-evidence C:\controlled\final-acceptance-evidence.json `
  --final-public-key C:\controlled\final-acceptance-authority.pub
```

It exits non-zero and reports the exact blocked checks until every gate is
ready; it reports `DEPLOYMENT_CLOSURE_READY` only when readiness and final
acceptance both pass. This command itself performs no external execution.

After readiness is ready, final acceptance requires a separate
`PMIRI-FINAL-ACCEPTANCE-EVIDENCE` version `0.1` bound to the exact readiness
report fingerprint. Its required assertions are FA-02 (34 controlled D2
scenarios accepted), FA-03 (17/17 R-FC PASS), FA-04 (migration/restore/failover
accepted), FA-05 (independent D2/R-FC review accepted) and FA-06 (operations
approval). Each assertion must carry the exact expected values, evidence
references, observation and fingerprint, and it must be signed by a deployment
authority with a different reviewer identity. These artifacts are inputs to
the verifier, not files to be filled with local or synthetic observations.

After the checks pass locally, start the candidate in a separate terminal:

```powershell
& $py -m pmiri.cli serve-local --profile deployment-profile.example.json
```

The profile supplies the SQLite store, control-plane and audit paths when the
positional store and `--control-plane` override are omitted; relative paths
resolve beside the profile file. Explicit paths remain supported for controlled
overrides.

The server prints `SERVING_LOOPBACK_ONLY`, the active profile ID/fingerprint and
the effective storage/control-plane paths, and binds only to `127.0.0.1`. Stop
it with Ctrl+C. The local control plane contains no principals after bootstrap,
so requests remain unauthorized until an approved local/deployed identity
adapter registers them; no identity provider is created by this command.
For a deployment-owned identity/revocation service and distributed
coordination plane, construct the server through
`pmiri.server.build_local_read_server` and inject a fully initialized
`ServerAuthorizationAdapters` set (and, when approved, a `BlobCipher`). The
assembly validates the required adapter surface and policy epoch and refuses
invalid injection; this seam does not grant public bind, TLS or network
authority.

The selected deployment route is the package-level host-native launcher with
an explicit deployment-owned adapter contract:

```powershell
& $py -m pmiri.cli serve-deployment `
  --profile C:\controlled\pmiri\profile.json `
  --adapter-module company_pmiri_adapters `
  --adapter-dir C:\controlled\pmiri\adapters `
  --adapter-config C:\controlled\pmiri\adapter-config.json
```

This command is only an adapter-injection and loopback assembly path. It does
not prove VM/OS isolation, deployed identity, distributed failover, KMS/key
escrow, real transport, independent review or final acceptance.

The Windows VM route is intentionally deferred. Its executable deployment pack
remains available in [`deployment/vm/README.md`](deployment/vm/README.md) for
a later isolated deployment, but it is not part of the current acceptance
path. Gateway/TLS exposure, KMS/escrow, control-plane failover and independent
review evidence remain deployment-owned prerequisites.

Example controlled start:

```powershell
& $py deployment\vm\serve_vm.py `
  --profile C:\controlled\pmiri\profile.json `
  --adapter-module company_pmiri_adapters `
  --adapter-dir C:\controlled\pmiri\adapters `
  --adapter-config C:\controlled\pmiri\adapter-config.json
```

Materialize the immutable clean-room/review handoff after the local candidate
checks. The destination must not already exist; transfer this bundle to the
authorized environment and have the independent reviewer verify its manifest
before any replay is attempted.

The authorized environment must also provide the implementation-under-test as
an importable module with `HANDLERS` and a digest-bound manifest. Generate the
manifest only after the exact handler source has been selected:

```powershell
& $py -m pmiri.cli rfc-handler-manifest . --handler-module your_handlers --output artifacts/r-fc-handler-manifest.json
```

`rfc-run` requires that manifest and verifies the module source fingerprint and
every dispatched handler symbol before execution. A changed source file or
missing manifest blocks the case.

```powershell
& .\scripts\create_handoff.ps1 -ProjectRoot . -PythonPath $py
```

The complete local release-candidate sequence is available as one command:

```powershell
& .\scripts\create_release_candidate.ps1 -ProjectRoot . -PythonPath $py
```

It materializes a bootstrap handoff for the workspace integration test, runs
the full test suite, then refreshes the seal and materializes the final
immutable handoff. `-SkipTests` is permitted only when the same workspace test
run has already completed successfully.

When tests are enabled, the first printed handoff is only a bootstrap for the
dirty-workspace integration test. Use the final printed `handoff_manifest=`
path for external transfer; it is created after the test suite and final seal.

The helper chooses the next unused `handoff-release-vN` directory and refuses
to reuse an existing directory. The two manifest types have different scopes and must not be substituted for
one another. `artifacts/sealed/<case>/artifact-manifest.json` seals the
candidate workspace root and can include inputs that are intentionally not
copied into the reduced handoff payload. The handoff's
`handoff-manifest.json` is the authoritative transfer inventory: after
unpacking, verify it against the `payload/` directory and use its per-file
fingerprints for the external review. Neither manifest is an acceptance
decision; the external attestation and independent review remain required.

## 3. Migration, canary and backup/recovery rehearsal

Always inspect the source and destination before migration. The dry-run reads
the complete source history and reports its canonical fingerprint, project and
record counts, but never creates the target database. Migration refuses an
existing target database, so a canary uses a new destination beside the source.

```powershell
& $py -m pmiri.cli migrate-json-to-sqlite .pmiri .pmiri-sqlite-canary --dry-run
& $py -m pmiri.cli migrate-json-to-sqlite .pmiri .pmiri-sqlite-canary
& $py -m pmiri.cli query .pmiri-sqlite-canary project-alpha "release status" --backend sqlite
```

Backups are verified by canonical fingerprint and restore only into a new
destination. Never overwrite a live store during a rehearsal.

```powershell
& $py -m pmiri.cli backup-sqlite .pmiri-sqlite .pmiri-sqlite-backup
& $py -m pmiri.cli restore-sqlite .pmiri-sqlite-backup .pmiri-sqlite-restored
& $py -m pmiri.cli query .pmiri-sqlite-restored project-alpha "release status" --backend sqlite
```

For an actual rollout, record the dry-run source fingerprint, migrated target
fingerprint, backup fingerprint, restore fingerprint, query comparison and
rollback decision in the change record. Rollback means keeping the source or
last verified backup serving, stopping the canary, and promoting only a newly
verified restore; never overwrite an existing store during rollback. A dry-run
or local smoke does not authorize production migration.

## 4. Stop conditions

Stop and preserve the evidence if any of these occurs:

- a dependency is missing or differs from `requirements.lock`;
- authority/schema fingerprints or a sealed artifact do not verify;
- the local store or control plane fails its integrity/WAL/full-sync probe;
- a caller attempts to supply authorization, operation or cursor authority;
- network default-deny is not observed;
- a preflight, attestation, reviewer or deployment profile is missing;
- a requested action would require production data, real credentials, external
  DNS/TLS/network I/O, or independent acceptance not present in the workspace.

## 5. Promotion evidence still required

The current candidate remains blocked until the environment supplies
independent clean-room evidence, deployed identity/revocation, distributed
control-plane failover, metadata/volume encryption and key escrow, authorized
provider/connector network execution, and an independent Gate-D R2 decision.
The handoff helper runs the read-only local audit against the exact new
manifest, the active profile and the current source tree before returning
success; it must establish `LOCAL_CANDIDATE_VERIFIED`. The audit compares the
canonical profile file fingerprint with the readiness report, so a changed
profile or source tree requires a fresh readiness/final/review chain and a new
immutable handoff.
The audit’s `EXTERNAL_CLOSURE_PENDING` result remains truthful until
independently signed deployment evidence is supplied. For a separately
materialized handoff, run `scripts/verify_candidate.py --profile
deployment-profile.example.json --handoff-manifest
artifacts/handoff-release-vN/handoff-manifest.json` with that manifest’s
in-project path.
After those dependencies are available, rerun the readiness report, all
controlled D2/R-FC cases, migration/recovery rehearsal and independent review.
