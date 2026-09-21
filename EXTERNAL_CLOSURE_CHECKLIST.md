# PMIRI external closure checklist

This checklist is the handoff from the verified local candidate to an
authorized deployment. It is an execution checklist, not external evidence.
Do not mark an item `READY` from a local simulation, a configuration file or a
self-authored observation. Every `READY` result below must be independently
observed in the controlled deployment, bound to the immutable candidate and
signed by the deployment authority.

## Immutable baseline

Use the latest verified handoff reported by the read-only candidate audit
(`scripts/verify_candidate.py --root .`). Do not rebuild or edit that immutable
handoff in place. The versioned path below is intentionally resolved from the
audit output rather than hard-coded here.

```text
manifest: <latest verified manifest from candidate audit>
profile_id: workspace-local-candidate
profile_fingerprint: 0dbdff1675beccf3c9f74b722c33365fe4e467297491da04f673d7dcfa3235f9
authority_fingerprint: 9a5628f336cc6332128ad434ac0bad478933d5e76baa53f2982fbc1b2ef49b8b
```

The local candidate audit is currently `LOCAL_CANDIDATE_VERIFIED` with zero
local failures. This does not promote any external check and does not replace
the independent reviewer.

## Required roles

Assign three separate responsibilities before execution:

| Role | Responsibility |
|---|---|
| Deployment authority | Owns the target infrastructure, adapter configuration and signing key |
| Operations owner | Approves migration, restore, failover, rotation and rollback outcomes |
| Independent reviewer | Rechecks Gate-D, D2 and R-FC results; must not be the deployment authority |

Never send passwords, private keys, KMS material or service tokens to this
chat. Keep them in the controlled environment and share only evidence paths and
public keys for verification.

## Closure sequence

### EXT-01 — clean-room boundary

1. Freeze and hash the handoff manifest, payload, profile, authority bundle,
   fixture catalog, preflight matrix and runner package.
2. In the authorized clean-room, run PF-01..PF-16 from the controlled launcher
   with a fresh case root. The eight isolation domains must be observed with
   these exact outcomes: `network=DENIED`, `credentials=DENIED`,
   `filesystem=ALLOWLIST_VERIFIED`, `connectors=DENIED`,
   `determinism=VERIFIED`, `resource_limits=VERIFIED`, `teardown=AVAILABLE`,
   `privacy=VERIFIED`.
3. Have an observer independent of the launcher operator record the evidence
   references and sign the attestation against the exact fingerprints.

The local Hyper-V smoke proves loopback health and teardown only; it is not an
independent clean-room attestation.

### EXT-02 — deployed identity and revocation

Deploy the approved IdP/revocation gateway and inject an adapter module that
implements `build_authorization_adapters(config)`. Exercise valid identity,
invalid identity, revocation after retrieval, gateway binding and credential
redaction. Record the gateway logs and request IDs in the signed evidence.

### EXT-03 — distributed control plane

Provide at least two deployment-owned control-plane instances. Exercise atomic
replay consumption, rate limiting, monotonic policy-epoch updates, instance
loss and recovery. Prove that a failover cannot accept replayed or stale
policy state. Record both instance identities, failover timestamps and the
resulting audit entries.

### EXT-04 — encryption, escrow and recovery

Run the candidate on the approved encrypted metadata/volume path with the
deployment KMS/DPAPI and key-escrow adapter. Exercise key creation, rotation,
escrow retrieval, encrypted backup and restore. The operations owner must sign
the recovery and rollback result; raw key material must never enter evidence.

### EXT-05 — authorized real transport

Only after EXT-01..EXT-04 pass, enable the approved provider/connector path.
Capture DNS resolution, selected-address pinning, TLS identity, final
revalidation, credential boundary, response-size limits and guaranteed
teardown. Any resolver, TLS, policy or limit mismatch must stop the run and
remain `BLOCKED`.

### EXT-06 / final acceptance — independent replay and review

Run all 34 D2 scenarios and all 17 R-FC obligations with the pinned handler
manifest and clean-room records. R-FC is `PASS` only when all 17 obligations
are accepted by the independent reviewer. Obtain a separate Gate-D R2 review,
then repeat migration/restore/failover and obtain operations approval.

## Evidence files to provide for final verification

The deployment authority should keep the private signing keys local and make
the following files available to the verifier:

```text
C:\controlled\deployment-evidence.json
C:\controlled\deployment-authority.pub
C:\controlled\final-acceptance-evidence.json
C:\controlled\final-acceptance-authority.pub
```

Build the external bundle only from real observations:

```powershell
& $py C:\PMIRI\source\scripts\build_signed_evidence.py external `
  --project-root C:\PMIRI\source `
  --profile C:\PMIRI\source\deployment-profile.example.json `
  --observations C:\controlled\external-observations.json `
  --private-key C:\controlled\deployment-authority.key `
  --output C:\controlled\deployment-evidence.json
```

Then ask the independent reviewer to produce the final-acceptance assertion
set. Once both bundles exist, run the read-only closure verifier:

```powershell
& $py C:\PMIRI\source\scripts\verify_deployment_closure.py `
  --project-root C:\PMIRI\source `
  --profile C:\PMIRI\source\deployment-profile.example.json `
  --external-evidence C:\controlled\deployment-evidence.json `
  --external-public-key C:\controlled\deployment-authority.pub `
  --final-evidence C:\controlled\final-acceptance-evidence.json `
  --final-public-key C:\controlled\final-acceptance-authority.pub
```

The only acceptable terminal output is `DEPLOYMENT_CLOSURE_READY`. Missing,
unsigned, stale or tampered evidence must remain blocked.

## What I can do after handoff

Given the evidence paths and public keys, I can run the closure verifier,
diagnose schema/fingerprint/signature/binding failures, regenerate local
readiness and final-acceptance reports, and prepare the final verified package.
I cannot replace the deployment authority, operate an unavailable IdP/KMS or
act as the independent reviewer.
