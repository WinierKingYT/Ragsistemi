# Windows VM deployment pack

The selected deployment platform is a Windows VM. This pack makes the
deployment seam executable without pretending that the workspace owns an
identity provider, distributed control plane, KMS, network gateway or an
independent reviewer.

## Target topology

| Role | Responsibility | Minimum closure requirement |
|---|---|---|
| `pmiri-app-vm` | PMIRI SQLite content store, loopback read server, audit, health and metrics | One hardened Windows VM is enough for the single-node application candidate |
| `pmiri-control-vm-a` and `pmiri-control-vm-b` | Deployment-owned identity/revocation, replay guard, rate limiter and monotonic policy epoch | Two independently failure-tested control-plane instances are needed for EXT-03 |
| Gateway / observer / reviewer | Approved identity gateway, TLS termination, isolation observation and independent acceptance | Must be controlled and reviewed outside the application VM |

The application server still binds only to `127.0.0.1`. A gateway may expose an
approved endpoint only after the deployment has separately established TLS,
identity and network evidence. The launcher never opens a public listener.

For the isolated local-candidate smoke path only, the repository includes
`local_candidate_adapters.py` and
`local-candidate-adapter-config.example.json`. This module initializes the
existing SQLite control-plane adapters and is useful for proving that the VM
launcher and loopback server assemble correctly. It is not a production
identity, revocation, distributed-coordination or key-escrow implementation;
it must not be used to claim EXT-01..EXT-06 or final acceptance.

## Prerequisites supplied by the deployment

- Windows Server VM with Python 3.12 and a service account with least privilege.
- Trusted offline package mirror and a deployment-managed hash-pinned lock.
- An initialized SQLite content store on an approved encrypted data volume.
- An importable adapter module implementing the contract below.
- An approved KMS/key escrow integration when content encryption or key rotation is enabled.
- At least two control-plane instances if failover is claimed.
- An approved gateway/IdP, DNS/TLS configuration and a separate operator/reviewer identity.

Do not put passwords, private keys or raw KMS material in the adapter config JSON.
Pass references, handles or deployment-specific secret-manager locations instead.

## Adapter contract

The deployment-owned module must expose:

```python
def build_authorization_adapters(config: Mapping[str, Any]) -> ServerAuthorizationAdapters:
    ...
```

It may also expose:

```python
def build_blob_cipher(config: Mapping[str, Any]) -> BlobCipher | None:
    ...
```

The returned authorization adapters must already be initialized and implement
identity/revocation, replay consumption, atomic rate limiting and policy-epoch
read/advance. `serve_vm.py` rejects a missing or invalid adapter before the
HTTP socket is created. It does not initialize or fall back to local SQLite
authorization state.

## Controlled start

Run the local checks and supply a deployment-approved profile first. Relative
profile paths resolve beside the profile; absolute paths may point to the
approved encrypted data volume.

[`profile.example.json`](profile.example.json) is a non-secret starting
template for that deployment profile. It deliberately requires content
encryption, external volume protection, external KMS and an injected control
plane; it is not evidence that those services exist.

```powershell
$py = 'C:\Python312\python.exe'
& $py -m pmiri.cli init 'D:\PMIRI\content' --backend sqlite
& $py deployment\vm\serve_vm.py `
  --profile 'D:\PMIRI\profile.json' `
  --adapter-module 'company_pmiri_adapters' `
  --adapter-dir 'D:\PMIRI\adapters' `
  --adapter-config 'D:\PMIRI\adapter-config.json'
```

The first output line must report `SERVING_LOOPBACK_ONLY`, host
`127.0.0.1`, the active profile fingerprint and the effective paths. Stop the
process with Ctrl+C. A service wrapper may invoke the same command only after
the deployment has reviewed the profile, adapter package and service account.

## VM provisioning

When a Windows Server ISO and Hyper-V administrator token are available, the
provided script creates a fresh Generation 2 VM with Secure Boot, a dynamic
VHDX, zero virtual NICs and disabled automatic checkpoints. It copies the
source ISO into the VM root without modifying the source file, attaches that
local copy, refuses to reuse an existing VM, VHDX or VM-root media copy, and
sets the UEFI boot order explicitly to DVD first and disk second so a stale
firmware `File` entry cannot bypass the installer. It then stops at
`OS_INSTALL_PENDING`:

```powershell
PowerShell -ExecutionPolicy Bypass -File .\deployment\vm\Provision-PmiriVM.ps1 `
  -VmName pmiri-app-vm `
  -IsoPath C:\ISO\WindowsServer.iso `
  -VmRoot D:\HyperV\PMIRI
```

The script removes any NIC Hyper-V may create by default and asserts the
zero-NIC invariant before continuing. Automatic checkpoints remain disabled;
the explicit application backup/restore flow is the recovery mechanism. It
does not install Windows, create accounts, attach a public network, or claim
isolation evidence. Complete the OS installation and independent clean-room
observation before running the PMIRI bootstrap.

After Windows is installed, run the bootstrap from an elevated PowerShell. It
validates Python 3.12, the profile and loopback/default-deny invariants. When
`-InstallDependencies` is supplied, the offline packages are installed before
the PMIRI profile import so a clean Python installation can validate the
profile without a missing dependency. It uses only the supplied offline
package directory. `-InitializeStore` creates the SQLite content store and
nothing else:

The host may stage `Install-PmiriVM.ps1` together with the official Python
3.12.10 x64 installer. Run that helper from an elevated guest PowerShell to
verify the installer SHA-256, install Python to `C:\Python312`, install the
staged packages with no index access, and invoke the bootstrap in one repeatable
sequence. The helper refuses any installer with a different hash:

```powershell
PowerShell -ExecutionPolicy Bypass -File C:\PMIRI\Install-PmiriVM.ps1
```

If the host operator prefers not to type the guest command in VMConnect, the
host helper prompts for the guest credential locally and invokes the same
script through PowerShell Direct. The credential is not written to output and
the helper refuses any VM with a network adapter:

```powershell
PowerShell -ExecutionPolicy Bypass -File .\deployment\vm\Invoke-PmiriVMBootstrap.ps1
```

```powershell
PowerShell -File .\deployment\vm\Bootstrap-PmiriVM.ps1 `
  -ProjectRoot C:\PMIRI\source `
  -PythonPath C:\Python312\python.exe `
  -ProfilePath C:\PMIRI\profile.json `
  -OfflinePackageDir C:\PMIRI\packages `
  -InstallDependencies `
  -InitializeStore
```

The result is `VM_BOOTSTRAP_LOCAL_READY_EXTERNAL_PENDING`; it deliberately does
not create signed evidence or close any EXT-* requirement.

To run the local-candidate loopback smoke server after bootstrap, stage the
adapter module and config, then use the effective Python path reported by the
bootstrap:

```powershell
$py = 'C:\\Program Files\\Python312\\python.exe'
& $py C:\\PMIRI\\source\\deployment\\vm\\serve_vm.py `
  --profile C:\\PMIRI\\profile.json `
  --adapter-module local_candidate_adapters `
  --adapter-dir C:\\PMIRI\\source\\deployment\\vm `
  --adapter-config C:\\PMIRI\\local-candidate-adapter-config.json
```

The first line must report `SERVING_LOOPBACK_ONLY`. Stop the process with
Ctrl+C. This smoke path is local-only and remains externally unaccepted.

Before running the guest smoke, the host operator can run this read-only
isolation preflight from an elevated Hyper-V PowerShell:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\deployment\vm\Test-PmiriVMIsolation.ps1
```

It requires a running Generation 2 VM, Secure Boot `On`, zero virtual NICs and
an enabled Guest Service Interface. Any violation returns
`VM_ISOLATION_CHECK_BLOCKED` and exit code `2`; it never changes VM state.

For a repeatable runtime check that starts and stops the server itself, stage
`Smoke-PmiriVMCandidate.ps1` and run it from an elevated guest PowerShell:

```powershell
# Run this first from an elevated host Hyper-V PowerShell to eliminate stale
# guest copies of the smoke helper:
PowerShell.exe -ExecutionPolicy Bypass -File .\deployment\vm\Stage-PmiriVMCandidate.ps1

# Then run this inside the guest VM from an elevated PowerShell:
PowerShell.exe -ExecutionPolicy Bypass -File C:\\PMIRI\\source\\deployment\\vm\\Smoke-PmiriVMCandidate.ps1
```

The staging helper verifies that the VM is running and its Guest Service
Interface is enabled, copies the host-controlled script through Hyper-V
integration services, and prints its SHA-256. It does not attach a NIC or
change VM firmware. The smoke script checks `/healthz`, an unauthenticated `/v1/read/search` denial, `/metrics`
and the redacted 401 audit event, writes short-lived process logs below
`C:\\PMIRI\\source\\.pmiri-vm-smoke`, and always tears down the child server.
Its success marker is `VM_LOCAL_HTTP_SMOKE_PASS`.

The complete host-side flow can be run with one elevated command. It performs
the read-only isolation preflight, stages the current smoke script, asks for a
guest credential locally, and invokes the smoke through PowerShell Direct:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\deployment\vm\Invoke-PmiriVMCandidateSmoke.ps1
```

The credential is not written to disk or included in output. The helper still
compares the guest script SHA-256 with the host source before execution; it
does not attach a NIC, change firmware or create external evidence.

If the current host shell is not elevated, use the convenience launcher below.
It requests normal Windows UAC elevation and then delegates to the same
fail-closed host orchestrator; it does not bypass or weaken any VM check:

```powershell
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File .\deployment\vm\Start-PmiriVMCandidateSmoke.ps1
```

When the authorized deployment has collected real observations, package them
with the repository helper from outside the VM source tree:

```powershell
& $PythonPath C:\PMIRI\source\scripts\build_signed_evidence.py external `
  --project-root C:\PMIRI\source `
  --profile C:\PMIRI\profile.json `
  --observations C:\controlled\external-observations.json `
  --private-key C:\controlled\deployment-authority.key `
  --output C:\controlled\deployment-evidence.json
```

The helper signs supplied observations only, refuses output overwrite, and
self-verifies the bundle. It never observes external systems and never copies
the private key into the evidence. The separate `final` subcommand is valid
only after a `DEPLOYMENT_READY` readiness report and binds FA-02..FA-06 to its
fingerprint.

When both bundles are present, the host-side closure check is read-only:

```powershell
& $PythonPath C:\PMIRI\source\scripts\verify_deployment_closure.py `
  --project-root C:\PMIRI\source `
  --profile C:\PMIRI\source\deployment-profile.example.json `
  --external-evidence C:\controlled\deployment-evidence.json `
  --external-public-key C:\controlled\deployment-authority.pub `
  --final-evidence C:\controlled\final-acceptance-evidence.json `
  --final-public-key C:\controlled\final-acceptance-authority.pub
```

`DEPLOYMENT_CLOSURE_READY` is emitted only when both gates pass; no VM,
provider or identity service is contacted by this verifier.

## What this pack does not prove

Running this launcher locally proves only that the PMIRI assembly accepts the
deployment adapter contract and remains loopback-only. It does not create
EXT-01..EXT-06 or FA-01..FA-06 evidence. Those require independently observed
VM isolation, real deployment services, controlled D2/R-FC execution,
migration/restore/failover rehearsal and a reviewer who is separate from the
operator and deployment authority.
