#requires -RunAsAdministrator

[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$')]
    [string]$VmName = 'pmiri-app-vm',
    [string]$GuestSmokePath = 'C:\PMIRI\source\deployment\vm\Smoke-PmiriVMCandidate.ps1'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$isolationScript = Join-Path $PSScriptRoot 'Test-PmiriVMIsolation.ps1'
$stageScript = Join-Path $PSScriptRoot 'Stage-PmiriVMCandidate.ps1'
foreach ($path in @($isolationScript, $stageScript)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required host helper is missing: $path"
    }
}

$isolationOutput = @(
    & PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File $isolationScript -VmName $VmName
)
$isolationExitCode = [int]$LASTEXITCODE
if ($isolationExitCode -ne 0) {
    $isolationOutput | Write-Output
    throw "VM isolation preflight failed for: $VmName (exit code $isolationExitCode)"
}
$isolationOutput | Write-Output

& PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File $stageScript -VmName $VmName
$stageExitCode = [int]$LASTEXITCODE
if ($stageExitCode -ne 0) {
    throw "VM smoke staging failed for: $VmName (exit code $stageExitCode)"
}

$expectedHash = (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'Smoke-PmiriVMCandidate.ps1') -Algorithm SHA256).Hash
$credential = Get-Credential -Message "Enter a local administrator credential for $VmName. It is used only for this PowerShell Direct call."
$guestResult = Invoke-Command -VMName $VmName -Credential $credential -ScriptBlock {
    param([string]$SmokePath, [string]$ExpectedHash)

    $guestHash = (Get-FileHash -LiteralPath $SmokePath -Algorithm SHA256).Hash
    if ($guestHash -ne $ExpectedHash) {
        throw "Guest smoke script hash mismatch: expected $ExpectedHash, got $guestHash"
    }
    [ordered]@{
        status = 'VM_SMOKE_SCRIPT_HASH_VERIFIED'
        guest_script = $SmokePath
        sha256 = $guestHash
    } | ConvertTo-Json -Compress

    & PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File $SmokePath
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
} -ArgumentList $GuestSmokePath, $expectedHash

$guestResult | Write-Output
[ordered]@{
    status = 'VM_LOCAL_HTTP_SMOKE_INVOKED'
    vm_name = $VmName
    guest_script = $GuestSmokePath
    expected_sha256 = $expectedHash
    transport = 'POWERSHELL_DIRECT'
    credential_persisted = $false
} | ConvertTo-Json -Compress
