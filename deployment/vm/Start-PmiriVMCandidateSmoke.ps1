#requires -Version 5.1

[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$')]
    [string]$VmName = 'pmiri-app-vm',
    [string]$GuestSmokePath = 'C:\PMIRI\source\deployment\vm\Smoke-PmiriVMCandidate.ps1'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$targetScript = Join-Path $PSScriptRoot 'Invoke-PmiriVMCandidateSmoke.ps1'
if (-not (Test-Path -LiteralPath $targetScript -PathType Leaf)) {
    throw "Host smoke orchestrator is missing: $targetScript"
}
if ($GuestSmokePath.Contains('"')) {
    throw 'GuestSmokePath must not contain a double quote.'
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$administrator = [Security.Principal.WindowsBuiltInRole]::Administrator

if (-not $principal.IsInRole($administrator)) {
    # Preserve the fail-closed elevation requirement of the underlying host
    # helpers while making the operator flow usable from a normal shell.
    $argumentList = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -VmName "{1}" -GuestSmokePath "{2}"' -f `
        $targetScript, $VmName, $GuestSmokePath
    $elevated = Start-Process `
        -FilePath 'PowerShell.exe' `
        -Verb RunAs `
        -ArgumentList $argumentList `
        -Wait `
        -PassThru
    if ($null -eq $elevated) {
        exit 1
    }
    exit $elevated.ExitCode
}

& $targetScript -VmName $VmName -GuestSmokePath $GuestSmokePath
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
