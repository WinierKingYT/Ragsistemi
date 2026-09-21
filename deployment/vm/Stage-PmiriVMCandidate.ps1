#requires -RunAsAdministrator

[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$')]
    [string]$VmName = 'pmiri-app-vm',
    [string]$GuestPath = 'C:\PMIRI\source\deployment\vm\Smoke-PmiriVMCandidate.ps1'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$sourcePath = Join-Path $PSScriptRoot 'Smoke-PmiriVMCandidate.ps1'
if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
    throw "Host smoke script is missing: $sourcePath"
}

$vm = Get-VM -Name $VmName -ErrorAction Stop
if ([string]$vm.State -ne 'Running') {
    throw "VM must be running before staging: $VmName"
}

$guestService = @(Get-VMIntegrationService -VMName $VmName -ErrorAction Stop | Where-Object {
        $_.Name -match '(?i)guest.*service|konuk.*hizmet'
    })
if ($guestService.Count -ne 1 -or -not $guestService[0].Enabled) {
    throw "Guest Service Interface is not enabled for VM: $VmName"
}

Copy-VMFile `
    -VMName $VmName `
    -SourcePath $sourcePath `
    -DestinationPath $GuestPath `
    -FileSource Host `
    -CreateFullPath `
    -Force

$hash = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash
[ordered]@{
    status = 'VM_SMOKE_SCRIPT_STAGED'
    vm_name = $VmName
    source = $sourcePath
    destination = $GuestPath
    sha256 = $hash
    transport = 'GUEST_SERVICE_INTERFACE'
} | ConvertTo-Json -Compress
