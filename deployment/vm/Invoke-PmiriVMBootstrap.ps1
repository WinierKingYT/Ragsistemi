#requires -RunAsAdministrator

[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$')]
    [string]$VmName = 'pmiri-app-vm',

    [PSCredential]$Credential
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$vm = Get-VM -Name $VmName -ErrorAction Stop
if ($vm.State -ne 'Running') {
    throw "The VM must be running before PowerShell Direct bootstrap: $VmName"
}
if (@(Get-VMNetworkAdapter -VMName $VmName).Count -ne 0) {
    throw "The VM has a network adapter; refusing to bootstrap outside the isolated path: $VmName"
}

if (-not $Credential) {
    $Credential = Get-Credential -Message "Enter the Windows guest administrator credential for $VmName. It is used only by PowerShell Direct and is not recorded."
}
if (-not $Credential) {
    throw 'A Windows guest credential is required.'
}

$result = Invoke-Command `
    -VMName $VmName `
    -Credential $Credential `
    -ScriptBlock {
        & 'C:\PMIRI\Install-PmiriVM.ps1'
        if ($LASTEXITCODE -ne 0) {
            throw "PMIRI guest installer failed with exit code $LASTEXITCODE"
        }
    } `
    -ErrorAction Stop

$result
