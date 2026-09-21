#requires -RunAsAdministrator

[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$')]
    [string]$VmName = 'pmiri-app-vm'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$vm = Get-VM -Name $VmName -ErrorAction Stop
$firmware = Get-VMFirmware -VMName $VmName -ErrorAction Stop
$adapters = @(Get-VMNetworkAdapter -VMName $VmName -ErrorAction Stop)
$guestService = @(Get-VMIntegrationService -VMName $VmName -ErrorAction Stop | Where-Object {
        $_.Name -match '(?i)guest.*service|konuk.*hizmet'
    })

$failures = [System.Collections.Generic.List[string]]::new()
if ([string]$vm.State -ne 'Running') {
    $failures.Add('vm_not_running')
}
if ([string]$firmware.SecureBoot -ne 'On') {
    $failures.Add('secure_boot_not_on')
}
if ($adapters.Count -ne 0) {
    $failures.Add('network_adapters_present')
}
if ($guestService.Count -ne 1) {
    $failures.Add('guest_service_not_uniquely_identified')
} elseif (-not $guestService[0].Enabled) {
    $failures.Add('guest_service_disabled')
}

$result = [ordered]@{
    status = if ($failures.Count -eq 0) { 'VM_ISOLATION_CHECK_PASS' } else { 'VM_ISOLATION_CHECK_BLOCKED' }
    vm_name = $VmName
    state = [string]$vm.State
    generation = [int]$vm.Generation
    secure_boot = [string]$firmware.SecureBoot
    network_adapters = $adapters.Count
    guest_service_enabled = if ($guestService.Count -eq 1) { [bool]$guestService[0].Enabled } else { $false }
    guest_service_status = if ($guestService.Count -eq 1) { [string]$guestService[0].PrimaryStatusDescription } else { 'NOT_FOUND' }
    failures = @($failures)
    network = if ($adapters.Count -eq 0) { 'NOT_ATTACHED' } else { 'ATTACHED' }
}
$result | ConvertTo-Json -Compress
if ($failures.Count -ne 0) {
    exit 2
}
