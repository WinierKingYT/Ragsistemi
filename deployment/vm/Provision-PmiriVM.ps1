#requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$')]
    [string]$VmName,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$IsoPath,

    [string]$VmRoot = 'C:\PMIRI-VM',

    [ValidateRange(2GB, 64GB)]
    [UInt64]$StartupMemoryBytes = 4GB,

    [ValidateRange(1, 32)]
    [int]$ProcessorCount = 4,

    [ValidateRange(32GB, 2048GB)]
    [UInt64]$VhdSizeBytes = 80GB,

    [switch]$Start
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) {
    throw 'Hyper-V PowerShell tools are not available.'
}

$sourceIso = (Get-Item -LiteralPath $IsoPath -ErrorAction Stop).FullName
$root = [IO.Path]::GetFullPath($VmRoot)
$vmPath = Join-Path $root $VmName
$vhdPath = Join-Path $root "$VmName.vhdx"
$iso = Join-Path $root ([IO.Path]::GetFileName($sourceIso))

if (Get-VM -Name $VmName -ErrorAction SilentlyContinue) {
    throw "A VM named '$VmName' already exists; refusing to modify it."
}
if (Test-Path -LiteralPath $vmPath) {
    throw "The VM directory already exists; refusing to reuse it: $vmPath"
}
if (Test-Path -LiteralPath $vhdPath) {
    throw "The VHDX already exists; refusing to reuse it: $vhdPath"
}
if ((-not [StringComparer]::OrdinalIgnoreCase.Equals($sourceIso, $iso)) -and (Test-Path -LiteralPath $iso)) {
    throw "The VM-root install media already exists; refusing to overwrite it: $iso"
}

if ($PSCmdlet.ShouldProcess($VmName, 'Create isolated Generation 2 PMIRI VM')) {
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    New-Item -ItemType Directory -Path $vmPath -Force | Out-Null
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($sourceIso, $iso)) {
        # Keep the source media untouched and place a local copy beside the
        # VM. Hyper-V firmware is more reliable with VM-owned local media
        # than with an ISO under a user profile or a redirected path.
        Copy-Item -LiteralPath $sourceIso -Destination $iso -Force:$false
        $sourceLength = (Get-Item -LiteralPath $sourceIso).Length
        $copiedLength = (Get-Item -LiteralPath $iso).Length
        if ($sourceLength -ne $copiedLength) {
            throw "The copied install media length does not match the source: $iso"
        }
    }
    New-VHD -Path $vhdPath -SizeBytes $VhdSizeBytes -Dynamic | Out-Null

    # No -SwitchName is supplied. The new VM receives no external network
    # connection; PMIRI's loopback-only boundary remains the default.
    New-VM `
        -Name $VmName `
        -Generation 2 `
        -MemoryStartupBytes $StartupMemoryBytes `
        -VHDPath $vhdPath `
        -Path $vmPath | Out-Null

    # Enforce the isolation invariant instead of relying only on the absence
    # of -SwitchName. Hyper-V defaults or host policy must not leave a NIC on
    # the newly-created VM.
    $networkAdapters = @(Get-VMNetworkAdapter -VMName $VmName)
    foreach ($networkAdapter in $networkAdapters) {
        Remove-VMNetworkAdapter -VMNetworkAdapter $networkAdapter -Confirm:$false
    }
    if (@(Get-VMNetworkAdapter -VMName $VmName).Count -ne 0) {
        throw "The new VM has a network adapter after isolation cleanup; refusing to continue."
    }

    Set-VMProcessor -VMName $VmName -Count $ProcessorCount
    # Automatic checkpoints create an unbounded differencing-disk chain and
    # are not a substitute for the explicit application backup/restore flow.
    Set-VM `
        -Name $VmName `
        -AutomaticStartAction Nothing `
        -AutomaticStopAction ShutDown `
        -AutomaticCheckpointsEnabled $false
    Set-VMFirmware -VMName $VmName -EnableSecureBoot On -SecureBootTemplate 'MicrosoftWindows'
    $dvd = Add-VMDvdDrive -VMName $VmName -Path $iso
    # Make the install path explicit. Some Hyper-V firmware configurations
    # retain a stale File entry ahead of the DVD even after FirstBootDevice.
    $firmware = Get-VMFirmware -VMName $VmName
    $dvdBoot = $firmware.BootOrder | Where-Object {
        $_.Device -is [Microsoft.HyperV.PowerShell.DvdDrive]
    }
    $diskBoot = $firmware.BootOrder | Where-Object {
        $_.Device -is [Microsoft.HyperV.PowerShell.HardDiskDrive]
    }
    if (-not $dvdBoot -or -not $diskBoot) {
        throw 'The new VM does not expose both DVD and hard-disk firmware boot entries.'
    }
    Set-VMFirmware -VMName $VmName -BootOrder $dvdBoot, $diskBoot

    $status = 'VM_CREATED_OS_INSTALL_PENDING'
    if ($Start) {
        Start-VM -Name $VmName | Out-Null
        $status = 'VM_STARTED_OS_INSTALL_PENDING'
    }

    [ordered]@{
        status = $status
        vm_name = $VmName
        generation = 2
        memory_bytes = $StartupMemoryBytes
        processor_count = $ProcessorCount
        vm_path = $vmPath
        vhd_path = $vhdPath
        source_install_media = $sourceIso
        install_media = $iso
        external_network = 'NOT_ATTACHED'
        network_adapters = 0
        automatic_checkpoints = 'DISABLED'
        next_step = 'Install Windows from the attached ISO, then run the PMIRI VM bootstrap.'
    } | ConvertTo-Json -Compress
}
