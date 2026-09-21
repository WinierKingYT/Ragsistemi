#requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
    [string]$ProjectRoot,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$PythonPath,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$ProfilePath,

    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
    [string]$OfflinePackageDir,

    [switch]$InstallDependencies,
    [switch]$InitializeStore
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = (Get-Item -LiteralPath $ProjectRoot).FullName
$profile = (Get-Item -LiteralPath $ProfilePath).FullName
$profileDirectory = Split-Path -Parent $profile
$profileObject = Get-Content -LiteralPath $profile -Raw -Encoding UTF8 | ConvertFrom-Json

if ($profileObject.network.mode -ne 'DENY_BY_DEFAULT' -or $profileObject.network.external_execution -ne 'DISABLED') {
    throw 'The VM bootstrap refuses a profile that enables external network execution.'
}
if ($profileObject.api.transport -ne 'HTTP_LOOPBACK' -or $profileObject.api.bind_host -ne '127.0.0.1') {
    throw 'The VM bootstrap refuses a non-loopback API profile.'
}
if ($profileObject.storage.backend -ne 'sqlite' -or [string]::IsNullOrWhiteSpace([string]$profileObject.storage.root)) {
    throw 'The VM bootstrap requires an initialized SQLite content-store profile.'
}

if ($InstallDependencies -and [string]::IsNullOrWhiteSpace($OfflinePackageDir)) {
    throw '-OfflinePackageDir is required with -InstallDependencies; public package indexes are never used.'
}

$env:PYTHONPATH = if ([string]::IsNullOrWhiteSpace($env:PYTHONPATH)) { $root } else { $root + [IO.Path]::PathSeparator + $env:PYTHONPATH }

function Invoke-PythonChecked {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [Parameter(Mandatory = $true)]
        [string]$FailureMessage
    )

    & $PythonPath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FailureMessage (exit code $LASTEXITCODE)"
    }
}

if ($InstallDependencies) {
    $lockPath = Join-Path $root 'requirements.lock'
    if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) {
        throw "requirements.lock is missing: $lockPath"
    }
    Invoke-PythonChecked `
        -Arguments @('-m', 'pip', 'install', '--no-index', '--find-links', (Get-Item -LiteralPath $OfflinePackageDir).FullName, '--requirement', $lockPath) `
        -FailureMessage 'Offline dependency installation failed'
}

$versionOutput = & $PythonPath '--version' 2>&1
if ($LASTEXITCODE -ne 0 -or ($versionOutput -notmatch 'Python 3\.12(?:\.|$)')) {
    throw "Python 3.12 is required; observed: $versionOutput"
}

Invoke-PythonChecked `
    -Arguments @('-c', 'import sys; from pmiri.readiness import load_profile; load_profile(sys.argv[1])', $profile) `
    -FailureMessage 'PMIRI deployment profile validation failed'

$storageRoot = [string]$profileObject.storage.root
if (-not [IO.Path]::IsPathRooted($storageRoot)) {
    $storageRoot = Join-Path $profileDirectory $storageRoot
}
$storageRoot = [IO.Path]::GetFullPath($storageRoot)

if ($InitializeStore) {
    Invoke-PythonChecked `
        -Arguments @('-m', 'pmiri.cli', 'init', $storageRoot, '--backend', 'sqlite') `
        -FailureMessage 'PMIRI SQLite store initialization failed'
}

if (-not (Test-Path -LiteralPath (Join-Path $storageRoot 'pmiri.sqlite3') -PathType Leaf)) {
    throw "The PMIRI SQLite store is not initialized: $storageRoot"
}

[ordered]@{
    status = 'VM_BOOTSTRAP_LOCAL_READY_EXTERNAL_PENDING'
    project_root = $root
    python = (Get-Item -LiteralPath $PythonPath).FullName
    profile = $profile
    storage = $storageRoot
    network = 'DENY_BY_DEFAULT'
    api_bind = '127.0.0.1'
    external_evidence = 'NOT_CREATED'
    next_step = 'Provide the deployment-owned adapter module, then start serve_vm.py.'
} | ConvertTo-Json -Compress
