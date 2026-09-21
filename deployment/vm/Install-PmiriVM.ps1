#requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$PythonInstallerPath = 'C:\PMIRI\installers\python-3.12.10-amd64.exe',
    [string]$PythonHome = 'C:\Python312',
    [string]$ProjectRoot = 'C:\PMIRI\source',
    [string]$ProfilePath = 'C:\PMIRI\profile.json',
    [string]$OfflinePackageDir = 'C:\PMIRI\packages',
    [string]$BootstrapPath = 'C:\PMIRI\Bootstrap-PmiriVM.ps1',
    [string]$InstallerLogPath = 'C:\PMIRI\python-install.log'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$expectedInstallerSha256 = '67B5635E80EA51072B87941312D00EC8927C4DB9BA18938F7AD2D27B328B95FB'
if (-not (Test-Path -LiteralPath $PythonInstallerPath -PathType Leaf)) {
    throw "Python installer is missing: $PythonInstallerPath"
}
if (-not (Test-Path -LiteralPath $BootstrapPath -PathType Leaf)) {
    throw "PMIRI bootstrap script is missing: $BootstrapPath"
}

$installerHash = (Get-FileHash -LiteralPath $PythonInstallerPath -Algorithm SHA256).Hash
if ($installerHash -ne $expectedInstallerSha256) {
    throw "Python installer hash mismatch; refusing to execute: $installerHash"
}

$pythonExe = Join-Path $PythonHome 'python.exe'
function Get-PythonCandidatePaths {
    @(
        (Join-Path $PythonHome 'python.exe'),
        (Join-Path ${env:ProgramFiles} 'Python312\python.exe'),
        (Join-Path ${env:ProgramFiles} 'Python3.12\python.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Python312\python.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Python3.12\python.exe'),
        (Join-Path ${env:LocalAppData} 'Programs\Python\Python312\python.exe'),
        (Join-Path ${env:LocalAppData} 'Programs\Python\Python312-64\python.exe')
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -Unique
}

$existingPython = @(Get-PythonCandidatePaths)
if ($existingPython.Count -eq 1) {
    $pythonExe = [string]$existingPython[0]
    if ($pythonExe -ne (Join-Path $PythonHome 'python.exe')) {
        Write-Warning "Using the existing Python installation at: $pythonExe"
    }
} elseif ($existingPython.Count -gt 1) {
    throw "Multiple Python 3.12 candidates were found; refusing to guess: $($existingPython -join '; ')"
} else {
    New-Item -ItemType Directory -Path $PythonHome -Force | Out-Null
    Write-Output "PYTHON_INSTALL_START target=$PythonHome log=$InstallerLogPath"
    $installer = Start-Process `
        -FilePath $PythonInstallerPath `
        -ArgumentList @(
            '/quiet',
            '/log', $InstallerLogPath,
            'InstallAllUsers=1',
            'TargetDir=' + $PythonHome,
            'DefaultAllUsersTargetDir=' + $PythonHome,
            'Include_launcher=0',
            'InstallLauncherAllUsers=0',
            'PrependPath=0',
            'Include_test=0'
        ) `
        -Wait `
        -PassThru
    if ($installer.ExitCode -notin @(0, 3010)) {
        $existingPython = @(Get-PythonCandidatePaths)
        if ($existingPython.Count -eq 1) {
            $pythonExe = [string]$existingPython[0]
            Write-Warning "Python installer returned exit code $($installer.ExitCode), but a valid existing installation was found at: $pythonExe"
        } else {
            throw "Python installer failed with exit code $($installer.ExitCode); log: $InstallerLogPath"
        }
    }
}

if (-not (Test-Path -LiteralPath $pythonExe -PathType Leaf)) {
    throw "Python installation did not produce the expected executable: $pythonExe; installer log: $InstallerLogPath"
}
$versionOutput = & $pythonExe '--version' 2>&1
if ($LASTEXITCODE -ne 0 -or ($versionOutput -notmatch '^Python 3\.12(?:\.|$)')) {
    throw "Python 3.12 is required; observed: $versionOutput"
}

& $BootstrapPath `
    -ProjectRoot $ProjectRoot `
    -PythonPath $pythonExe `
    -ProfilePath $ProfilePath `
    -OfflinePackageDir $OfflinePackageDir `
    -InstallDependencies `
    -InitializeStore
if ($LASTEXITCODE -ne 0) {
    throw "PMIRI VM bootstrap failed with exit code $LASTEXITCODE"
}
