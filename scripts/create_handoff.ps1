param(
    [string]$ProjectRoot = ".",
    [string]$PythonPath,
    [string]$FixtureId = "GC-C1-FC01",
    [string]$CaseId = "GC-C1-FC01-P"
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path -LiteralPath $ProjectRoot).Path
if ([string]::IsNullOrWhiteSpace($PythonPath)) {
    $localExactPython = Join-Path $root ".venv-pmiri-exact\Scripts\python.exe"
    if (Test-Path -LiteralPath $localExactPython -PathType Leaf) {
        $PythonPath = (Resolve-Path -LiteralPath $localExactPython).Path
    } else {
        $PythonPath = "python"
    }
}
$artifactRoot = Join-Path $root "artifacts"
$nextVersion = 1

if (Test-Path -LiteralPath $artifactRoot -PathType Container) {
    $versions = @(
        Get-ChildItem -LiteralPath $artifactRoot -Directory -Filter "handoff-release-v*" |
            ForEach-Object {
                if ($_.Name -match '^handoff-release-v([1-9][0-9]*)$') {
                    [int]$Matches[1]
                }
            }
    )
    if ($versions.Count -gt 0) {
        $nextVersion = ([int](($versions | Measure-Object -Maximum).Maximum)) + 1
    }
}

$relativeOutput = "artifacts/handoff-release-v$nextVersion"
$outputPath = Join-Path $root ($relativeOutput -replace '/', '\\')
if (Test-Path -LiteralPath $outputPath) {
    throw "Refusing to reuse existing immutable handoff directory: $outputPath"
}

Push-Location $root
try {
    & $PythonPath -m pmiri.cli handoff . --output $relativeOutput --fixture-id $FixtureId --case-id $CaseId
    if ($LASTEXITCODE -ne 0) {
        throw "PMIRI handoff creation failed with exit code $LASTEXITCODE"
    }
    $manifestPath = Join-Path $outputPath "handoff-manifest.json"
    & $PythonPath (Join-Path $root "scripts\verify_candidate.py") --root $root --profile (Join-Path $root "deployment-profile.example.json") --handoff-manifest $manifestPath | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "PMIRI local release-candidate audit failed for $manifestPath"
    }
    Write-Output ("handoff_manifest=" + $manifestPath)
} finally {
    Pop-Location
}
