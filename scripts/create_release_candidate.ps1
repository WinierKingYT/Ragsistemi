param(
    [string]$ProjectRoot = ".",
    [string]$PythonPath,
    [string]$FixtureId = "GC-C1-FC01",
    [string]$CaseId = "GC-C1-FC01-P",
    [string]$OfflinePackageDir,
    [string]$HashPinnedLockPath,
    [switch]$InstallDependencies,
    [switch]$SkipTests
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
$handoffScript = Join-Path $root "scripts\create_handoff.ps1"
if (-not (Test-Path -LiteralPath $handoffScript -PathType Leaf)) {
    throw "Release-candidate handoff helper is missing: $handoffScript"
}

$profilePath = Join-Path $root "deployment-profile.example.json"
$readinessPath = Join-Path $root "artifacts\deployment-readiness-report.json"
$finalAcceptancePath = Join-Path $root "artifacts\final-acceptance-gate.json"
$reviewPackagePath = Join-Path $root "artifacts\review-package.json"

function Refresh-CandidateReportChain {
    # Reports are byte-bound review inputs. Refresh all derived reports before
    # every handoff so a manually rerun smoke cannot leave stale fingerprints.
    & $PythonPath -m pmiri.cli readiness . --profile $profilePath --output $readinessPath | Out-Null
    $readinessExit = $LASTEXITCODE
    if ($readinessExit -notin @(0, 1)) {
        throw "Release-candidate readiness refresh failed with exit code $readinessExit"
    }

    & $PythonPath -m pmiri.cli final-acceptance . --readiness $readinessPath --output $finalAcceptancePath | Out-Null
    $finalAcceptanceExit = $LASTEXITCODE
    if ($finalAcceptanceExit -notin @(0, 1)) {
        throw "Release-candidate final-acceptance refresh failed with exit code $finalAcceptanceExit"
    }

    & $PythonPath -m pmiri.cli review-package . --output $reviewPackagePath | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Release-candidate review-package refresh failed with exit code $LASTEXITCODE"
    }
}

Push-Location $root
$previousSourceDateEpoch = $env:SOURCE_DATE_EPOCH
$env:SOURCE_DATE_EPOCH = "946684800"
try {
    if ($InstallDependencies) {
        if ([string]::IsNullOrWhiteSpace($OfflinePackageDir) -or -not (Test-Path -LiteralPath $OfflinePackageDir -PathType Container)) {
            throw "-OfflinePackageDir must identify an existing offline package mirror when -InstallDependencies is used."
        }
        if (-not [string]::IsNullOrWhiteSpace($HashPinnedLockPath)) {
            if (-not (Test-Path -LiteralPath $HashPinnedLockPath -PathType Leaf)) {
                throw "-HashPinnedLockPath must identify an existing hash-pinned lock when supplied."
            }
            & $PythonPath scripts/verify_supply_chain.py --lock $HashPinnedLockPath --artifact-dir (Get-Item -LiteralPath $OfflinePackageDir).FullName
            if ($LASTEXITCODE -ne 0) {
                throw "Release-candidate hash-pinned mirror verification failed with exit code $LASTEXITCODE"
            }
        }
        $lockPath = Join-Path $root "requirements.lock"
        & $PythonPath -m pip install --no-index --find-links (Get-Item -LiteralPath $OfflinePackageDir).FullName --requirement $lockPath
        if ($LASTEXITCODE -ne 0) {
            throw "Release-candidate offline dependency installation failed with exit code $LASTEXITCODE"
        }
    } elseif (-not [string]::IsNullOrWhiteSpace($OfflinePackageDir)) {
        throw "-OfflinePackageDir requires -InstallDependencies."
    } elseif (-not [string]::IsNullOrWhiteSpace($HashPinnedLockPath)) {
        throw "-HashPinnedLockPath requires -InstallDependencies and -OfflinePackageDir."
    }

    & $PythonPath scripts/verify_reproducibility.py --check-installed
    if ($LASTEXITCODE -ne 0) {
        throw "Release-candidate Python environment does not match requirements.lock; refusing to create a candidate."
    }

    & $PythonPath scripts/generate_sbom.py
    if ($LASTEXITCODE -ne 0) {
        throw "Release-candidate SBOM generation failed with exit code $LASTEXITCODE"
    }
    & $PythonPath scripts/generate_sbom.py --check
    if ($LASTEXITCODE -ne 0) {
        throw "Release-candidate SBOM verification failed with exit code $LASTEXITCODE"
    }

    if (-not $SkipTests) {
        # The workspace integration test expects an existing verified handoff.
        # Materialize a bootstrap candidate first; the final seal/handoff below
        # is the release artifact produced after the test suite has completed.
        & $PythonPath -m pmiri.cli seal . s0-acceptance --output-dir artifacts/sealed/s0-acceptance | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Release-candidate bootstrap seal failed with exit code $LASTEXITCODE"
        }
        Refresh-CandidateReportChain
        & $PythonPath -m pmiri.cli seal . s0-acceptance --output-dir artifacts/sealed/s0-acceptance | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Release-candidate bootstrap final seal failed with exit code $LASTEXITCODE"
        }
        & $handoffScript -ProjectRoot $root -PythonPath $PythonPath -FixtureId $FixtureId -CaseId $CaseId
        if ($LASTEXITCODE -ne 0) {
            throw "Release-candidate bootstrap handoff failed with exit code $LASTEXITCODE"
        }

        & $PythonPath -m unittest discover -s tests -p "test_*.py"
        if ($LASTEXITCODE -ne 0) {
            throw "Release-candidate test suite failed with exit code $LASTEXITCODE"
        }
    }

    & $PythonPath -m pmiri.cli seal . s0-acceptance --output-dir artifacts/sealed/s0-acceptance | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Release-candidate seal failed with exit code $LASTEXITCODE"
    }

    Refresh-CandidateReportChain

    # final-acceptance is included in the case seal; refresh it once more
    # after all report generation and before the immutable handoff.
    & $PythonPath -m pmiri.cli seal . s0-acceptance --output-dir artifacts/sealed/s0-acceptance | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Release-candidate final seal failed with exit code $LASTEXITCODE"
    }

    & $handoffScript -ProjectRoot $root -PythonPath $PythonPath -FixtureId $FixtureId -CaseId $CaseId
    if ($LASTEXITCODE -ne 0) {
        throw "Release-candidate handoff failed with exit code $LASTEXITCODE"
    }
} finally {
    if ($null -eq $previousSourceDateEpoch) {
        Remove-Item Env:SOURCE_DATE_EPOCH -ErrorAction SilentlyContinue
    } else {
        $env:SOURCE_DATE_EPOCH = $previousSourceDateEpoch
    }
    Pop-Location
}
