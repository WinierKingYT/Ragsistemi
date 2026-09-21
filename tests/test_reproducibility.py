from pathlib import Path
import unittest

from scripts.verify_reproducibility import read_lock, verify_installed, verify_project_contract


class ReproducibilityTests(unittest.TestCase):
    def test_lock_matches_project_and_build_contract(self):
        locked = read_lock()
        self.assertEqual(verify_project_contract(locked), [])

    def test_workspace_runtime_matches_exact_lock(self):
        self.assertEqual(verify_installed(read_lock()), [])

    def test_ci_workflow_preserves_release_gates(self):
        workflow = (Path(__file__).parents[1] / ".github" / "workflows" / "pmiri.yml").read_text(encoding="utf-8")
        required_fragments = (
            "python scripts/verify_supply_chain.py --lock artifacts/vm-offline-requirements-hashed.lock --artifact-dir artifacts/vm-offline-packages",
            "python -m pip install --no-index --find-links artifacts/vm-offline-packages --requirement artifacts/vm-offline-requirements-hashed.lock",
            "python -m pip wheel --no-deps --no-build-isolation .",
            "SOURCE_DATE_EPOCH: \"946684800\"",
            "pmiri-wheel-a",
            "pmiri-wheel-b",
            "Get-FileHash -Algorithm SHA256",
            "wheel reproducibility mismatch",
            "$installTarget = Join-Path $env:RUNNER_TEMP \"pmiri-install\"",
            "$sourceRoot = $env:GITHUB_WORKSPACE",
            "-FilePath $env:GITHUB_ENV",
            "PYTHONPATH=$installTarget;$sourceRoot",
            "Push-Location $env:RUNNER_TEMP",
            "finally { Pop-Location }",
            "sys.path.remove('')",
            "runpy.run_module('unittest',run_name='__main__')",
            "$smokeReport = Join-Path $workspace \"artifacts\\deployment-smoke-report.json\"",
            "python -m pmiri.cli deployment-smoke $workspace --output $smokeReport",
            "python -m pmiri.cli init (Join-Path $workspace \".pmiri-sqlite\") --backend sqlite",
            "python -m pmiri.cli init-control-plane (Join-Path $workspace \".pmiri-control\\control.db\")",
            "$reviewPackage = Join-Path $workspace \"artifacts\\review-package.json\"",
            "python -m pmiri.cli readiness $workspace --profile $profile --output $readinessReport",
            "$readinessExit = $LASTEXITCODE",
            "$finalGateReport = Join-Path $workspace \"artifacts\\final-acceptance-gate.json\"",
            "python -m pmiri.cli final-acceptance $workspace --readiness $readinessReport --output $finalGateReport",
            "$finalGateExit = $LASTEXITCODE",
            "FINAL_ACCEPTANCE_BLOCKED",
            "python -m pmiri.cli review-package $workspace --output $reviewPackage",
            '$handoffRoot = Join-Path $workspace "artifacts\\handoff-ci"',
            '& (Join-Path $workspace "scripts\\create_release_candidate.ps1")',
            "python -m pmiri.cli handoff $workspace --output $handoffRoot",
            "from pmiri.handoff import verify_handoff",
            "verify_handoff(r'$handoffManifest', project_root=r'$workspace')",
            "scripts\\verify_candidate.py",
            "--profile $profile",
            "--handoff-manifest $handoffManifest",
            "python -m pmiri.cli integrity $workspace",
        )
        for fragment in required_fragments:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, workflow)
        self.assertIn('expected = @("EXT-01", "EXT-02", "EXT-03", "EXT-04", "EXT-05", "EXT-06")', workflow)
        self.assertIn('finalExpected = @("FA-01", "FA-02", "FA-03", "FA-04", "FA-05", "FA-06")', workflow)
        self.assertLess(
            workflow.index("python -m pmiri.cli deployment-smoke $workspace"),
            workflow.index("python -m pmiri.cli readiness $workspace --profile $profile"),
        )
        self.assertLess(
            workflow.index("python -m pmiri.cli readiness $workspace --profile $profile"),
            workflow.index("python -m pmiri.cli final-acceptance $workspace"),
        )
        self.assertLess(
            workflow.index("python -m pmiri.cli final-acceptance $workspace"),
            workflow.index("python -m pmiri.cli review-package $workspace"),
        )
        self.assertLess(
            workflow.index("python -m pmiri.cli review-package $workspace"),
            workflow.rindex('& (Join-Path $workspace "scripts\\create_release_candidate.ps1")'),
        )
        self.assertLess(
            workflow.rindex('& (Join-Path $workspace "scripts\\create_release_candidate.ps1")'),
            workflow.index("python -m pmiri.cli handoff $workspace --output $handoffRoot"),
        )

    def test_release_candidate_helper_orders_tests_seal_and_handoff(self):
        helper = (Path(__file__).parents[1] / "scripts" / "create_release_candidate.ps1").read_text(encoding="utf-8")
        for fragment in (
            "[switch]$SkipTests",
            "[switch]$InstallDependencies",
            "[string]$OfflinePackageDir",
            "[string]$HashPinnedLockPath",
            "--no-index",
            "scripts/verify_supply_chain.py",
            "--lock $HashPinnedLockPath",
            "--artifact-dir (Get-Item -LiteralPath $OfflinePackageDir).FullName",
            "scripts/verify_reproducibility.py --check-installed",
            "scripts/generate_sbom.py",
            "scripts/generate_sbom.py --check",
            "-m unittest discover",
            "pmiri.cli seal",
            "scripts\\create_handoff.ps1",
            "finally {",
            "IsNullOrWhiteSpace($PythonPath)",
            ".venv-pmiri-exact\\Scripts\\python.exe",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, helper)
        self.assertLess(helper.index("pmiri.cli seal"), helper.index("-m unittest discover"))
        self.assertLess(helper.index("& $handoffScript -ProjectRoot"), helper.index("-m unittest discover"))
        self.assertLess(helper.index("verify_reproducibility.py --check-installed"), helper.index("scripts/generate_sbom.py"))
        self.assertLess(helper.index("scripts/generate_sbom.py --check"), helper.index("pmiri.cli seal"))
        self.assertLess(helper.rindex("pmiri.cli seal"), helper.rindex("& $handoffScript -ProjectRoot"))

    def test_release_candidate_refreshes_report_chain_before_final_handoff(self):
        helper = (Path(__file__).parents[1] / "scripts" / "create_release_candidate.ps1").read_text(encoding="utf-8")
        for fragment in (
            "readiness . --profile $profilePath --output $readinessPath",
            "function Refresh-CandidateReportChain",
            "$readinessExit -notin @(0, 1)",
            "final-acceptance . --readiness $readinessPath --output $finalAcceptancePath",
            "$finalAcceptanceExit -notin @(0, 1)",
            "review-package . --output $reviewPackagePath",
            "# final-acceptance is included in the case seal",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, helper)
        self.assertLess(helper.index("readiness . --profile $profilePath"), helper.index("review-package . --output $reviewPackagePath"))
        self.assertLess(helper.index("review-package . --output $reviewPackagePath"), helper.rindex("pmiri.cli seal"))
        self.assertLess(helper.rindex("pmiri.cli seal"), helper.rindex("& $handoffScript -ProjectRoot"))
        self.assertGreaterEqual(helper.count("pmiri.cli seal"), 4)


if __name__ == "__main__":
    unittest.main()
