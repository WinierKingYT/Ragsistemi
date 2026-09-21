from __future__ import annotations

import unittest
from pathlib import Path

from pmiri.deployment_smoke import run_local_deployment_smoke, validate_deployment_smoke_report


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class DeploymentSmokeTests(unittest.TestCase):
    def test_local_deployment_recovery_chain_is_proven(self):
        report = run_local_deployment_smoke(PROJECT_ROOT, captured_at="2026-01-01T00:00:00Z")
        self.assertEqual(report["status"], "DEPLOYMENT_SMOKE_CANDIDATE")
        self.assertEqual(report["source_count"], 3)
        self.assertEqual(report["query_evidence_count"], 3)
        self.assertEqual(report["backup_fingerprint"], report["restored_fingerprint"])
        self.assertEqual(report["local_readiness_blocked_checks"], [])
        self.assertEqual(report["external_access"], "NOT_PERFORMED")
        self.assertEqual(validate_deployment_smoke_report(report), ())

    def test_smoke_report_fingerprint_is_tamper_evident(self):
        report = run_local_deployment_smoke(PROJECT_ROOT, captured_at="2026-01-01T00:00:00Z")
        report["query_evidence_count"] = 99
        self.assertIn("report_fingerprint_mismatch", validate_deployment_smoke_report(report))


if __name__ == "__main__":
    unittest.main()
