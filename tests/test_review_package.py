from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from pmiri.canonical import sha256_json
from pmiri.review_package import (
    ReviewPackageError,
    REVIEW_PACKAGE_KIND,
    REVIEW_PACKAGE_STATUS,
    build_review_package,
    validate_review_package,
)


class ReviewPackageTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parents[1]

    def test_review_package_covers_local_candidate_and_external_boundary(self):
        package = build_review_package(self.root)
        self.assertEqual(package["artifact_kind"], REVIEW_PACKAGE_KIND)
        self.assertEqual(package["status"], REVIEW_PACKAGE_STATUS)
        self.assertEqual(package["external_execution"], "NOT_PERFORMED")
        self.assertEqual(package["promotion_result"], "DEPLOYMENT_READINESS_BLOCKED")
        self.assertEqual(len(package["evidence_inventory"]), 11)
        self.assertEqual(package["acceptance_inventory"]["preflight"]["observed_checks"], 16)
        self.assertEqual(package["acceptance_inventory"]["d2"]["observed_scenarios"], 34)
        self.assertEqual(package["acceptance_inventory"]["r_fc"]["blocked_obligations"], 17)
        self.assertEqual(package["acceptance_inventory"]["local_r_fc_handlers"]["oracle_matches"], 34)
        self.assertEqual(package["acceptance_inventory"]["final_acceptance"]["overall_result"], "FINAL_ACCEPTANCE_BLOCKED")
        closure = package["closure_matrix"]
        self.assertEqual(
            [item["requirement_id"] for item in closure["local_candidate"]],
            ["LOCAL-REL-01", "LOCAL-CANDIDATE-01", "LOCAL-SECURITY-01", "LOCAL-VERIFICATION-01"],
        )
        self.assertTrue(all(item["state"] == "BLOCKED_EXTERNAL" for item in closure["external_readiness"] + closure["final_acceptance"]))
        self.assertEqual(closure["external_readiness"][0]["observed_result"], "BLOCKED")
        self.assertEqual(validate_review_package(package, project_root=self.root), ())

    def test_review_package_rejects_tampered_closure_state(self):
        package = build_review_package(self.root)
        package["closure_matrix"]["external_readiness"][0]["state"] = "READY_EXTERNAL"
        unsigned = {key: value for key, value in package.items() if key != "review_package_fingerprint"}
        package["review_package_fingerprint"] = sha256_json(unsigned)
        self.assertIn("project_binding_mismatch", validate_review_package(package, project_root=self.root))

    def test_review_package_self_fingerprint_is_tamper_evident(self):
        package = build_review_package(self.root)
        package["scope"] = "ALTERED"
        self.assertIn("self_fingerprint_mismatch", validate_review_package(package))

    def test_review_package_remains_bound_to_current_reports_after_resigning(self):
        package = build_review_package(self.root)
        package["promotion_result"] = "DEPLOYMENT_READY"
        unsigned = {key: value for key, value in package.items() if key != "review_package_fingerprint"}
        package["review_package_fingerprint"] = sha256_json(unsigned)
        self.assertIn("project_binding_mismatch", validate_review_package(package, project_root=self.root))

    def test_review_package_rejects_incomplete_preflight_record(self):
        original_read_json = __import__("pmiri.review_package", fromlist=["_read_json"])._read_json

        def read_json(root, relative):
            data, raw = original_read_json(root, relative)
            if relative == "artifacts/preflight-record.json":
                data = dict(data)
                data["checks"] = list(data["checks"][:-1])
            return data, raw

        with patch("pmiri.review_package._read_json", side_effect=read_json):
            with self.assertRaisesRegex(ReviewPackageError, "preflight_inventory_incomplete"):
                build_review_package(self.root)


if __name__ == "__main__":
    unittest.main()
