from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pmiri.canonical import canonical_json, sha256_bytes, sha256_json
from pmiri.deployment_evidence import FINAL_ACCEPTANCE_ASSERTIONS, DeploymentEvidenceError, verify_final_acceptance_evidence
from pmiri.final_acceptance import build_final_acceptance_report, validate_final_acceptance_report


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class FinalAcceptanceTests(unittest.TestCase):
    def _signed_evidence(self, directory: Path, readiness: dict) -> tuple[Path, Path]:
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        assertions = []
        for check_id, assertion, observed_values in FINAL_ACCEPTANCE_ASSERTIONS:
            item = {
                "check_id": check_id,
                "assertion": assertion,
                "result": "READY",
                "observed_values": dict(observed_values),
                "evidence_refs": ["external://final/" + check_id.lower()],
                "observation": "controlled environment evidence",
            }
            item["observed_fingerprint"] = sha256_json({key: item[key] for key in ("check_id", "assertion", "result", "observed_values", "evidence_refs", "observation")})
            assertions.append(item)
        unsigned = {
            "artifact_kind": "PMIRI-FINAL-ACCEPTANCE-EVIDENCE",
            "version": "0.1",
            "status": "VERIFIED",
            "profile_id": readiness["profile_id"],
            "profile_fingerprint": readiness["profile_fingerprint"],
            "authority_fingerprint": readiness["authority_fingerprint"],
            "readiness_report_fingerprint": readiness["report_fingerprint"],
            "assertions": assertions,
            "issuer": {"key_id": sha256_bytes(public_key), "principal_id": "deployment-authority", "role": "deployment_authority"},
            "independent_review": {"reviewer_id": "independent-reviewer", "review_result": "ACCEPTED", "evidence_ref": "external://final/review"},
        }
        payload_sha256 = sha256_json(unsigned)
        record = {
            **unsigned,
            "payload_sha256": payload_sha256,
            "signature": base64.b64encode(private_key.sign(canonical_json({**unsigned, "payload_sha256": payload_sha256}))).decode("ascii"),
        }
        evidence_path = directory / "final-evidence.json"
        public_key_path = directory / "final-public-key.bin"
        evidence_path.write_text(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
        public_key_path.write_bytes(public_key)
        return evidence_path, public_key_path

    def _ready_readiness_copy(self, directory: Path) -> dict:
        readiness = json.loads((PROJECT_ROOT / "artifacts/deployment-readiness-report.json").read_text(encoding="utf-8"))
        for item in readiness["checks"]:
            if item["check_id"].startswith("EXT-"):
                item["result"] = "READY"
                item["observation"] = "test-only controlled deployment observation"
                item["evidence_refs"] = ["external://test/" + item["check_id"].lower()]
                item["observed_fingerprint"] = sha256_json({key: item[key] for key in ("check_id", "category", "assertion", "result", "observation", "evidence_refs")})
        readiness["overall_result"] = "DEPLOYMENT_READY"
        readiness["report_fingerprint"] = sha256_json({key: readiness[key] for key in readiness if key != "report_fingerprint"})
        readiness_path = directory / "readiness.json"
        readiness_path.write_text(json.dumps(readiness, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
        return readiness

    def test_workspace_gate_is_fail_closed_and_self_validating(self):
        report = build_final_acceptance_report(PROJECT_ROOT, captured_at="2026-01-01T00:00:00Z")
        self.assertEqual(report["overall_result"], "FINAL_ACCEPTANCE_BLOCKED")
        self.assertEqual([item["check_id"] for item in report["checks"] if item["result"] == "BLOCKED"], ["FA-01", "FA-02", "FA-03", "FA-04", "FA-05", "FA-06"])
        self.assertEqual(validate_final_acceptance_report(report), ())

    def test_verified_final_evidence_requires_all_claims_and_binds_readiness(self):
        with TemporaryDirectory() as temp:
            directory = Path(temp)
            readiness = self._ready_readiness_copy(directory)
            evidence_path, key_path = self._signed_evidence(directory, readiness)
            report = build_final_acceptance_report(
                PROJECT_ROOT,
                readiness_path=directory / "readiness.json",
                evidence_path=evidence_path,
                public_key_path=key_path,
                captured_at="2026-01-01T00:00:00Z",
            )
            self.assertEqual(report["overall_result"], "FINAL_ACCEPTANCE_READY")
            self.assertEqual(report["external_evidence_status"], "VERIFIED")
            self.assertEqual(validate_final_acceptance_report(report), ())

            record = json.loads(evidence_path.read_text(encoding="utf-8"))
            record["assertions"][0]["observed_values"]["scenario_count"] = 33
            evidence_path.write_text(json.dumps(record), encoding="utf-8")
            with self.assertRaisesRegex(DeploymentEvidenceError, "final_acceptance_evidence_assertion_values_invalid"):
                verify_final_acceptance_evidence(
                    evidence_path,
                    trusted_public_key=key_path.read_bytes(),
                    profile_id=readiness["profile_id"],
                    profile_fingerprint=readiness["profile_fingerprint"],
                    authority_fingerprint=readiness["authority_fingerprint"],
                    readiness_report_fingerprint=readiness["report_fingerprint"],
                )

    def test_gate_rejects_partial_evidence_arguments(self):
        report = build_final_acceptance_report(PROJECT_ROOT, evidence_path="missing.json")
        self.assertEqual(report["external_evidence_status"], "INVALID")
        self.assertEqual(report["overall_result"], "FINAL_ACCEPTANCE_BLOCKED")

    def test_final_evidence_rejects_security_sensitive_mutations(self):
        with TemporaryDirectory() as temp:
            directory = Path(temp)
            readiness = self._ready_readiness_copy(directory)
            expected_args = {
                "profile_id": readiness["profile_id"],
                "profile_fingerprint": readiness["profile_fingerprint"],
                "authority_fingerprint": readiness["authority_fingerprint"],
                "readiness_report_fingerprint": readiness["report_fingerprint"],
            }
            mutations = (
                ("fields", lambda record: record.update({"extra": True}), "final_acceptance_evidence_fields_invalid"),
                ("issuer", lambda record: record["issuer"].update({"role": "reviewer"}), "final_acceptance_evidence_issuer_invalid"),
                ("review", lambda record: record["independent_review"].update({"review_result": "PENDING"}), "final_acceptance_evidence_review_invalid"),
                ("identity", lambda record: record["assertions"][0].update({"assertion": "WRONG"}), "final_acceptance_evidence_assertion_identity_invalid"),
                ("refs", lambda record: record["assertions"][0].update({"evidence_refs": []}), "final_acceptance_evidence_assertion_refs_invalid"),
                ("observation", lambda record: record["assertions"][0].update({"observation": ""}), "final_acceptance_evidence_assertion_observation_invalid"),
                ("assertion_fingerprint", lambda record: record["assertions"][0].update({"observation": "tampered"}), "final_acceptance_evidence_assertion_fingerprint_mismatch"),
                ("payload", lambda record: record.update({"payload_sha256": "0" * 64}), "final_acceptance_evidence_payload_fingerprint_mismatch"),
                ("signature_encoding", lambda record: record.update({"signature": "not-base64"}), "final_acceptance_evidence_signature_invalid"),
                ("signature", lambda record: record.update({"signature": "AA=="}), "final_acceptance_evidence_signature_mismatch"),
            )
            for name, mutate, expected_error in mutations:
                with self.subTest(name=name):
                    evidence_path, key_path = self._signed_evidence(directory, readiness)
                    record = json.loads(evidence_path.read_text(encoding="utf-8"))
                    mutate(record)
                    evidence_path.write_text(json.dumps(record), encoding="utf-8")
                    with self.assertRaisesRegex(DeploymentEvidenceError, expected_error):
                        verify_final_acceptance_evidence(evidence_path, trusted_public_key=key_path.read_bytes(), **expected_args)

            evidence_path, key_path = self._signed_evidence(directory, readiness)
            with self.assertRaisesRegex(DeploymentEvidenceError, "final_acceptance_evidence_key_id_mismatch"):
                verify_final_acceptance_evidence(evidence_path, trusted_public_key=b"0" * 32, **expected_args)
            with self.assertRaisesRegex(DeploymentEvidenceError, "deployment_public_key_encoding_invalid"):
                verify_final_acceptance_evidence(evidence_path, trusted_public_key=b"not-a-key", **expected_args)
            with self.assertRaisesRegex(DeploymentEvidenceError, "final_acceptance_evidence_readiness_binding_mismatch"):
                verify_final_acceptance_evidence(evidence_path, trusted_public_key=key_path.read_bytes(), **{**expected_args, "readiness_report_fingerprint": "0" * 64})

    def test_review_binding_rejects_resigned_report_from_another_root(self):
        report = build_final_acceptance_report(PROJECT_ROOT, captured_at="2026-01-01T00:00:00Z")
        report["project_root"] = "C:/foreign/pmiri"
        report["report_fingerprint"] = sha256_json({key: report[key] for key in report if key != "report_fingerprint"})
        self.assertIn("project_root_binding_mismatch", validate_final_acceptance_report(report, project_root=PROJECT_ROOT))

    def test_ready_report_requires_verified_evidence_fingerprint(self):
        report = build_final_acceptance_report(PROJECT_ROOT, captured_at="2026-01-01T00:00:00Z")
        for item in report["checks"]:
            item["result"] = "READY"
            item["observed_fingerprint"] = sha256_json({key: item[key] for key in ("check_id", "assertion", "result", "observation", "evidence_refs", "severity")})
        report["status"] = "FINAL_ACCEPTANCE_READY"
        report["overall_result"] = "FINAL_ACCEPTANCE_READY"
        report["report_fingerprint"] = sha256_json({key: report[key] for key in report if key != "report_fingerprint"})
        errors = validate_final_acceptance_report(report)
        self.assertIn("ready_without_verified_evidence", errors)

    def test_cli_accepts_verified_final_evidence_contract(self):
        with TemporaryDirectory() as temp:
            directory = Path(temp)
            readiness = self._ready_readiness_copy(directory)
            evidence_path, key_path = self._signed_evidence(directory, readiness)
            output_path = directory / "final-gate.json"
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(PROJECT_ROOT) + os.pathsep + environment.get("PYTHONPATH", "")
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pmiri.cli",
                    "final-acceptance",
                    str(PROJECT_ROOT),
                    "--readiness",
                    str(readiness_path := directory / "readiness.json"),
                    "--evidence",
                    str(evidence_path),
                    "--public-key",
                    str(key_path),
                    "--output",
                    str(output_path),
                ],
                cwd=PROJECT_ROOT,
                env=environment,
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            summary = json.loads(result.stdout)
            self.assertEqual(summary["status"], "FINAL_ACCEPTANCE_READY")
            self.assertEqual(summary["external_evidence_status"], "VERIFIED")
            report = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(validate_final_acceptance_report(report), ())


if __name__ == "__main__":
    unittest.main()
