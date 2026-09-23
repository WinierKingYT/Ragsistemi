from __future__ import annotations

import base64
import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pmiri.canonical import canonical_json, sha256_bytes, sha256_json
from pmiri.deployment_evidence import FINAL_ACCEPTANCE_ASSERTIONS, FINAL_EVIDENCE_KIND, FINAL_EVIDENCE_VERSION
from pmiri.integrity import authority_fingerprint
from pmiri.readiness import REPORT_TYPE, REPORT_VERSION, _EXTERNAL_BLOCKERS, load_profile


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "verify_deployment_closure.py"
PROFILE_PATH = PROJECT_ROOT / "deployment-profile.example.json"


def _load_script():
    spec = importlib.util.spec_from_file_location("pmiri_deployment_closure_test", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load closure verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _ready_readiness(profile: dict) -> dict:
    check = {
        "check_id": "LOC-0001",
        "category": "CONFIGURATION",
        "assertion": "PROFILE_CONTRACT",
        "result": "READY",
        "observation": "valid controlled profile",
        "evidence_refs": ["local://profile"],
        "severity": "HARD_BLOCK",
    }
    check["observed_fingerprint"] = sha256_json({key: check[key] for key in ("check_id", "category", "assertion", "result", "observation", "evidence_refs")})
    unsigned = {
        "report_id": "readiness_test_closure",
        "report_type": REPORT_TYPE,
        "report_version": REPORT_VERSION,
        "project_root": PROJECT_ROOT.as_posix(),
        "profile_id": profile["profile_id"],
        "profile_fingerprint": sha256_json(profile),
        "authority_fingerprint": authority_fingerprint(PROJECT_ROOT),
        "captured_at": "2026-01-01T00:00:00Z",
        "checks": [check],
        "required_external_evidence": [
            {"check_id": check_id, "assertion": assertion, "reason": reason}
            for check_id, assertion, reason in _EXTERNAL_BLOCKERS
        ],
        "overall_result": "DEPLOYMENT_READY",
    }
    return {**unsigned, "report_fingerprint": sha256_json(unsigned)}


def _write_final_evidence(directory: Path, profile: dict, readiness: dict) -> tuple[Path, Path]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw()
    assertions = []
    for check_id, assertion, observed_values in FINAL_ACCEPTANCE_ASSERTIONS:
        item = {
            "check_id": check_id,
            "assertion": assertion,
            "result": "READY",
            "observed_values": observed_values,
            "evidence_refs": [f"controlled://final/{check_id}"],
            "observation": f"independently observed {check_id}",
        }
        item["observed_fingerprint"] = sha256_json({key: item[key] for key in ("check_id", "assertion", "result", "observed_values", "evidence_refs", "observation")})
        assertions.append(item)
    unsigned = {
        "artifact_kind": FINAL_EVIDENCE_KIND,
        "version": FINAL_EVIDENCE_VERSION,
        "status": "VERIFIED",
        "profile_id": profile["profile_id"],
        "profile_fingerprint": readiness["profile_fingerprint"],
        "authority_fingerprint": readiness["authority_fingerprint"],
        "readiness_report_fingerprint": readiness["report_fingerprint"],
        "assertions": assertions,
        "issuer": {"key_id": sha256_bytes(public_key), "principal_id": "deployment-authority", "role": "deployment_authority"},
        "independent_review": {"reviewer_id": "independent-reviewer", "review_result": "ACCEPTED", "evidence_ref": "controlled://review/final"},
    }
    unsigned["payload_sha256"] = sha256_json(unsigned)
    record = {**unsigned, "signature": base64.b64encode(private_key.sign(canonical_json(unsigned))).decode("ascii")}
    evidence_path = directory / "final-evidence.json"
    key_path = directory / "final-public-key.bin"
    evidence_path.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
    key_path.write_bytes(public_key)
    return evidence_path, key_path


class DeploymentClosureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.closure = _load_script()

    def test_closure_stays_blocked_without_final_evidence(self):
        profile = load_profile(PROFILE_PATH)
        readiness = _ready_readiness(profile)
        with patch.object(self.closure, "run_deployment_readiness", return_value=SimpleNamespace(structured=lambda: readiness)):
            result = self.closure.verify_deployment_closure(PROJECT_ROOT, PROFILE_PATH)
        self.assertEqual(result["status"], "DEPLOYMENT_CLOSURE_BLOCKED")
        self.assertEqual(result["readiness"]["result"], "DEPLOYMENT_READY")
        self.assertEqual(result["final_acceptance"]["reason"], "final_evidence_and_public_key_required")

    def test_closure_cli_preserves_external_blockers_and_nonzero_exit(self):
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--project-root",
                str(PROJECT_ROOT),
                "--profile",
                str(PROFILE_PATH),
            ],
            cwd=PROJECT_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 1, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["status"], "DEPLOYMENT_CLOSURE_BLOCKED")
        self.assertEqual(result["readiness"]["blocked_checks"], [f"EXT-0{index}" for index in range(1, 7)])
        self.assertEqual(result["final_acceptance"]["reason"], "readiness_not_ready")

    def test_closure_verifies_final_evidence_against_current_readiness(self):
        profile = load_profile(PROFILE_PATH)
        readiness = _ready_readiness(profile)
        with TemporaryDirectory() as temp:
            evidence_path, key_path = _write_final_evidence(Path(temp), profile, readiness)
            with patch.object(self.closure, "run_deployment_readiness", return_value=SimpleNamespace(structured=lambda: readiness)):
                result = self.closure.verify_deployment_closure(
                    PROJECT_ROOT,
                    PROFILE_PATH,
                    final_evidence_path=evidence_path,
                    final_public_key_path=key_path,
                )
        self.assertEqual(result["status"], "DEPLOYMENT_CLOSURE_READY")
        self.assertEqual(result["final_acceptance"]["result"], "FINAL_ACCEPTANCE_READY")
        self.assertEqual(result["final_acceptance"]["reviewer_id"], "independent-reviewer")


if __name__ == "__main__":
    unittest.main()
