from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pmiri.canonical import sha256_json
from pmiri.deployment_evidence import (
    EXTERNAL_REQUIREMENTS,
    FINAL_ACCEPTANCE_ASSERTIONS,
    verify_external_evidence,
    verify_final_acceptance_evidence,
)
from pmiri.integrity import authority_fingerprint


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BUILDER_PATH = PROJECT_ROOT / "scripts" / "build_signed_evidence.py"


def _load_builder():
    spec = importlib.util.spec_from_file_location("pmiri_signed_evidence_builder_test", BUILDER_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load evidence builder")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SignedEvidenceBuilderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder = _load_builder()

    def _inputs(self, root: Path):
        profile = json.loads((PROJECT_ROOT / "deployment-profile.example.json").read_text(encoding="utf-8"))
        profile_path = root / "profile.json"
        profile_path.write_text(json.dumps(profile), encoding="utf-8")
        private_key = Ed25519PrivateKey.generate()
        private_key_path = root / "authority.key"
        private_key_path.write_bytes(private_key.private_bytes_raw())
        observations = {
            "issuer_principal_id": "deployment-authority",
            "reviewer_id": "independent-reviewer",
            "review_evidence_ref": "controlled://review/accepted",
            "checks": {
                check_id: {
                    "evidence_refs": [f"controlled://evidence/{check_id}"],
                    "observation": f"independently observed {check_id}",
                }
                for check_id, _ in EXTERNAL_REQUIREMENTS
            },
        }
        observations_path = root / "observations.json"
        observations_path.write_text(json.dumps(observations), encoding="utf-8")
        return profile, profile_path, private_key, private_key_path, observations_path

    def test_external_builder_emits_verifiable_bundle(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            profile, profile_path, private_key, private_key_path, observations_path = self._inputs(root)
            output = root / "external-evidence.json"
            result = self.builder.build_external_evidence(
                PROJECT_ROOT,
                profile_path,
                observations_path,
                private_key_path,
                output,
            )
            public_key = private_key.public_key().public_bytes_raw()
            verified = verify_external_evidence(
                output,
                trusted_public_key=public_key,
                profile_id=profile["profile_id"],
                profile_fingerprint=sha256_json(profile),
                authority_fingerprint=authority_fingerprint(PROJECT_ROOT),
            )
            self.assertEqual(result["payload_sha256"], verified.evidence_fingerprint)
            self.assertEqual(verified.reviewer_id, "independent-reviewer")
            self.assertNotIn(private_key_path.read_bytes().hex(), output.read_text(encoding="utf-8"))

    def test_builder_rejects_missing_observation_and_output_overwrite(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            profile, profile_path, _, private_key_path, observations_path = self._inputs(root)
            observations = json.loads(observations_path.read_text(encoding="utf-8"))
            observations["checks"].pop("EXT-06")
            observations_path.write_text(json.dumps(observations), encoding="utf-8")
            with self.assertRaisesRegex(self.builder.EvidenceBuildError, "observation_set_invalid"):
                self.builder.build_external_evidence(PROJECT_ROOT, profile_path, observations_path, private_key_path, root / "evidence.json")

            _, _, _, _, observations_path = self._inputs(root)
            output = root / "evidence.json"
            output.write_text("existing", encoding="utf-8")
            with self.assertRaisesRegex(self.builder.EvidenceBuildError, "output_exists"):
                self.builder.build_external_evidence(PROJECT_ROOT, profile_path, observations_path, private_key_path, output)

    def test_final_builder_requires_ready_readiness_and_binds_report(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            profile, profile_path, private_key, private_key_path, _ = self._inputs(root)
            blocked_readiness = PROJECT_ROOT / "artifacts" / "deployment-readiness-report.json"
            with self.assertRaisesRegex(self.builder.EvidenceBuildError, "readiness_report_invalid"):
                self.builder.build_final_acceptance_evidence(
                    PROJECT_ROOT,
                    profile_path,
                    blocked_readiness,
                    root / "missing-observations.json",
                    private_key_path,
                    root / "final-evidence.json",
                )

            readiness = json.loads(blocked_readiness.read_text(encoding="utf-8"))
            readiness["profile_id"] = profile["profile_id"]
            readiness["profile_fingerprint"] = sha256_json(profile)
            readiness["overall_result"] = "DEPLOYMENT_READY"
            for check in readiness["checks"]:
                check["result"] = "READY"
                check["observed_fingerprint"] = sha256_json({key: check[key] for key in ("check_id", "category", "assertion", "result", "observation", "evidence_refs")})
            unsigned = {key: readiness[key] for key in readiness if key != "report_fingerprint"}
            readiness["report_fingerprint"] = sha256_json(unsigned)
            readiness_path = root / "ready-readiness.json"
            readiness_path.write_text(json.dumps(readiness), encoding="utf-8")
            observations = {
                "issuer_principal_id": "deployment-authority",
                "reviewer_id": "independent-final-reviewer",
                "review_evidence_ref": "controlled://review/final-accepted",
                "assertions": {
                    check_id: {
                        "evidence_refs": [f"controlled://evidence/{check_id}"],
                        "observation": f"independently observed {check_id}",
                    }
                    for check_id, _, _ in FINAL_ACCEPTANCE_ASSERTIONS
                },
            }
            observations_path = root / "final-observations.json"
            observations_path.write_text(json.dumps(observations), encoding="utf-8")
            output = root / "final-evidence.json"
            result = self.builder.build_final_acceptance_evidence(
                PROJECT_ROOT,
                profile_path,
                readiness_path,
                observations_path,
                private_key_path,
                output,
            )
            verified = verify_final_acceptance_evidence(
                output,
                trusted_public_key=private_key.public_key().public_bytes_raw(),
                profile_id=profile["profile_id"],
                profile_fingerprint=sha256_json(profile),
                authority_fingerprint=authority_fingerprint(PROJECT_ROOT),
                readiness_report_fingerprint=readiness["report_fingerprint"],
            )
            self.assertEqual(result["payload_sha256"], verified.evidence_fingerprint)
            self.assertEqual(verified.reviewer_id, "independent-final-reviewer")


if __name__ == "__main__":
    unittest.main()
