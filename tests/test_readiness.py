from __future__ import annotations

import json
import base64
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pmiri.canonical import canonical_json, sha256_bytes, sha256_json
from pmiri.control_plane import SQLiteAuthenticationRegistry, SQLitePolicyEpoch, SQLiteRateLimiter, SQLiteReplayGuard
from pmiri.deployment_evidence import DeploymentEvidenceError, verify_external_evidence
from pmiri.integrity import authority_fingerprint
from pmiri.readiness import (
    ReadinessContractError,
    default_profile,
    run_deployment_readiness,
    validate_readiness_report,
)
from pmiri.store import SQLiteStore


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class ReadinessTests(unittest.TestCase):
    def _signed_external_evidence(self, directory: Path, profile: dict):
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        checks = []
        assertions = (
            ("EXT-01", "INDEPENDENT_CLEAN_ROOM"),
            ("EXT-02", "DEPLOYED_IDENTITY_PROVIDER"),
            ("EXT-03", "DISTRIBUTED_CONTROL_PLANE"),
            ("EXT-04", "METADATA_ENCRYPTION_AND_KEY_ESCROW"),
            ("EXT-05", "REAL_PROVIDER_CONNECTOR_AUTHORIZATION"),
            ("EXT-06", "INDEPENDENT_GATE_D_RECHECK"),
        )
        for check_id, assertion in assertions:
            item = {
                "check_id": check_id,
                "assertion": assertion,
                "result": "READY",
                "evidence_refs": ["external://signed/" + check_id.lower()],
                "observation": "externally observed deployment evidence",
            }
            item["observed_fingerprint"] = sha256_json({key: item[key] for key in ("check_id", "assertion", "result", "observation", "evidence_refs")})
            checks.append(item)
        unsigned = {
            "artifact_kind": "PMIRI-DEPLOYMENT-EXTERNAL-EVIDENCE",
            "version": "0.1",
            "status": "VERIFIED",
            "profile_id": profile["profile_id"],
            "profile_fingerprint": sha256_json(profile),
            "authority_fingerprint": authority_fingerprint(PROJECT_ROOT),
            "checks": checks,
            "issuer": {"key_id": sha256_bytes(public_key), "principal_id": "deployment-authority", "role": "deployment_authority"},
            "independent_review": {"reviewer_id": "independent-reviewer", "review_result": "ACCEPTED", "evidence_ref": "external://review/accepted"},
        }
        unsigned["payload_sha256"] = sha256_json(unsigned)
        record = {**unsigned, "signature": base64.b64encode(private_key.sign(canonical_json(unsigned))).decode("ascii")}
        evidence_path = directory / "external-evidence.json"
        key_path = directory / "external-public-key.bin"
        evidence_path.write_text(json.dumps(record, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        key_path.write_bytes(public_key)
        return evidence_path, key_path

    def test_workspace_report_is_fail_closed_and_self_validating(self):
        report = run_deployment_readiness(PROJECT_ROOT, captured_at="2026-01-01T00:00:00Z")
        structured = report.structured()
        self.assertEqual(structured["overall_result"], "DEPLOYMENT_READINESS_BLOCKED")
        self.assertEqual(validate_readiness_report(structured), ())
        checks = {item["assertion"]: item for item in structured["checks"]}
        self.assertEqual(checks["STANDARDS_SCHEMA_VALIDATOR"]["result"], "READY")
        self.assertEqual(checks["NETWORK_DEFAULT_DENY"]["result"], "READY")
        self.assertEqual(checks["PMIRI-GC-C1-R-FC-LOCAL-HANDLER-CANDIDATE-REPORT"]["result"], "READY")
        self.assertEqual(checks["INDEPENDENT_CLEAN_ROOM"]["result"], "BLOCKED")
        self.assertEqual(checks["DEPLOYED_IDENTITY_PROVIDER"]["result"], "BLOCKED")

    def test_profile_cannot_enable_external_execution(self):
        profile = default_profile()
        profile["network"]["external_execution"] = "ENABLED"
        with self.assertRaisesRegex(ReadinessContractError, "deny_by_default"):
            run_deployment_readiness(PROJECT_ROOT, profile=profile)

    def test_profile_cannot_move_read_server_off_loopback(self):
        profile = default_profile()
        profile["api"]["bind_host"] = "0.0.0.0"
        with self.assertRaisesRegex(ReadinessContractError, "readiness_api_must_remain_loopback"):
            run_deployment_readiness(PROJECT_ROOT, profile=profile)

    def test_sqlite_and_control_plane_health_are_checked_read_only(self):
        with TemporaryDirectory(dir=PROJECT_ROOT) as temporary:
            root = Path(temporary)
            store = SQLiteStore(root / "store")
            store.initialize()
            control_path = root / "control.db"
            SQLiteAuthenticationRegistry(control_path).initialize()
            SQLiteReplayGuard(control_path).initialize()
            SQLiteRateLimiter(control_path).initialize()
            SQLitePolicyEpoch(control_path).initialize()

            profile = default_profile()
            profile["storage"]["root"] = root.relative_to(PROJECT_ROOT).joinpath("store").as_posix()
            profile["control_plane"]["path"] = root.relative_to(PROJECT_ROOT).joinpath("control.db").as_posix()
            report = run_deployment_readiness(PROJECT_ROOT, profile=profile, captured_at="2026-01-01T00:00:00Z")
            checks = {item.assertion: item for item in report.checks}
            self.assertEqual(checks["TRANSACTIONAL_SQLITE_STORAGE"].result, "READY")
            self.assertEqual(checks["LOCAL_CONTROL_PLANE"].result, "READY")

    def test_report_fingerprint_rejects_tampering(self):
        data = run_deployment_readiness(PROJECT_ROOT, captured_at="2026-01-01T00:00:00Z").structured()
        data["overall_result"] = "DEPLOYMENT_READY"
        errors = validate_readiness_report(data)
        self.assertIn("report_fingerprint_mismatch", errors)

    def test_profile_json_can_be_round_tripped_without_authority(self):
        profile = default_profile()
        encoded = json.dumps(profile, ensure_ascii=False, sort_keys=True)
        self.assertEqual(json.loads(encoded), profile)

    def test_signed_external_evidence_can_release_only_the_external_checks(self):
        profile = default_profile()
        with TemporaryDirectory() as temp:
            evidence_path, key_path = self._signed_external_evidence(Path(temp), profile)
            report = run_deployment_readiness(
                PROJECT_ROOT,
                profile=profile,
                external_evidence_path=evidence_path,
                external_public_key_path=key_path,
                captured_at="2026-01-01T00:00:00Z",
            )
            checks = {item["assertion"]: item for item in report.structured()["checks"]}
            self.assertTrue(all(check["result"] == "READY" for check in checks.values() if check["check_id"].startswith("EXT-")))
            self.assertEqual(validate_readiness_report(report.structured()), ())

    def test_signed_external_evidence_tamper_remains_blocked(self):
        profile = default_profile()
        with TemporaryDirectory() as temp:
            evidence_path, key_path = self._signed_external_evidence(Path(temp), profile)
            record = json.loads(evidence_path.read_text(encoding="utf-8"))
            record["checks"][0]["observation"] = "tampered"
            evidence_path.write_text(json.dumps(record), encoding="utf-8")
            report = run_deployment_readiness(
                PROJECT_ROOT,
                profile=profile,
                external_evidence_path=evidence_path,
                external_public_key_path=key_path,
                captured_at="2026-01-01T00:00:00Z",
            )
            checks = {item["assertion"]: item for item in report.structured()["checks"]}
            self.assertTrue(all(checks[name]["result"] == "BLOCKED" for _, name in (("EXT-01", "INDEPENDENT_CLEAN_ROOM"), ("EXT-02", "DEPLOYED_IDENTITY_PROVIDER"))))

    def test_external_evidence_contract_rejects_incomplete_bundle_and_non_independent_reviewer(self):
        profile = default_profile()
        with TemporaryDirectory() as temp:
            evidence_path, key_path = self._signed_external_evidence(Path(temp), profile)
            record = json.loads(evidence_path.read_text(encoding="utf-8"))
            record["checks"] = record["checks"][:-1]
            evidence_path.write_text(json.dumps(record), encoding="utf-8")
            with self.assertRaisesRegex(DeploymentEvidenceError, "deployment_evidence_checks_invalid"):
                verify_external_evidence(
                    evidence_path,
                    trusted_public_key=key_path.read_bytes(),
                    profile_id=profile["profile_id"],
                    profile_fingerprint=sha256_json(profile),
                    authority_fingerprint=authority_fingerprint(PROJECT_ROOT),
                )

            evidence_path, key_path = self._signed_external_evidence(Path(temp), profile)
            record = json.loads(evidence_path.read_text(encoding="utf-8"))
            record["independent_review"]["reviewer_id"] = record["issuer"]["principal_id"]
            evidence_path.write_text(json.dumps(record), encoding="utf-8")
            with self.assertRaisesRegex(DeploymentEvidenceError, "deployment_evidence_reviewer_not_independent"):
                verify_external_evidence(
                    evidence_path,
                    trusted_public_key=key_path.read_bytes(),
                    profile_id=profile["profile_id"],
                    profile_fingerprint=sha256_json(profile),
                    authority_fingerprint=authority_fingerprint(PROJECT_ROOT),
                )

    def test_external_evidence_profile_and_authority_bindings_are_fail_closed(self):
        profile = default_profile()
        with TemporaryDirectory() as temp:
            evidence_path, key_path = self._signed_external_evidence(Path(temp), profile)
            with self.assertRaisesRegex(DeploymentEvidenceError, "deployment_evidence_profile_binding_mismatch"):
                verify_external_evidence(
                    evidence_path,
                    trusted_public_key=key_path.read_bytes(),
                    profile_id="wrong-profile",
                    profile_fingerprint=sha256_json(profile),
                    authority_fingerprint=authority_fingerprint(PROJECT_ROOT),
                )

            with self.assertRaisesRegex(DeploymentEvidenceError, "deployment_evidence_authority_binding_mismatch"):
                verify_external_evidence(
                    evidence_path,
                    trusted_public_key=key_path.read_bytes(),
                    profile_id=profile["profile_id"],
                    profile_fingerprint=sha256_json(profile),
                    authority_fingerprint="0" * 64,
                )

    def test_external_evidence_rejects_security_sensitive_mutations(self):
        profile = default_profile()
        expected_args = {
            "profile_id": profile["profile_id"],
            "profile_fingerprint": sha256_json(profile),
            "authority_fingerprint": authority_fingerprint(PROJECT_ROOT),
        }
        mutations = (
            ("fields", lambda record: record.update({"extra": True}), "deployment_evidence_fields_invalid"),
            ("issuer", lambda record: record["issuer"].update({"role": "reviewer"}), "deployment_evidence_issuer_invalid"),
            ("review", lambda record: record["independent_review"].update({"review_result": "PENDING"}), "deployment_evidence_review_invalid"),
            ("identity", lambda record: record["checks"][0].update({"assertion": "WRONG"}), "deployment_evidence_check_identity_invalid"),
            ("refs", lambda record: record["checks"][0].update({"evidence_refs": []}), "deployment_evidence_check_refs_invalid"),
            ("observation", lambda record: record["checks"][0].update({"observation": ""}), "deployment_evidence_check_observation_invalid"),
            ("check_fingerprint", lambda record: record["checks"][0].update({"observation": "tampered"}), "deployment_evidence_check_fingerprint_mismatch"),
            ("payload", lambda record: record.update({"payload_sha256": "0" * 64}), "deployment_evidence_payload_fingerprint_mismatch"),
            ("signature_encoding", lambda record: record.update({"signature": "not-base64"}), "deployment_evidence_signature_invalid"),
            ("signature", lambda record: record.update({"signature": "AA=="}), "deployment_evidence_signature_mismatch"),
        )
        with TemporaryDirectory() as temp:
            directory = Path(temp)
            for name, mutate, expected_error in mutations:
                with self.subTest(name=name):
                    evidence_path, key_path = self._signed_external_evidence(directory, profile)
                    record = json.loads(evidence_path.read_text(encoding="utf-8"))
                    mutate(record)
                    evidence_path.write_text(json.dumps(record), encoding="utf-8")
                    with self.assertRaisesRegex(DeploymentEvidenceError, expected_error):
                        verify_external_evidence(evidence_path, trusted_public_key=key_path.read_bytes(), **expected_args)

            evidence_path, key_path = self._signed_external_evidence(directory, profile)
            with self.assertRaisesRegex(DeploymentEvidenceError, "deployment_evidence_key_id_mismatch"):
                verify_external_evidence(evidence_path, trusted_public_key=b"0" * 32, **expected_args)
            with self.assertRaisesRegex(DeploymentEvidenceError, "deployment_public_key_encoding_invalid"):
                verify_external_evidence(evidence_path, trusted_public_key=b"not-a-key", **expected_args)


if __name__ == "__main__":
    unittest.main()
