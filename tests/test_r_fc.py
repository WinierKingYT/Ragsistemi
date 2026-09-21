from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from pmiri.attestation import create_attestation, write_attestation
from pmiri.canonical import sha256_bytes, sha256_json
from pmiri.clean_room import IsolationObservation
from pmiri.preflight import run_preflight, write_preflight
from pmiri.r_fc import create_handler_manifest, load_handler_manifest, run_r_fc_candidate, write_handler_manifest
from pmiri.replay import RUNNER_ID, RUNNER_VERSION
from pmiri.sealing import verify_seal


class RfcCandidateTests(unittest.TestCase):
    def _identity(self):
        return {
            "runner_id": RUNNER_ID,
            "runner_version": RUNNER_VERSION,
            "latest_alias_allowed": False,
            "self_upgrade_allowed": False,
        }

    def _fingerprints(self):
        docs = Path("PMIRI_ALL_DOCUMENTATION_CHECKPOINT_17")
        files = {
            "runner_source": docs / "GC-C1" / "PMIRI_GC-C1_REPLAY_RUNNER_0.1.0" / "pmiri_gc_c1_replay_runner.py",
            "runner_manifest": docs / "GC-C1" / "PMIRI_GC-C1-03_REPLAY_RUNNER_MANIFEST.json",
            "authority_bundle": docs / "GATE-D-R2" / "PMIRI_GD-R2_AUTHORITY_BUNDLE_MANIFEST_v0.1.json",
            "evidence_schema": docs / "GC-C1" / "PMIRI_GC-C1-02_EVIDENCE_RECORD.schema.json",
            "fixture_catalog": docs / "GC-C1" / "PMIRI_GC-C1-02_REPLAY_FIXTURE_CATALOG.json",
            "preflight_matrix": docs / "GC-C1" / "PMIRI_GC-C1-05_CONTROLLED_PREFLIGHT_SCENARIO_MATRIX.json",
            "preflight_record_schema": docs / "GC-C1" / "PMIRI_GC-C1-06_PREFLIGHT_RECORD.schema.json",
        }
        return {
            name: sha256_bytes(path.read_bytes()) for name, path in files.items()
        }

    def _attestation(self, path: Path, case_id: str):
        fingerprints = self._fingerprints()
        attestation_fingerprints = {name: fingerprints[name] for name in fingerprints if name != "preflight_record_schema"}
        attestation_fingerprints["profile"] = "b" * 64
        expected = {
            "network": "DENIED",
            "credentials": "DENIED",
            "filesystem": "ALLOWLIST_VERIFIED",
            "connectors": "DENIED",
            "determinism": "VERIFIED",
            "resource_limits": "VERIFIED",
            "teardown": "AVAILABLE",
            "privacy": "VERIFIED",
        }
        observations = {
            domain: IsolationObservation(domain, result, "external://" + domain, "controlled environment observation")
            for domain, result in expected.items()
        }
        write_attestation(
            create_attestation(
                authorization_id="auth-test",
                case_id=case_id,
                launcher={"launcher_id": "pmiri-gc-c1-clean-room-launcher", "launcher_version": "0.1.0"},
                fingerprints=attestation_fingerprints,
                observations=observations,
                case_root_policy="FRESH_CASE_ROOT",
            ),
            path,
        )
        return fingerprints, observations

    def test_candidate_fails_closed_without_attestation_and_does_not_call_handler(self):
        called: list[str] = []
        case_id = "GC-C1-FC01-P"
        report = run_r_fc_candidate(
            Path("."),
            identity=self._identity(),
            fingerprints=self._fingerprints(),
            attestation_paths=None,
            preflight_paths=None,
            case_handlers={case_id: lambda *_: called.append(case_id) or {"disposition": "ALLOWED_WITHIN_ENVELOPE"}},
            handler_manifest=None,
            operator_ref="reviewer://operator",
            independent_reviewer_ref="reviewer://independent",
            case_ids=[case_id],
        )
        self.assertEqual(report["status"], "R_FC_REPLAY_BLOCKED")
        self.assertEqual(report["executed_case_count"], 0)
        self.assertEqual(called, [])
        self.assertEqual(report["cases"][0]["block_reason"], "preflight_record_absent")

    def test_attested_case_is_executed_sealed_and_not_promoted_to_pass(self):
        case_id = "GC-C1-FC01-P"
        with TemporaryDirectory() as temp:
            root = Path(temp)
            attestation_path = root / "attestation.json"
            fingerprints, observations = self._attestation(attestation_path, case_id)
            preflight_path = root / "preflight.json"
            write_preflight(
                run_preflight(
                    Path("."),
                    identity=self._identity(),
                    isolation=observations,
                    operator="reviewer://operator",
                    independent_reviewer="reviewer://independent",
                    selected_fixture_id="GC-C1-FC01",
                    selected_case_id=case_id,
                ),
                preflight_path,
            )
            persist = root / "persisted"

            def handler(case_root, fixture, declared_case):
                self.assertTrue((case_root / "inputs" / "fixture.json").is_file())
                expected = declared_case["oracle"]["expected_dispositions"][0]
                return {
                    "disposition": expected,
                    "lineage": {
                        "authorization_lineage_ref": "lineage://r-fc/test",
                        "evidence_refs": ["evidence://r-fc/test"],
                        "citation_refs": [],
                    },
                    "notes": "controlled candidate handler",
                }

            handler_manifest = create_handler_manifest(
                Path("."),
                case_handlers={case_id: handler},
                case_ids=[case_id],
            )
            handler_manifest_path = root / "handler-manifest.json"
            write_handler_manifest(handler_manifest, handler_manifest_path)
            self.assertEqual(load_handler_manifest(handler_manifest_path), handler_manifest)

            report = run_r_fc_candidate(
                Path("."),
                identity=self._identity(),
                fingerprints=fingerprints,
                attestation_paths={case_id: attestation_path},
                preflight_paths={case_id: preflight_path},
                case_handlers={case_id: handler},
                handler_manifest=handler_manifest,
                operator_ref="reviewer://operator",
                independent_reviewer_ref="reviewer://independent",
                case_ids=[case_id],
                persist_dir=persist,
            )
            result = report["cases"][0]
            self.assertEqual(report["status"], "R_FC_REPLAY_RECORDED")
            self.assertEqual(report["executed_case_count"], 1)
            self.assertEqual(report["oracle_match_count"], 1)
            self.assertEqual(report["r_fc_pass"], "NONE")
            self.assertEqual(result["evidence"]["status"], "UNVERIFIED")
            self.assertTrue(report["schema_valid"])
            manifest = persist / case_id / "sealed" / "artifact-manifest.json"
            self.assertTrue(manifest.is_file())
            self.assertEqual(verify_seal(manifest, root=persist / case_id), (True, "SEALED"))

    def test_candidate_requires_handler_manifest_after_replay_prerequisites(self):
        case_id = "GC-C1-FC01-P"
        with TemporaryDirectory() as temp:
            root = Path(temp)
            attestation_path = root / "attestation.json"
            fingerprints, observations = self._attestation(attestation_path, case_id)
            preflight_path = root / "preflight.json"
            write_preflight(
                run_preflight(
                    Path("."),
                    identity=self._identity(),
                    isolation=observations,
                    operator="reviewer://operator",
                    independent_reviewer="reviewer://independent",
                    selected_fixture_id="GC-C1-FC01",
                    selected_case_id=case_id,
                ),
                preflight_path,
            )
            called: list[str] = []
            report = run_r_fc_candidate(
                Path("."),
                identity=self._identity(),
                fingerprints=fingerprints,
                attestation_paths={case_id: attestation_path},
                preflight_paths={case_id: preflight_path},
                case_handlers={case_id: lambda *_: called.append(case_id) or {"disposition": "DENIED"}},
                handler_manifest=None,
                operator_ref="reviewer://operator",
                independent_reviewer_ref="reviewer://independent",
                case_ids=[case_id],
            )
            self.assertEqual(report["cases"][0]["block_reason"], "handler_manifest_absent")
            self.assertEqual(called, [])

    def test_candidate_blocks_when_handler_source_fingerprint_is_tampered(self):
        case_id = "GC-C1-FC01-P"
        with TemporaryDirectory() as temp:
            root = Path(temp)
            attestation_path = root / "attestation.json"
            fingerprints, observations = self._attestation(attestation_path, case_id)
            preflight_path = root / "preflight.json"
            write_preflight(
                run_preflight(
                    Path("."),
                    identity=self._identity(),
                    isolation=observations,
                    operator="reviewer://operator",
                    independent_reviewer="reviewer://independent",
                    selected_fixture_id="GC-C1-FC01",
                    selected_case_id=case_id,
                ),
                preflight_path,
            )

            def handler(case_root, fixture, declared_case):
                return {"disposition": declared_case["oracle"]["expected_dispositions"][0]}

            handler_manifest = create_handler_manifest(Path("."), case_handlers={case_id: handler}, case_ids=[case_id])
            handler_manifest["module"]["source_fingerprint"] = "c" * 64
            handler_manifest["handler_manifest_sha256"] = sha256_json({key: value for key, value in handler_manifest.items() if key != "handler_manifest_sha256"})
            report = run_r_fc_candidate(
                Path("."),
                identity=self._identity(),
                fingerprints=fingerprints,
                attestation_paths={case_id: attestation_path},
                preflight_paths={case_id: preflight_path},
                case_handlers={case_id: handler},
                handler_manifest=handler_manifest,
                operator_ref="reviewer://operator",
                independent_reviewer_ref="reviewer://independent",
                case_ids=[case_id],
            )
            self.assertEqual(report["cases"][0]["block_reason"], "handler_source_fingerprint_mismatch")


if __name__ == "__main__":
    unittest.main()
