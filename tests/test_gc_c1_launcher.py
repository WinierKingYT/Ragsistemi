from __future__ import annotations

import sys
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from pmiri.attestation import create_attestation, write_attestation
from pmiri.canonical import sha256_bytes, sha256_json
from pmiri.clean_room import DOMAINS, IsolationObservation
from pmiri.gc_c1_launcher import ResourceProfile, launch_pinned_runner
from pmiri.replay import RUNNER_ID, RUNNER_VERSION


class GcC1LauncherTests(unittest.TestCase):
    def _identity(self):
        return {
            "runner_id": RUNNER_ID,
            "runner_version": RUNNER_VERSION,
            "latest_alias_allowed": False,
            "self_upgrade_allowed": False,
        }

    def _attestation(self, root: Path, case_id: str, profile: ResourceProfile):
        files = {}
        for name in (
            "runner_source",
            "runner_manifest",
            "authority_bundle",
            "evidence_schema",
            "fixture_catalog",
            "preflight_matrix",
        ):
            path = root / (name + ".bin")
            path.write_bytes(name.encode("ascii"))
            files[name] = path
        fingerprints = {name: sha256_bytes(path.read_bytes()) for name, path in files.items()}
        fingerprints["profile"] = sha256_json(profile.as_dict())
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
        record = create_attestation(
            authorization_id="auth-test",
            case_id=case_id,
            launcher={"launcher_id": "pmiri-gc-c1-clean-room-launcher", "launcher_version": "0.1.0"},
            fingerprints=fingerprints,
            observations=observations,
            case_root_policy="FRESH_CASE_ROOT",
        )
        attestation_path = root / "attestation.json"
        write_attestation(record, attestation_path)
        return attestation_path, fingerprints, files

    def test_attestation_is_required_before_command_start(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            result = launch_pinned_runner(
                case_id="R-FC-01",
                identity=self._identity(),
                attestation_path=root / "missing-attestation.json",
                fingerprints={"runner_source": "a" * 64},
                fingerprint_paths={},
                argv=[sys.executable, "-c", "raise SystemExit(99)"],
                inputs={"fixture.txt": b"fixture"},
            )
            self.assertEqual(result.status, "BLOCKED")
            self.assertFalse(result.started)

    def test_verified_attestation_runs_one_subprocess_with_limits_and_seal(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            profile = ResourceProfile(wall_time_seconds=10, cpu_time_seconds=5)
            attestation, fingerprints, files = self._attestation(root, "R-FC-01", profile)
            persist = root / "evidence"
            result = launch_pinned_runner(
                case_id="R-FC-01",
                identity=self._identity(),
                attestation_path=attestation,
                fingerprints=fingerprints,
                fingerprint_paths=files,
                argv=[sys.executable, "-c", "print('runner-ok')"],
                inputs={"fixture.txt": b"fixture"},
                profile=profile,
                persist_dir=persist,
                temp_parent=root,
            )
            self.assertEqual(result.status, "RECORDED", result.structured())
            self.assertTrue(result.started)
            self.assertEqual(result.returncode, 0)
            self.assertTrue(result.job_limits_enforced)
            self.assertTrue(result.teardown_verified)
            self.assertTrue(result.artifact_bundle_fingerprint)
            self.assertTrue((persist / "sealed" / "artifact-manifest.json").is_file())
            self.assertIn(b"runner-ok", (persist / "stdout.bin").read_bytes())
            launch_record = json.loads((persist / "launch-record.json").read_text(encoding="utf-8"))
            if Path(sys.executable).parent.name.casefold() == "scripts":
                self.assertEqual(launch_record["interpreter_resolution"], "WINDOWS_VENV_BASE_INTERPRETER")
                self.assertNotEqual(
                    Path(launch_record["effective_argv"][0]).resolve(),
                    Path(sys.executable).resolve(),
                )
            else:
                self.assertEqual(launch_record["interpreter_resolution"], "NONE")


if __name__ == "__main__":
    unittest.main()
