from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.generate_sbom import REPRODUCIBLE_SOURCE_DATE_EPOCH, build_sbom, read_lock, verify_sbom
from scripts.verify_supply_chain import read_hash_pinned_lock, verify_hash_pinned_lock, verify_mirror_artifacts


class SupplyChainTests(unittest.TestCase):
    def test_sbom_is_deterministic_and_matches_lock(self):
        locked = read_lock()
        first = build_sbom(locked=locked)
        second = build_sbom(locked=locked)
        self.assertEqual(first, second)
        self.assertEqual(verify_sbom(first, locked=locked, announce=False), ())
        self.assertEqual(len(first["packages"]), len(locked) + 1)

    def test_sbom_uses_the_canonical_release_epoch(self):
        with patch.dict(os.environ, {}, clear=True):
            document = build_sbom()
        self.assertEqual(
            document["creationInfo"]["created"],
            "2000-01-01T00:00:00Z",
        )
        with patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "0"}, clear=True):
            with self.assertRaisesRegex(ValueError, f"source_date_epoch_must_equal:{REPRODUCIBLE_SOURCE_DATE_EPOCH}"):
                build_sbom()

    def test_sbom_rejects_version_drift(self):
        document = build_sbom()
        packages = [item for item in document["packages"] if item["name"] == "idna"]
        packages[0]["versionInfo"] = "0.0.0"
        errors = verify_sbom(document, announce=False)
        self.assertIn("package_version_mismatch:idna", errors)

        document = build_sbom()
        document["documentNamespace"] = "urn:pmiri:sbom:tampered"
        self.assertIn("document_namespace_invalid", verify_sbom(document, announce=False))

    def test_sbom_is_json_serializable(self):
        self.assertIsInstance(json.loads(json.dumps(build_sbom())), dict)

    def test_hash_pinned_lock_must_match_exact_repository_inventory(self):
        locked = read_lock()
        with tempfile.TemporaryDirectory() as directory:
            lock_path = Path(directory) / "requirements.hashes.lock"
            lock_path.write_text(
                "\n".join(
                    f"{name}=={version} --hash=sha256:{'a' * 64}"
                    for name, version in sorted(locked.items())
                )
                + "\n",
                encoding="utf-8",
            )
            self.assertEqual(verify_hash_pinned_lock(lock_path, base_lock=locked), ())
            parsed = read_hash_pinned_lock(lock_path)
            self.assertEqual(parsed["cryptography"][0], "50.0.1")
            self.assertEqual(parsed["cryptography"][1], ("a" * 64,))

            lock_path.write_text(
                lock_path.read_text(encoding="utf-8").replace(
                    "idna==3.10", "idna==3.9"
                ),
                encoding="utf-8",
            )
            self.assertIn("hash_lock_version_mismatch:idna==3.9;expected==3.10", verify_hash_pinned_lock(lock_path, base_lock=locked))

    def test_local_mirror_requires_matching_hash_for_every_locked_package(self):
        payload = b"verified artifact bytes"
        digest = __import__("hashlib").sha256(payload).hexdigest()
        entries = {"attrs": ("26.1.0", (digest,))}
        with tempfile.TemporaryDirectory() as directory:
            mirror = Path(directory)
            artifact = mirror / "attrs-26.1.0-py3-none-any.whl"
            artifact.write_bytes(payload)
            self.assertEqual(verify_mirror_artifacts(mirror, entries=entries), ())
            artifact.write_bytes(b"tampered artifact bytes")
            self.assertEqual(
                verify_mirror_artifacts(mirror, entries=entries),
                ("mirror_artifact_hash_mismatch:attrs==26.1.0",),
            )


if __name__ == "__main__":
    unittest.main()
