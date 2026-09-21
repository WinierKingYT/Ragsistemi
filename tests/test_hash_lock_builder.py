from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.verify_reproducibility import read_lock
from scripts.verify_supply_chain import read_hash_pinned_lock, verify_hash_pinned_lock, verify_mirror_artifacts


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "build_hash_pinned_lock.py"


def _load_builder():
    spec = importlib.util.spec_from_file_location("pmiri_hash_lock_builder_test", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load hash-lock builder")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HashLockBuilderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder = _load_builder()

    def test_builds_and_verifies_complete_offline_hash_lock(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            mirror = root / "mirror"
            mirror.mkdir()
            for name, version in read_lock().items():
                (mirror / f"{name}-{version}-py3-none-any.whl").write_bytes(f"{name}:{version}".encode())
            output = root / "requirements.hashes.lock"
            result = self.builder.build_hash_pinned_lock(mirror, output)
            entries = read_hash_pinned_lock(output)
            self.assertEqual(result["package_count"], len(read_lock()))
            self.assertEqual(verify_hash_pinned_lock(output), ())
            self.assertEqual(verify_mirror_artifacts(mirror, entries=entries), ())

    def test_builder_rejects_missing_artifact_overwrite_and_near_version(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            mirror = root / "mirror"
            mirror.mkdir()
            for name, version in read_lock().items():
                filename_version = "26.1.00" if name == "attrs" else version
                (mirror / f"{name}-{filename_version}-py3-none-any.whl").write_bytes(b"artifact")
            with self.assertRaisesRegex(self.builder.HashLockBuildError, "mirror_artifact_missing:attrs==26.1.0"):
                self.builder.build_hash_pinned_lock(mirror, root / "requirements.hashes.lock")

            (mirror / "attrs-26.1.0-py3-none-any.whl").write_bytes(b"correct")
            output = root / "requirements.hashes.lock"
            self.builder.build_hash_pinned_lock(mirror, output)
            with self.assertRaisesRegex(self.builder.HashLockBuildError, "output_exists"):
                self.builder.build_hash_pinned_lock(mirror, output)


if __name__ == "__main__":
    unittest.main()
