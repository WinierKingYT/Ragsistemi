from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import pmiri


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class CliMigrationWorkflowTests(unittest.TestCase):
    def _run(self, *arguments: str) -> dict:
        environment = os.environ.copy()
        package_root = Path(pmiri.__file__).resolve().parent.parent
        environment["PYTHONPATH"] = str(package_root) + os.pathsep + environment.get("PYTHONPATH", "")
        result = subprocess.run(
            [sys.executable, "-m", "pmiri.cli", *arguments],
            cwd=Path(tempfile.gettempdir()),
            env=environment,
            capture_output=True,
            text=True,
            timeout=20,
        )
        if result.returncode != 0:
            self.fail(f"CLI failed ({result.returncode}): {result.stdout}\n{result.stderr}")
        return json.loads(result.stdout)

    def test_dry_run_canary_backup_restore_and_rollback_guard(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            source_store = root / "source-json"
            canary_store = root / "canary-sqlite"
            backup_store = root / "backup-sqlite"
            restored_store = root / "restored-sqlite"
            source_files = root / "source-files"
            source_files.mkdir()
            (source_files / "guide.md").write_text("release status is verified\n", encoding="utf-8")
            (source_files / "history.md").write_text("release status was previously blocked\n", encoding="utf-8")

            self._run("init", str(source_store), "--backend", "json")
            self._run("add-dir", str(source_store), "project-alpha", str(source_files), "--backend", "json")

            dry_run = self._run("migrate-json-to-sqlite", str(source_store), str(canary_store), "--dry-run")
            self.assertEqual(dry_run["status"], "MIGRATION_DRY_RUN")
            self.assertFalse(dry_run["write_performed"])
            self.assertTrue(dry_run["ready_for_migration"])
            self.assertFalse((canary_store / "store.db").exists())

            migration = self._run("migrate-json-to-sqlite", str(source_store), str(canary_store))
            self.assertEqual(migration["status"], "MIGRATED")
            self.assertEqual(migration["source_fingerprint"], migration["target_fingerprint"])

            canary_query = self._run("query", str(canary_store), "project-alpha", "release status", "--backend", "sqlite", "--json")
            self.assertEqual(canary_query["request"]["project_constraint"], "project-alpha")
            self.assertGreaterEqual(len(canary_query["evidence"]), 1)

            backup = self._run("backup-sqlite", str(canary_store), str(backup_store))
            self.assertEqual(backup["status"], "BACKUP_VERIFIED")
            self.assertEqual(backup["source_fingerprint"], backup["backup_fingerprint"])

            restore = self._run("restore-sqlite", str(backup_store), str(restored_store))
            self.assertEqual(restore["status"], "RESTORE_VERIFIED")
            self.assertEqual(restore["source_fingerprint"], restore["restored_fingerprint"])
            restored_query = self._run("query", str(restored_store), "project-alpha", "release status", "--backend", "sqlite", "--json")
            self.assertEqual(restored_query["evidence"], canary_query["evidence"])

            environment = os.environ.copy()
            package_root = Path(pmiri.__file__).resolve().parent.parent
            environment["PYTHONPATH"] = str(package_root) + os.pathsep + environment.get("PYTHONPATH", "")
            rollback_attempt = subprocess.run(
                [sys.executable, "-m", "pmiri.cli", "restore-sqlite", str(backup_store), str(restored_store)],
                cwd=Path(tempfile.gettempdir()),
                env=environment,
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertNotEqual(rollback_attempt.returncode, 0)
            self.assertIn("restore_destination_exists", rollback_attempt.stdout + rollback_attempt.stderr)


if __name__ == "__main__":
    unittest.main()
