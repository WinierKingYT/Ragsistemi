from __future__ import annotations

import concurrent.futures
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from pmiri.models import QueryRequest
from pmiri.runtime import LocalEvidenceRuntime
from pmiri.store import LocalStore, SQLiteStore


class SQLiteStoreTests(unittest.TestCase):
    def test_read_before_initialize_does_not_create_database(self):
        with TemporaryDirectory() as temp:
            store = SQLiteStore(Path(temp) / "sqlite")
            self.assertEqual(store.list_sources(), ())
            self.assertFalse(store.db_path.exists())

    def test_migration_preserves_history_fingerprint_and_query_surface(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            json_store = LocalStore(root / "json")
            json_store.initialize()
            json_store.register_bytes("project", "guide.md", b"release old\n", capture_time="2026-01-01T00:00:00Z", metadata={"kind": "guide"})
            json_store.register_bytes("project", "guide.md", b"release new\n", capture_time="2026-01-02T00:00:00Z", metadata={"kind": "guide"})
            json_store.register_bytes("other", "note.txt", b"separate project\n", capture_time="2026-01-01T00:00:00Z")
            sqlite_store = SQLiteStore(root / "sqlite")
            report = sqlite_store.migrate_from_local_store(root / "json")
            self.assertEqual(report["status"], "MIGRATED")
            self.assertEqual(report["source_count"], 3)
            self.assertEqual(report["source_fingerprint"], json_store.canonical_fingerprint())
            self.assertEqual(report["target_fingerprint"], sqlite_store.canonical_fingerprint())
            self.assertEqual(
                [record.public_dict() for record in json_store.list_sources(include_history=True)],
                [record.public_dict() for record in sqlite_store.list_sources(include_history=True)],
            )
            result = LocalEvidenceRuntime(sqlite_store).query(QueryRequest("q1", "project", "release"))
            self.assertEqual(result.evidence[0].project_id, "project")
            self.assertIn("release new", result.context.text)

    def test_migration_dry_run_is_read_only_and_detects_target_conflict(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            json_store = LocalStore(root / "json")
            json_store.initialize()
            json_store.register_bytes("project", "guide.md", b"release\n")
            sqlite_store = SQLiteStore(root / "sqlite")

            plan = sqlite_store.migration_plan(root / "json")
            self.assertEqual(plan["status"], "MIGRATION_DRY_RUN")
            self.assertEqual(plan["source_count"], 1)
            self.assertEqual(plan["project_count"], 1)
            self.assertEqual(plan["source_fingerprint"], json_store.canonical_fingerprint())
            self.assertFalse(plan["write_performed"])
            self.assertTrue(plan["ready_for_migration"])
            self.assertFalse(sqlite_store.db_path.exists())

            sqlite_store.initialize()
            conflict = sqlite_store.migration_plan(root / "json")
            self.assertFalse(conflict["ready_for_migration"])
            with self.assertRaisesRegex(ValueError, "migration_target_exists"):
                sqlite_store.migrate_from_local_store(root / "json")

    def test_concurrent_writers_are_transactionally_idempotent(self):
        with TemporaryDirectory() as temp:
            store = SQLiteStore(Path(temp) / "sqlite")
            store.initialize()

            def write(index: int):
                return store.register_bytes("project", f"source-{index}.md", f"content {index}\n".encode("utf-8"))

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                records = list(executor.map(write, range(24)))
            self.assertEqual(len(records), 24)
            self.assertEqual(len(store.list_sources("project")), 24)
            self.assertEqual(len(store.list_sources("project", include_history=True)), 24)

    def test_blob_corruption_is_detected_before_content_is_served(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / "sqlite"
            store = SQLiteStore(root)
            store.initialize()
            record = store.register_bytes("project", "source.md", b"trusted content\n")
            import sqlite3

            connection = sqlite3.connect(store.db_path)
            try:
                connection.execute("UPDATE blobs SET content = ? WHERE fingerprint = ?", (b"tampered\n", record.content_fingerprint))
                connection.commit()
            finally:
                connection.close()
            with self.assertRaisesRegex(ValueError, "source_blob_fingerprint_mismatch"):
                store.list_sources("project")

    def test_backup_uses_consistent_snapshot_and_preserves_fingerprint(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            source = SQLiteStore(root / "source")
            source.initialize()
            source.register_bytes("project", "source.md", b"backup me\n", capture_time="2026-01-01T00:00:00Z")
            report = source.backup_to(root / "backup")
            self.assertEqual(report["status"], "BACKUP_VERIFIED")
            self.assertEqual(report["source_fingerprint"], report["backup_fingerprint"])
            self.assertEqual(
                [item.public_dict() for item in source.list_sources(include_history=True)],
                [item.public_dict() for item in SQLiteStore(root / "backup").list_sources(include_history=True)],
            )

    def test_restore_is_verified_and_never_overwrites_existing_destination(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            source = SQLiteStore(root / "source")
            source.initialize()
            source.register_bytes("project", "source.md", b"restore me\n", capture_time="2026-01-01T00:00:00Z")
            backup = source.backup_to(root / "backup")
            restored = SQLiteStore(root / "backup").restore_from_backup(root / "restored")
            self.assertEqual(restored["status"], "RESTORE_VERIFIED")
            self.assertEqual(restored["source_fingerprint"], backup["backup_fingerprint"])
            self.assertEqual(restored["source_fingerprint"], restored["restored_fingerprint"])
            with self.assertRaisesRegex(ValueError, "restore_destination_exists"):
                SQLiteStore(root / "backup").restore_from_backup(root / "restored")


if __name__ == "__main__":
    unittest.main()
