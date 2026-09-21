"""Small replaceable content-addressed local store for PMIRI-V1-S0."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Iterable, Iterator

from .canonical import normalize_text, sha256_bytes, sha256_json, utc_now
from .models import SourceRecord
from .storage_crypto import BlobCipher, StorageEncryptionError


class LocalStore:
    """JSON-backed store with no hidden global state.

    Registration is the only mutating operation. Query and inspection methods
    never update indexes, caches or timestamps.
    """

    INDEX_NAME = "index.json"

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.blob_root = self.root / "blobs"
        self.index_path = self.root / self.INDEX_NAME
        self.lock_path = self.root / ".pmiri-write.lock"

    @contextmanager
    def _write_lock(self) -> Iterator[None]:
        """Serialize writers without adding a third-party dependency."""
        self.root.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("a+b") as handle:
            if os.name == "nt":
                import msvcrt

                handle.seek(0, os.SEEK_END)
                if handle.tell() == 0:
                    handle.write(b"0")
                    handle.flush()
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                if os.name == "nt":
                    import msvcrt

                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _initialize_unlocked(self) -> None:
        self.blob_root.mkdir(parents=True, exist_ok=True)
        if not self.index_path.exists():
            self._write_index({"format": "pmiri-s0", "version": 1, "sources": []})

    def initialize(self) -> None:
        with self._write_lock():
            self._initialize_unlocked()

    def _read_index(self) -> dict:
        if not self.index_path.exists():
            return {"format": "pmiri-s0", "version": 1, "sources": []}
        try:
            data = json.loads(self.index_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("store_index_invalid") from exc
        if data.get("format") != "pmiri-s0" or not isinstance(data.get("sources"), list):
            raise ValueError("store_index_schema_invalid")
        return data

    def _write_index(self, data: dict) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix="index-", suffix=".tmp", dir=self.root)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(self.index_path)
        finally:
            if temporary.exists():
                temporary.unlink()

    def _write_blob(self, path: Path, content: bytes) -> None:
        descriptor, temporary_name = tempfile.mkstemp(prefix="blob-", suffix=".tmp", dir=self.blob_root)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(path)
        finally:
            if temporary.exists():
                temporary.unlink()

    @staticmethod
    def _source_id(project_id: str, source_name: str) -> str:
        return "src_" + sha256_json({"project_id": project_id, "source_name": source_name})[:32]

    def register_bytes(
        self,
        project_id: str,
        source_name: str,
        raw: bytes,
        *,
        capture_time: str | None = None,
        metadata: dict[str, str] | None = None,
    ) -> SourceRecord:
        name_path = Path(source_name)
        if not project_id or not source_name or name_path.is_absolute() or ".." in name_path.parts:
            raise ValueError("source_identity_invalid")
        content = normalize_text(raw)
        normalized = content.encode("utf-8")
        fingerprint = sha256_bytes(normalized)
        source_id = self._source_id(project_id, source_name.replace("\\", "/"))
        version_id = "ver_" + fingerprint
        record = SourceRecord(
            source_id=source_id,
            version_id=version_id,
            project_id=project_id,
            source_name=source_name.replace("\\", "/"),
            content_fingerprint=fingerprint,
            content=content,
            capture_time=capture_time or utc_now(),
            metadata=dict(metadata or {}),
        )
        with self._write_lock():
            self._initialize_unlocked()
            index = self._read_index()
            existing = [item for item in index["sources"] if item["source_id"] == source_id and item["version_id"] == version_id]
            if not existing:
                blob = self.blob_root / f"{fingerprint}.txt"
                if not blob.exists() or sha256_bytes(blob.read_bytes()) != fingerprint:
                    self._write_blob(blob, normalized)
                index["sources"].append(record.public_dict())
                index["sources"].sort(key=lambda item: (item["project_id"], item["source_id"], item["version_id"]))
                self._write_index(index)
        return record

    def register_file(self, project_id: str, path: str | Path, *, source_name: str | None = None) -> SourceRecord:
        source_path = Path(path)
        raw = source_path.read_bytes()
        return self.register_bytes(
            project_id,
            source_name or source_path.name,
            raw,
            metadata={"input_path": source_path.name},
        )

    def ingest_directory(self, project_id: str, directory: str | Path) -> tuple[SourceRecord, ...]:
        """Register only explicit UTF-8 Markdown/text files under one root."""
        source_root = Path(directory).resolve()
        if not source_root.is_dir():
            raise ValueError("ingest_root_not_directory")
        paths = [
            path for path in source_root.rglob("*")
            if path.is_file() and not path.is_symlink() and path.suffix.casefold() in {".md", ".markdown", ".txt"}
        ]
        records = []
        for path in sorted(paths, key=lambda item: item.relative_to(source_root).as_posix()):
            records.append(self.register_file(project_id, path, source_name=path.relative_to(source_root).as_posix()))
        return tuple(records)

    def list_sources(self, project_id: str | None = None, *, include_history: bool = False) -> tuple[SourceRecord, ...]:
        index = self._read_index()
        raw_records = []
        for item in index["sources"]:
            if project_id is None or item["project_id"] == project_id:
                raw_records.append(item)
        if not include_history:
            latest: dict[str, dict] = {}
            for item in raw_records:
                key = item["source_id"]
                current = latest.get(key)
                if current is None or (item["capture_time"], item["version_id"]) > (current["capture_time"], current["version_id"]):
                    latest[key] = item
            raw_records = list(latest.values())
        raw_records.sort(key=lambda item: (item["project_id"], item["source_id"], item["version_id"]))
        return tuple(self._record_from_dict(item) for item in raw_records)

    def get_source(self, source_id: str, version_id: str | None = None) -> SourceRecord:
        for record in self.list_sources(include_history=True):
            if record.source_id == source_id and (version_id is None or record.version_id == version_id):
                return record
        raise KeyError("source_not_found")

    def _record_from_dict(self, item: dict) -> SourceRecord:
        fingerprint = item["content_fingerprint"]
        blob = self.blob_root / f"{fingerprint}.txt"
        try:
            raw = blob.read_bytes()
            content = raw.decode("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise ValueError("source_blob_missing_or_invalid") from exc
        if sha256_bytes(raw) != fingerprint:
            raise ValueError("source_blob_fingerprint_mismatch")
        return SourceRecord(
            source_id=item["source_id"],
            version_id=item["version_id"],
            project_id=item["project_id"],
            source_name=item["source_name"],
            content_fingerprint=fingerprint,
            content=content,
            capture_time=item["capture_time"],
            metadata=item.get("metadata", {}),
        )

    def canonical_fingerprint(self) -> str:
        """Fingerprint only canonical metadata; query must not change it."""
        index = self._read_index()
        return sha256_json(index)


class SQLiteStore:
    """Transactional SQLite adapter for the S0 store contract.

    SQLite is selected as the first production-oriented adapter because it is
    bundled with Python, supports WAL/concurrent readers, and gives migration
    and transaction boundaries without adding an unreviewed dependency. The
    public surface intentionally mirrors :class:`LocalStore` so retrieval and
    runtime code remain storage-agnostic.
    """

    DB_NAME = "pmiri.sqlite3"
    SCHEMA_VERSION = 1

    def __init__(self, root: str | Path, *, blob_cipher: BlobCipher | None = None):
        self.root = Path(root)
        self.db_path = self.root / self.DB_NAME
        self.blob_cipher = blob_cipher

    def _connect(self, *, read_only: bool = False) -> sqlite3.Connection:
        if read_only:
            if not self.db_path.exists():
                raise FileNotFoundError(self.db_path)
            connection = sqlite3.connect(self.db_path.resolve().as_uri() + "?mode=ro", uri=True, timeout=30.0, isolation_level=None)
        else:
            connection = sqlite3.connect(self.db_path, timeout=30.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        if read_only:
            connection.execute("PRAGMA query_only = ON")
        else:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _ensure_schema(self, connection: sqlite3.Connection) -> None:
        connection.execute("CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        row = connection.execute("SELECT value FROM schema_meta WHERE key = 'version'").fetchone()
        if row is None:
            connection.execute("INSERT INTO schema_meta(key, value) VALUES ('version', ?)", (str(self.SCHEMA_VERSION),))
        elif int(row["value"]) != self.SCHEMA_VERSION:
            raise ValueError("sqlite_schema_version_unsupported")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS blobs (
                fingerprint TEXT PRIMARY KEY,
                content BLOB NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS sources (
                source_id TEXT NOT NULL,
                version_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                source_name TEXT NOT NULL,
                content_fingerprint TEXT NOT NULL REFERENCES blobs(fingerprint),
                capture_time TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                PRIMARY KEY (source_id, version_id)
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS sources_project_idx ON sources(project_id, source_id, version_id)")

    def _verify_schema(self, connection: sqlite3.Connection) -> None:
        try:
            row = connection.execute("SELECT value FROM schema_meta WHERE key = 'version'").fetchone()
        except sqlite3.OperationalError as exc:
            raise ValueError("sqlite_schema_invalid") from exc
        if row is None or int(row["value"]) != self.SCHEMA_VERSION:
            raise ValueError("sqlite_schema_version_unsupported")

    def initialize(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._ensure_schema(connection)
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise

    @staticmethod
    def _source_id(project_id: str, source_name: str) -> str:
        return LocalStore._source_id(project_id, source_name)

    @staticmethod
    def _validate_identity(project_id: str, source_name: str) -> str:
        name_path = Path(source_name)
        if not project_id or not source_name or name_path.is_absolute() or ".." in name_path.parts:
            raise ValueError("source_identity_invalid")
        return source_name.replace("\\", "/")

    def register_bytes(
        self,
        project_id: str,
        source_name: str,
        raw: bytes,
        *,
        capture_time: str | None = None,
        metadata: dict[str, str] | None = None,
    ) -> SourceRecord:
        normalized_name = self._validate_identity(project_id, source_name)
        content = normalize_text(raw)
        normalized = content.encode("utf-8")
        fingerprint = sha256_bytes(normalized)
        source_id = self._source_id(project_id, normalized_name)
        record = SourceRecord(
            source_id=source_id,
            version_id="ver_" + fingerprint,
            project_id=project_id,
            source_name=normalized_name,
            content_fingerprint=fingerprint,
            content=content,
            capture_time=capture_time or utc_now(),
            metadata=dict(metadata or {}),
        )
        if any(not isinstance(key, str) or not isinstance(value, str) for key, value in record.metadata.items()):
            raise ValueError("metadata_must_be_string_map")
        self.root.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._ensure_schema(connection)
                stored_content = self.blob_cipher.encrypt(fingerprint, normalized) if self.blob_cipher is not None else normalized
                connection.execute("INSERT OR IGNORE INTO blobs(fingerprint, content) VALUES (?, ?)", (fingerprint, stored_content))
                connection.execute(
                    """
                    INSERT OR IGNORE INTO sources
                    (source_id, version_id, project_id, source_name, content_fingerprint, capture_time, metadata_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (record.source_id, record.version_id, record.project_id, record.source_name, record.content_fingerprint, record.capture_time, json.dumps(record.metadata, ensure_ascii=False, sort_keys=True)),
                )
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise
        return record

    def register_file(self, project_id: str, path: str | Path, *, source_name: str | None = None) -> SourceRecord:
        source_path = Path(path)
        return self.register_bytes(project_id, source_name or source_path.name, source_path.read_bytes(), metadata={"input_path": source_path.name})

    def ingest_directory(self, project_id: str, directory: str | Path) -> tuple[SourceRecord, ...]:
        source_root = Path(directory).resolve()
        if not source_root.is_dir():
            raise ValueError("ingest_root_not_directory")
        paths = [path for path in source_root.rglob("*") if path.is_file() and not path.is_symlink() and path.suffix.casefold() in {".md", ".markdown", ".txt"}]
        return tuple(self.register_file(project_id, path, source_name=path.relative_to(source_root).as_posix()) for path in sorted(paths, key=lambda item: item.relative_to(source_root).as_posix()))

    def _rows(self, project_id: str | None = None) -> list[sqlite3.Row]:
        if not self.db_path.exists():
            return []
        with closing(self._connect(read_only=True)) as connection:
            self._verify_schema(connection)
            if project_id is None:
                return list(connection.execute("SELECT * FROM sources ORDER BY project_id, source_id, version_id"))
            return list(connection.execute("SELECT * FROM sources WHERE project_id = ? ORDER BY project_id, source_id, version_id", (project_id,)))

    def _record_from_row(self, row: sqlite3.Row) -> SourceRecord:
        with closing(self._connect(read_only=True)) as connection:
            blob = connection.execute("SELECT content FROM blobs WHERE fingerprint = ?", (row["content_fingerprint"],)).fetchone()
        if blob is None:
            raise ValueError("source_blob_missing_or_invalid")
        raw = bytes(blob["content"])
        if self.blob_cipher is not None:
            try:
                raw = self.blob_cipher.decrypt(row["content_fingerprint"], raw)
            except StorageEncryptionError as exc:
                raise ValueError("source_blob_decryption_failed") from exc
        if sha256_bytes(raw) != row["content_fingerprint"]:
            raise ValueError("source_blob_fingerprint_mismatch")
        try:
            metadata = json.loads(row["metadata_json"])
        except json.JSONDecodeError as exc:
            raise ValueError("source_metadata_invalid") from exc
        if not isinstance(metadata, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in metadata.items()):
            raise ValueError("source_metadata_invalid")
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("source_blob_missing_or_invalid") from exc
        return SourceRecord(row["source_id"], row["version_id"], row["project_id"], row["source_name"], row["content_fingerprint"], content, row["capture_time"], metadata)

    def list_sources(self, project_id: str | None = None, *, include_history: bool = False) -> tuple[SourceRecord, ...]:
        rows = self._rows(project_id)
        if not include_history:
            latest: dict[str, sqlite3.Row] = {}
            for row in rows:
                current = latest.get(row["source_id"])
                if current is None or (row["capture_time"], row["version_id"]) > (current["capture_time"], current["version_id"]):
                    latest[row["source_id"]] = row
            rows = list(latest.values())
        rows.sort(key=lambda row: (row["project_id"], row["source_id"], row["version_id"]))
        return tuple(self._record_from_row(row) for row in rows)

    def get_source(self, source_id: str, version_id: str | None = None) -> SourceRecord:
        for record in self.list_sources(include_history=True):
            if record.source_id == source_id and (version_id is None or record.version_id == version_id):
                return record
        raise KeyError("source_not_found")

    def canonical_fingerprint(self) -> str:
        payload = {"format": "pmiri-s0", "version": 1, "sources": [record.public_dict() for record in self.list_sources(include_history=True)]}
        return sha256_json(payload)

    def migrate_from_local_store(self, source_root: str | Path) -> dict[str, object]:
        """Copy every historical JSON-store record through transactional inserts."""
        if self.db_path.exists():
            raise ValueError("migration_target_exists")
        source_store = LocalStore(source_root)
        source_fingerprint = source_store.canonical_fingerprint()
        records = source_store.list_sources(include_history=True)
        self.initialize()
        for record in records:
            self.register_bytes(record.project_id, record.source_name, record.content.encode("utf-8"), capture_time=record.capture_time, metadata=dict(record.metadata))
        return {
            "status": "MIGRATED",
            "source_count": len(records),
            "source_fingerprint": source_fingerprint,
            "target_fingerprint": self.canonical_fingerprint(),
        }

    def migration_plan(self, source_root: str | Path) -> dict[str, object]:
        """Inspect a JSON-store migration without creating or changing the target."""
        source_store = LocalStore(source_root)
        source_fingerprint = source_store.canonical_fingerprint()
        records = source_store.list_sources(include_history=True)
        target_exists = self.db_path.exists()
        target_root_non_empty = self.root.exists() and any(self.root.iterdir())
        return {
            "status": "MIGRATION_DRY_RUN",
            "source_count": len(records),
            "project_count": len({record.project_id for record in records}),
            "source_fingerprint": source_fingerprint,
            "target_path": self.db_path.resolve().as_posix(),
            "target_exists": target_exists,
            "target_root_non_empty": target_root_non_empty,
            "write_performed": False,
            "ready_for_migration": not target_exists and not target_root_non_empty,
        }

    def backup_to(self, destination_root: str | Path) -> dict[str, object]:
        """Create a consistent SQLite backup and verify its canonical content."""
        if not self.db_path.exists():
            raise ValueError("sqlite_store_not_initialized")
        destination = SQLiteStore(destination_root, blob_cipher=self.blob_cipher)
        if destination.db_path.exists():
            raise ValueError("backup_destination_exists")
        destination.root.mkdir(parents=True, exist_ok=True)
        source_fingerprint = self.canonical_fingerprint()
        source = self._connect(read_only=True)
        target = sqlite3.connect(destination.db_path, timeout=30.0, isolation_level=None)
        try:
            source.backup(target)
            target.commit()
        finally:
            target.close()
            source.close()
        destination_fingerprint = destination.canonical_fingerprint()
        if source_fingerprint != destination_fingerprint:
            raise ValueError("sqlite_backup_fingerprint_mismatch")
        return {
            "status": "BACKUP_VERIFIED",
            "source_fingerprint": source_fingerprint,
            "backup_fingerprint": destination_fingerprint,
            "backup_path": destination.db_path.resolve().as_posix(),
        }

    def restore_from_backup(self, destination_root: str | Path) -> dict[str, object]:
        """Restore into a new destination and verify the canonical fingerprint.

        The destination must not already exist. This deliberate no-overwrite
        rule makes a recovery rehearsal safe to run beside an existing store;
        an operator can inspect and promote the restored directory separately.
        """
        if not self.db_path.exists():
            raise ValueError("sqlite_backup_not_initialized")
        destination = Path(destination_root)
        if destination.exists():
            raise ValueError("restore_destination_exists")
        report = self.backup_to(destination)
        return {
            "status": "RESTORE_VERIFIED",
            "source_fingerprint": report["source_fingerprint"],
            "restored_fingerprint": report["backup_fingerprint"],
            "restore_path": report["backup_path"],
        }


__all__ = ["LocalStore", "SQLiteStore"]
