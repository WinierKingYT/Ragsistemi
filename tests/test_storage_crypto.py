from __future__ import annotations

import json
import sqlite3
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from pmiri.canonical import sha256_bytes
from pmiri.storage_crypto import AesGcmBlobCipher, StorageEncryptionError
from pmiri.store import SQLiteStore


class StaticKeyProvider:
    def __init__(self):
        self.keys = {
            "STORE_BLOB_V1": b"1" * 32,
            "STORE_BLOB_V2": b"2" * 32,
        }

    def get_key(self, domain_id: str) -> bytes:
        return self.keys[domain_id]


class RecordingKeyEscrow:
    def __init__(self):
        self.calls = []

    def escrow(self, *, domain_id: str, key_version: str, key_fingerprint: str) -> None:
        self.calls.append(
            {
                "domain_id": domain_id,
                "key_version": key_version,
                "key_fingerprint": key_fingerprint,
            }
        )


class FailingKeyEscrow:
    def escrow(self, *, domain_id: str, key_version: str, key_fingerprint: str) -> None:
        raise RuntimeError("escrow_unavailable")


class StorageCryptoTests(unittest.TestCase):
    def test_versioned_ciphertext_is_authenticated_and_rotatable(self):
        provider = StaticKeyProvider()
        cipher = AesGcmBlobCipher(provider)
        plaintext = b"classified release material"
        fingerprint = sha256_bytes(plaintext)
        first = cipher.encrypt(fingerprint, plaintext)
        self.assertNotIn(plaintext, first)
        self.assertEqual(cipher.decrypt(fingerprint, first), plaintext)

        cipher.rotate("V2")
        second = cipher.encrypt(fingerprint, plaintext)
        self.assertEqual(cipher.decrypt(fingerprint, first), plaintext)
        self.assertEqual(cipher.decrypt(fingerprint, second), plaintext)
        with self.assertRaises(StorageEncryptionError):
            cipher.decrypt("0" * 64, second)

        envelope = json.loads(second)
        envelope["ciphertext"] = envelope["ciphertext"][:-2] + ("AA" if envelope["ciphertext"][-2:] != "AA" else "BB")
        with self.assertRaises(StorageEncryptionError):
            cipher.decrypt(fingerprint, json.dumps(envelope).encode("utf-8"))

    def test_sqlite_store_encrypts_blob_content_and_backup_remains_readable(self):
        provider = StaticKeyProvider()
        cipher = AesGcmBlobCipher(provider)
        with TemporaryDirectory() as directory:
            root = Path(directory) / "store"
            store = SQLiteStore(root, blob_cipher=cipher)
            store.initialize()
            secret = b"top secret provider context"
            store.register_bytes("project", "guide.md", secret, capture_time="2026-01-01T00:00:00Z")

            connection = sqlite3.connect(store.db_path)
            try:
                stored = connection.execute("SELECT content FROM blobs").fetchone()[0]
            finally:
                connection.close()
            self.assertNotIn(secret, bytes(stored))
            self.assertEqual(store.list_sources()[0].content.encode("utf-8"), secret)

            backup_root = Path(directory) / "backup"
            report = store.backup_to(backup_root)
            self.assertEqual(report["status"], "BACKUP_VERIFIED")
            restored = SQLiteStore(backup_root, blob_cipher=cipher)
            self.assertEqual(restored.list_sources()[0].content.encode("utf-8"), secret)

    def test_key_rotation_escrows_a_fingerprint_without_exposing_raw_key(self):
        provider = StaticKeyProvider()
        escrow = RecordingKeyEscrow()
        cipher = AesGcmBlobCipher(provider, key_escrow=escrow)

        cipher.rotate("V2")

        self.assertEqual(cipher.current_key_version, "V2")
        self.assertEqual(
            escrow.calls,
            [
                {
                    "domain_id": "STORE_BLOB",
                    "key_version": "V2",
                    "key_fingerprint": sha256_bytes(b"2" * 32),
                }
            ],
        )
        self.assertNotIn(b"2" * 32, repr(escrow.calls).encode("utf-8"))

    def test_key_escrow_failure_keeps_previous_key_version_active(self):
        cipher = AesGcmBlobCipher(StaticKeyProvider(), key_escrow=FailingKeyEscrow())

        with self.assertRaisesRegex(StorageEncryptionError, "storage_key_escrow_failed"):
            cipher.rotate("V2")

        self.assertEqual(cipher.current_key_version, "V1")
        self.assertEqual(cipher.accepted_key_versions, frozenset({"V1"}))

    def test_invalid_key_escrow_adapter_is_rejected_at_construction(self):
        with self.assertRaisesRegex(StorageEncryptionError, "storage_key_escrow_invalid"):
            AesGcmBlobCipher(StaticKeyProvider(), key_escrow=object())


if __name__ == "__main__":
    unittest.main()
