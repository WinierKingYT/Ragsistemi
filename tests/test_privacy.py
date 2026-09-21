from __future__ import annotations

import hashlib
import multiprocessing
import os
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from pmiri.privacy import DpapiKeyProvider, EncryptedTraceStore, TraceRetentionPolicy


class _MemoryKeyProvider:
    def get_key(self, domain_id: str) -> bytes:
        return hashlib.sha256(("test-key-domain:" + domain_id).encode("utf-8")).digest()


def _dpapi_key_worker(root: str) -> bytes:
    return DpapiKeyProvider(root).get_key("TRACE")


class PrivacyTests(unittest.TestCase):
    def test_raw_capture_is_disabled_by_default_and_writes_nothing(self):
        with TemporaryDirectory() as temp:
            store = EncryptedTraceStore(Path(temp) / "traces", key_provider=_MemoryKeyProvider())
            result = store.capture({"secret": "do-not-write"}, actor_role="independent_reviewer")
            self.assertEqual(result.status, "DISABLED")
            self.assertFalse(Path(temp, "traces").exists())

    def test_enabled_trace_is_encrypted_and_role_gated(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / "traces"
            store = EncryptedTraceStore(
                root,
                key_provider=_MemoryKeyProvider(),
                policy=TraceRetentionPolicy(capture_enabled=True, ttl_seconds=60, key_domain="TRACE"),
            )
            result = store.capture({"query": "sensitive query", "context": "sensitive context"}, actor_role="independent_reviewer", captured_at="2026-01-01T00:00:00Z")
            self.assertEqual(result.status, "RECORDED")
            raw = next(root.glob("trace_*.json")).read_text(encoding="utf-8")
            self.assertNotIn("sensitive query", raw)
            self.assertNotIn("sensitive context", raw)
            self.assertEqual(store.read(result.trace_id, actor_role="independent_reviewer", now="2026-01-01T00:00:30Z")["query"], "sensitive query")
            with self.assertRaisesRegex(PermissionError, "trace_access_denied"):
                store.read(result.trace_id, actor_role="operator")

    def test_expiry_and_purge_are_enforced(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / "traces"
            store = EncryptedTraceStore(
                root,
                key_provider=_MemoryKeyProvider(),
                policy=TraceRetentionPolicy(capture_enabled=True, ttl_seconds=60, key_domain="TRACE"),
            )
            result = store.capture({"value": "expires"}, actor_role="independent_reviewer", captured_at="2026-01-01T00:00:00Z")
            with self.assertRaisesRegex(PermissionError, "trace_expired"):
                store.read(result.trace_id, actor_role="independent_reviewer", now="2026-01-01T00:01:00Z")
            self.assertEqual(store.purge(now="2026-01-01T00:01:01Z"), 1)
            self.assertFalse(list(root.glob("trace_*.json")))

    def test_trace_read_rejects_path_like_identifiers(self):
        with TemporaryDirectory() as temp:
            store = EncryptedTraceStore(Path(temp) / "traces", key_provider=_MemoryKeyProvider())
            with self.assertRaisesRegex(ValueError, "trace_id_invalid"):
                store.read("trace_../outside", actor_role="independent_reviewer")

    @unittest.skipUnless(os.name == "nt", "DPAPI is Windows-specific")
    def test_dpapi_keys_are_persistent_and_domain_separated(self):
        with TemporaryDirectory() as temp:
            provider = DpapiKeyProvider(Path(temp) / "keys")
            trace_key = provider.get_key("TRACE")
            self.assertEqual(trace_key, provider.get_key("TRACE"))
            self.assertNotEqual(trace_key, provider.get_key("CREDENTIALS"))
            stored = b"".join(path.read_bytes() for path in Path(temp, "keys").glob("*.json"))
            self.assertNotIn(trace_key, stored)

    @unittest.skipUnless(os.name == "nt", "DPAPI is Windows-specific")
    def test_dpapi_first_key_creation_is_serialized_across_workers(self):
        for _attempt in range(5):
            with TemporaryDirectory() as temp:
                provider = DpapiKeyProvider(Path(temp) / "keys")
                with ThreadPoolExecutor(max_workers=8) as executor:
                    keys = list(executor.map(lambda _index: provider.get_key("TRACE"), range(16)))
                self.assertEqual(len(set(keys)), 1)
                self.assertEqual(len(list(Path(temp, "keys").glob("*.json"))), 1)

    @unittest.skipUnless(os.name == "nt", "DPAPI is Windows-specific")
    def test_dpapi_first_key_creation_is_serialized_across_processes(self):
        with TemporaryDirectory() as temp:
            root = str(Path(temp) / "keys")
            context = multiprocessing.get_context("spawn")
            with ProcessPoolExecutor(max_workers=4, mp_context=context) as executor:
                keys = list(executor.map(_dpapi_key_worker, [root] * 8))
            self.assertEqual(len(set(keys)), 1)
            self.assertEqual(len(list(Path(root).glob("*.json"))), 1)


if __name__ == "__main__":
    unittest.main()
