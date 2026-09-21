from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from pmiri.models import Coverage, Disposition, QueryRequest
from pmiri.network import NetworkBoundary, NetworkBoundaryError
from pmiri.egress import ExternalEmissionFence, compile_provider_neutral
from pmiri.runtime import LocalEvidenceRuntime
from pmiri.store import LocalStore


class V1SliceTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.store = LocalStore(Path(self.temp.name) / "store")
        self.store.initialize()
        self.store.register_bytes(
            "project-alpha",
            "source-a.md",
            b"# Release\nThe release status is ready.\n",
            capture_time="2026-01-01T00:00:00Z",
        )
        self.store.register_bytes(
            "project-alpha",
            "source-b.md",
            b"# Release\nThe release status is waiting for review.\n",
            capture_time="2026-01-01T00:00:00Z",
        )
        self.store.register_bytes("project-beta", "source-c.md", b"# Release\nThe release status is private.\n", capture_time="2026-01-01T00:00:00Z")
        self.store.register_bytes("project-alpha", "source-d.md", b"A recipe contains apples.\n", capture_time="2026-01-01T00:00:00Z")

    def tearDown(self):
        self.temp.cleanup()

    def test_vs01_register_retains_identity_version_and_hash(self):
        record = self.store.get_source(self.store.list_sources("project-alpha")[0].source_id)
        self.assertTrue(record.source_id.startswith("src_"))
        self.assertTrue(record.version_id.startswith("ver_"))
        self.assertEqual(len(record.content_fingerprint), 64)

    def test_vs02_identical_registration_is_deterministic(self):
        first = self.store.register_bytes("project-alpha", "same.md", b"same\n", capture_time="2026-01-01T00:00:00Z")
        before = self.store.canonical_fingerprint()
        second = self.store.register_bytes("project-alpha", "same.md", b"same\n", capture_time="2026-01-01T00:00:00Z")
        self.assertEqual(first.version_id, second.version_id)
        self.assertEqual(before, self.store.canonical_fingerprint())

    def test_source_history_does_not_make_old_version_current(self):
        first = self.store.register_bytes("project-alpha", "evolving.md", b"release old\n", capture_time="2026-01-01T00:00:00Z")
        second = self.store.register_bytes("project-alpha", "evolving.md", b"release new\n", capture_time="2026-01-02T00:00:00Z")
        self.assertNotEqual(first.version_id, second.version_id)
        current = self.store.list_sources("project-alpha")
        self.assertEqual([item.version_id for item in current if item.source_name == "evolving.md"], [second.version_id])
        self.assertEqual(len(self.store.list_sources("project-alpha", include_history=True)), len(current) + 1)

    def test_vs03_query_stays_in_project_and_has_anchors(self):
        result = LocalEvidenceRuntime(self.store).query(QueryRequest("r1", "project-alpha", "release status"))
        self.assertTrue(result.evidence)
        self.assertTrue(all(item.project_id == "project-alpha" and item.anchor for item in result.evidence))

    def test_vs04_foreign_project_is_not_authorization(self):
        result = LocalEvidenceRuntime(self.store).query(QueryRequest("r2", "project-alpha", "private"))
        self.assertEqual(result.disposition, Disposition.EMPTY)
        self.assertFalse(any(item.project_id == "project-beta" for item in result.evidence))

    def test_vs05_no_evidence_is_typed_empty(self):
        result = LocalEvidenceRuntime(self.store).query(QueryRequest("r3", "project-alpha", "quantum banana"))
        self.assertEqual(result.disposition, Disposition.EMPTY)
        self.assertEqual(result.coverage, Coverage.COMPLETE)
        self.assertEqual(result.context.text, "")

    def test_vs06_context_obeys_fixed_bound_and_keeps_citations(self):
        result = LocalEvidenceRuntime(self.store, context_bound=180).query(QueryRequest("r4", "project-alpha", "release"))
        self.assertLessEqual(len(result.context.text), 180)
        self.assertEqual(len(result.context.evidence_refs), len(result.context.citation_refs))

    def test_vs07_conflicting_evidence_is_visible(self):
        self.store.register_bytes(
            "project-alpha", "conflict-a.md", b"---\nconflict_group: release-status\n---\nRelease status is ready.\n", capture_time="2026-01-01T00:00:00Z"
        )
        self.store.register_bytes(
            "project-alpha", "conflict-b.md", b"---\nconflict_group: release-status\n---\nRelease status is blocked.\n", capture_time="2026-01-01T00:00:00Z"
        )
        result = LocalEvidenceRuntime(self.store, context_bound=1000).query(QueryRequest("r5", "project-alpha", "release status"))
        self.assertEqual(result.disposition, Disposition.CONFLICT)
        self.assertIn("release-status", " ".join(item.conflict_group or "" for item in result.evidence))

    def test_vs08_registration_order_does_not_change_result(self):
        a = LocalStore(Path(self.temp.name) / "a")
        b = LocalStore(Path(self.temp.name) / "b")
        docs = [("z.md", b"alpha beta\n"), ("a.md", b"alpha gamma\n")]
        for name, content in docs:
            a.register_bytes("p", name, content, capture_time="2026-01-01T00:00:00Z")
        for name, content in reversed(docs):
            b.register_bytes("p", name, content, capture_time="2026-01-01T00:00:00Z")
        ra = LocalEvidenceRuntime(a).query(QueryRequest("same", "p", "alpha")).structured()
        rb = LocalEvidenceRuntime(b).query(QueryRequest("same", "p", "alpha")).structured()
        self.assertEqual(ra, rb)

    def test_vs09_repeat_query_is_equivalent(self):
        runtime = LocalEvidenceRuntime(self.store)
        request = QueryRequest("repeat", "project-alpha", "release")
        self.assertEqual(runtime.query(request).structured(), runtime.query(request).structured())

    def test_vs10_malformed_utf8_fails_closed(self):
        with self.assertRaises(UnicodeDecodeError):
            self.store.register_bytes("project-alpha", "bad.md", b"\xff\xfe")

    def test_vs11_external_network_is_denied_without_call(self):
        boundary = NetworkBoundary()
        decision = boundary.evaluate("external_fetch", "https://example.com/a")
        self.assertEqual(decision.action_result, "DENY")
        self.assertEqual(decision.reason_class, "OUTBOUND_NETWORK_DISABLED")
        with self.assertRaises(NetworkBoundaryError):
            boundary.fetch("external_fetch", "https://example.com/a")

    def test_vs12_query_does_not_mutate_canonical_state(self):
        before = self.store.canonical_fingerprint()
        LocalEvidenceRuntime(self.store).query(QueryRequest("r12", "project-alpha", "release"))
        self.assertEqual(before, self.store.canonical_fingerprint())

    def test_provider_neutral_handoff_preserves_lineage_and_has_local_fence(self):
        result = LocalEvidenceRuntime(self.store).query(QueryRequest("egress", "project-alpha", "release"))
        envelope = compile_provider_neutral(result.context)
        self.assertEqual(envelope.authorization_lineage, result.authorization_lineage)
        self.assertEqual(envelope.citation_refs, result.context.citation_refs)
        ExternalEmissionFence().emit(envelope, current_context_fingerprint=result.context.fingerprint, destination="LOCAL_ONLY")
        with self.assertRaises(PermissionError):
            ExternalEmissionFence().emit(envelope, current_context_fingerprint=result.context.fingerprint, destination="cloud-provider")


if __name__ == "__main__":
    unittest.main()
