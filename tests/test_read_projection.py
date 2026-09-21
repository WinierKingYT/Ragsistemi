from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from pmiri.models import QueryRequest
from pmiri.read_projection import ReadProjectionService, parity_fingerprint
from pmiri.runtime import LocalEvidenceRuntime
from pmiri.store import LocalStore


class ReadProjectionTests(unittest.TestCase):
    def _service(self, *, with_source=True):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        store = LocalStore(Path(temp.name) / "store")
        store.initialize()
        if with_source:
            store.register_bytes("project", "guide.md", b"release status is ready\n", capture_time="2026-01-01T00:00:00Z")
        return ReadProjectionService(LocalEvidenceRuntime(store))

    def test_api_and_mcp_share_identical_server_semantics(self):
        service = self._service()
        raw = {"request_id": "request-1", "project_constraint": "project", "query": "release status"}
        api = service.api(raw)
        mcp = service.mcp(raw)
        equal, api_fingerprint, mcp_fingerprint = parity_fingerprint(api, mcp)
        self.assertTrue(equal)
        self.assertEqual(api_fingerprint, mcp_fingerprint)
        self.assertEqual(api["lineage"]["authorization_ref"], mcp["lineage"]["authorization_ref"])
        self.assertTrue(api["continuation"].startswith("cursor_"))

    def test_client_authorization_reference_cannot_change_binding(self):
        service = self._service()
        trusted = service.api({"request_id": "request-2", "project_constraint": "project", "query": "release"})
        forged = service.api({"request_id": "request-2", "project_constraint": "project", "query": "release", "authorization_ref": "auth-wider"})
        self.assertEqual(trusted["lineage"]["authorization_ref"], forged["lineage"]["authorization_ref"])
        self.assertEqual(trusted["context"]["fingerprint"], forged["context"]["fingerprint"])

    def test_stateless_continuation_is_deterministic(self):
        service = self._service()
        raw = {"request_id": "request-3", "project_constraint": "project", "query": "release"}
        first = service.api(raw)
        second = service.mcp({**raw, "cursor": first["continuation"]})
        self.assertEqual(first["continuation"], second["continuation"])
        self.assertEqual(first["context"]["fingerprint"], second["context"]["fingerprint"])

    def test_unknown_fields_and_malformed_cursor_fail_closed(self):
        service = self._service()
        with self.assertRaisesRegex(ValueError, "field_not_allowed"):
            service.api({"request_id": "request-4", "project_constraint": "project", "query": "release", "admin": True})
        with self.assertRaisesRegex(ValueError, "cursor_invalid"):
            service.api({"request_id": "request-4", "project_constraint": "project", "query": "release", "cursor": "cursor-forged"})

    def test_unauthorized_existence_is_indistinguishable_from_empty_result(self):
        raw = {"request_id": "request-5", "project_constraint": "project", "query": "release"}
        populated = self._service(with_source=True)
        empty = self._service(with_source=False)
        denied = populated.api_disclosed(raw, authorized=False)
        no_result = empty.api_disclosed(raw, authorized=True)
        self.assertEqual(denied, no_result)

    def test_disclosed_facades_preserve_allowed_evidence_and_parity(self):
        service = self._service()
        raw = {"request_id": "request-6", "project_constraint": "project", "query": "release"}
        api = service.api_disclosed(raw, authorized=True)
        mcp = service.mcp_disclosed(raw, authorized=True)
        self.assertTrue(api["evidence"])
        equal, api_fingerprint, mcp_fingerprint = parity_fingerprint(api, mcp)
        self.assertTrue(equal)
        self.assertEqual(api_fingerprint, mcp_fingerprint)

    def test_unauthorized_projection_has_no_internal_reason_or_count(self):
        service = self._service()
        response = service.api_disclosed({"request_id": "request-7", "project_constraint": "project", "query": "release"}, authorized=False)
        self.assertEqual(response["result"], {"disposition": "EMPTY", "coverage": "unknown"})
        self.assertNotIn("reason", response)
        self.assertNotIn("count", response)
        self.assertEqual(response["evidence"], [])


if __name__ == "__main__":
    unittest.main()
