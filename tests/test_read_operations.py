from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from pmiri.read_operations import (
    ExternalReadEmissionFence,
    ExternalReadEmissionError,
    READ_OPERATIONS,
    ReadOperationService,
    operation_parity_fingerprint,
)
from pmiri.read_projection import ReadProjectionService
from pmiri.runtime import LocalEvidenceRuntime
from pmiri.store import LocalStore


class ReadOperationTests(unittest.TestCase):
    def _service(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        store = LocalStore(Path(temp.name) / "store")
        store.initialize()
        store.register_bytes("project", "guide.md", b"release status is ready\n", capture_time="2026-01-01T00:00:00Z")
        return ReadOperationService(ReadProjectionService(LocalEvidenceRuntime(store)))

    def test_all_declared_operations_have_typed_result_projection_and_fence(self):
        service = self._service()
        raw = {"request_id": "operation-inventory", "project_constraint": "project", "query": "release"}

        for operation in READ_OPERATIONS:
            with self.subTest(operation=operation):
                api = service.api(operation, raw)
                mcp = service.mcp(operation, raw)
                equal, api_fingerprint, mcp_fingerprint = operation_parity_fingerprint(api, mcp)
                self.assertTrue(equal)
                self.assertEqual(api_fingerprint, mcp_fingerprint)
                self.assertEqual(api["typed_result"]["operation"], operation)
                self.assertEqual(api["emission_fence"]["status"], "EMIT_VALID")
                self.assertTrue(api["projection"]["continuation"].startswith("cursor_"))

                fence = ExternalReadEmissionFence.create(operation, api["projection"], api["typed_result"])
                fence.assert_valid(api)

                continued = service.api(operation, {**raw, "cursor": api["projection"]["continuation"]})
                self.assertEqual(continued["projection"]["continuation"], api["projection"]["continuation"])

    def test_cursor_and_transport_operation_cannot_be_substituted(self):
        service = self._service()
        raw = {"request_id": "operation-binding", "project_constraint": "project", "query": "release"}
        search = service.api("search", raw)

        with self.assertRaisesRegex(ValueError, "read_operation_substitution"):
            service.api("status", {**raw, "operation": "search"})
        with self.assertRaisesRegex(ValueError, "read_cursor_binding_mismatch"):
            service.api("status", {**raw, "cursor": search["projection"]["continuation"]})

    def test_fence_rejects_tampered_typed_result(self):
        service = self._service()
        response = service.api(
            "fetch_evidence",
            {"request_id": "operation-fence", "project_constraint": "project", "query": "release"},
        )
        tampered = {**response, "typed_result": {**response["typed_result"], "coverage": "tampered"}}
        fence = ExternalReadEmissionFence.create("fetch_evidence", response["projection"], response["typed_result"])
        with self.assertRaisesRegex(ExternalReadEmissionError, "read_typed_result_fingerprint_mismatch"):
            fence.assert_valid(tampered)


if __name__ == "__main__":
    unittest.main()
