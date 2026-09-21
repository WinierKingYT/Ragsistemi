from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from pmiri.audit import AuditError, JsonlAuditSink, ReadAuditEvent, validate_audit_event


class AuditTests(unittest.TestCase):
    def test_redacted_event_is_fingerprinted_and_verified(self):
        with TemporaryDirectory() as temp:
            sink = JsonlAuditSink(Path(temp) / "audit.jsonl")
            event = ReadAuditEvent.emitted(
                operation="search",
                projection_fingerprint="a" * 64,
                typed_result_fingerprint="b" * 64,
                captured_at="2026-01-01T00:00:00Z",
            )
            sink.append(event)
            self.assertEqual(validate_audit_event(event.structured()), ())
            self.assertEqual(sink.read_verified(), (event.structured(),))

    def test_tampering_is_rejected(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "audit.jsonl"
            sink = JsonlAuditSink(path)
            sink.append(ReadAuditEvent.rejected(operation="search", status_code=401, captured_at="2026-01-01T00:00:00Z"))
            data = json.loads(path.read_text(encoding="utf-8"))
            data["status_code"] = 200
            path.write_text(json.dumps(data) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(AuditError, "event_fingerprint_mismatch"):
                sink.read_verified()


if __name__ == "__main__":
    unittest.main()
