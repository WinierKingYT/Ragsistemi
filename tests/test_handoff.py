from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from pmiri.handoff import HandoffError, create_handoff_bundle, verify_handoff


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class HandoffTests(unittest.TestCase):
    def test_materialized_bundle_is_self_verifying_and_external_review_scoped(self):
        with TemporaryDirectory(dir=PROJECT_ROOT) as temp:
            output = Path(temp) / "handoff"
            report = create_handoff_bundle(PROJECT_ROOT, output)
            self.assertEqual(report["status"], "HANDOFF_READY_FOR_EXTERNAL_REVIEW")
            self.assertEqual(report["external_execution"], "NOT_PERFORMED")
            self.assertGreater(report["payload_count"], 20)
            self.assertTrue((output / "payload" / "EXTERNAL_CLOSURE_CHECKLIST.md").is_file())
            self.assertEqual(verify_handoff(output / "handoff-manifest.json", project_root=PROJECT_ROOT), (True, "VERIFIED"))

    def test_bundle_detects_payload_tampering_and_refuses_overwrite(self):
        with TemporaryDirectory(dir=PROJECT_ROOT) as temp:
            output = Path(temp) / "handoff"
            create_handoff_bundle(PROJECT_ROOT, output)
            payload = output / "payload" / "fixtures" / "s0" / "project-alpha" / "source-a.md"
            payload.write_text(payload.read_text(encoding="utf-8") + "tampered\n", encoding="utf-8")
            self.assertEqual(verify_handoff(output / "handoff-manifest.json", project_root=PROJECT_ROOT), (False, "payload_fingerprint_mismatch:payload/fixtures/s0/project-alpha/source-a.md"))
            with self.assertRaisesRegex(HandoffError, "handoff_destination_exists"):
                create_handoff_bundle(PROJECT_ROOT, output)


if __name__ == "__main__":
    unittest.main()
