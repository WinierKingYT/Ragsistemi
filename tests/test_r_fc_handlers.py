from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from pmiri.r_fc_handlers import HANDLERS, LOCAL_REPORT_KIND, run_local_r_fc_candidate


class LocalRfcHandlerTests(unittest.TestCase):
    def test_all_declared_cases_have_executable_local_handlers_and_match_oracles(self):
        self.assertEqual(len(HANDLERS), 34)
        with TemporaryDirectory() as temp:
            report = run_local_r_fc_candidate(
                Path("."),
                output_path=Path(temp) / "local-rfc.json",
            )
            self.assertEqual(report["artifact_kind"], LOCAL_REPORT_KIND)
            self.assertEqual(report["status"], "LOCAL_SYNTHETIC_ONLY")
            self.assertEqual(report["selected_case_count"], 34)
            self.assertEqual(report["executed_case_count"], 34)
            self.assertEqual(report["handler_error_count"], 0)
            self.assertEqual(report["oracle_match_count"], 34)
            self.assertTrue(report["all_oracles_match"])
            self.assertEqual(report["r_fc_pass"], "NONE")
            self.assertEqual(report["external_network_access"], "NOT_PERFORMED")

    def test_local_case_selection_is_closed(self):
        with self.assertRaisesRegex(ValueError, "local_r_fc_case_selection_invalid"):
            run_local_r_fc_candidate(Path("."), case_ids=["GC-C1-FC01-P", "not-declared"])


if __name__ == "__main__":
    unittest.main()
