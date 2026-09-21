from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from pmiri.models import QueryRequest
from pmiri.runtime import LocalEvidenceRuntime
from pmiri.store import LocalStore


class FixtureCorpusTest(unittest.TestCase):
    def test_documented_synthetic_corpus_runs_end_to_end(self):
        fixture_root = Path(__file__).parents[1] / "fixtures" / "s0" / "project-alpha"
        with TemporaryDirectory() as temp:
            store = LocalStore(Path(temp) / "store")
            records = store.ingest_directory("project-alpha", fixture_root)
            self.assertEqual(len(records), 3)
            result = LocalEvidenceRuntime(store).query(QueryRequest("fixture", "project-alpha", "release status"))
            self.assertGreaterEqual(len(result.evidence), 2)
            self.assertTrue(all(item.project_id == "project-alpha" for item in result.evidence))


if __name__ == "__main__":
    unittest.main()
