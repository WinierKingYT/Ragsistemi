from __future__ import annotations

import json
import textwrap
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from pmiri.store import SQLiteStore
from scripts.smoke_host_deployment import run_host_deployment_smoke


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class HostDeploymentSmokeTests(unittest.TestCase):
    def test_host_native_smoke_checks_loopback_rejection_and_audit(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            store_root = root / "store"
            audit_path = root / "audit.jsonl"
            SQLiteStore(store_root).initialize()
            profile = json.loads((PROJECT_ROOT / "deployment-profile.example.json").read_text(encoding="utf-8"))
            profile["storage"]["root"] = str(store_root)
            profile["control_plane"]["path"] = str(root / "deployment-owned.db")
            profile["api"]["audit_path"] = str(audit_path)
            profile_path = root / "profile.json"
            profile_path.write_text(json.dumps(profile), encoding="utf-8")
            (root / "host_adapter.py").write_text(
                textwrap.dedent(
                    """
                    from pmiri.request_auth import FixedWindowRateLimiter, ReplayGuard
                    from pmiri.server import ServerAuthorizationAdapters

                    class Registry:
                        def resolve(self, authentication_ref): return None
                        def register(self, principal): pass
                        def revoke(self, authentication_ref): pass

                    class Epoch:
                        def get(self): return 0
                        def advance(self, new_epoch): pass

                    def build_authorization_adapters(config):
                        return ServerAuthorizationAdapters(Registry(), ReplayGuard(), FixedWindowRateLimiter(), Epoch())
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            result = run_host_deployment_smoke(
                profile_path,
                adapter_module="host_adapter",
                adapter_dir=root,
            )

            self.assertEqual(result["status"], "HOST_NATIVE_DEPLOYMENT_SMOKE_PASS")
            self.assertEqual(result["health"], {"status": "OK", "transport": "LOOPBACK_ONLY"})
            self.assertEqual(result["unauthenticated_read_status"], 401)
            self.assertEqual(result["teardown"], "PROCESS_STOPPED_IN_FINALLY")
            self.assertTrue(audit_path.is_file())
            self.assertFalse((root / "deployment-owned.db").exists())


if __name__ == "__main__":
    unittest.main()
