from __future__ import annotations

import json
import textwrap
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from pmiri.deployment_server import DeploymentConfigurationError, build_deployment_server
from pmiri.store import SQLiteStore


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class DeploymentServerTests(unittest.TestCase):
    def test_requires_explicit_deployment_adapter_builder(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "empty_adapter.py").write_text("VALUE = 1\n", encoding="utf-8")
            with self.assertRaisesRegex(DeploymentConfigurationError, "builder_missing"):
                build_deployment_server(
                    PROJECT_ROOT / "deployment-profile.example.json",
                    adapter_module="empty_adapter",
                    adapter_dir=root,
                )

    def test_injected_adapter_starts_loopback_without_local_control_plane_creation(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            store_root = root / "store"
            control_path = root / "unused-control.db"
            audit_path = root / "audit.jsonl"
            SQLiteStore(store_root).initialize()
            profile = json.loads((PROJECT_ROOT / "deployment-profile.example.json").read_text(encoding="utf-8"))
            profile["storage"]["root"] = str(store_root)
            profile["control_plane"]["path"] = str(control_path)
            profile["api"]["audit_path"] = str(audit_path)
            profile_path = root / "profile.json"
            profile_path.write_text(json.dumps(profile), encoding="utf-8")
            (root / "injected_adapter.py").write_text(
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
            server, startup = build_deployment_server(
                profile_path,
                adapter_module="injected_adapter",
                adapter_dir=root,
                port=0,
            )
            try:
                self.assertEqual(startup["status"], "SERVING_LOOPBACK_ONLY")
                self.assertEqual(startup["adapter_module"], "injected_adapter")
                self.assertEqual(server.server_address[0], "127.0.0.1")
                self.assertFalse(control_path.exists())
            finally:
                server.server_close()


if __name__ == "__main__":
    unittest.main()
