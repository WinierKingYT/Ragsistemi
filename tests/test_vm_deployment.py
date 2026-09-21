from __future__ import annotations

import importlib.util
import json
import textwrap
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from pmiri.store import SQLiteStore


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LAUNCHER_PATH = PROJECT_ROOT / "deployment" / "vm" / "serve_vm.py"


def _load_launcher():
    spec = importlib.util.spec_from_file_location("pmiri_vm_launcher_test", LAUNCHER_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load VM launcher")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class VmDeploymentLauncherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.launcher = _load_launcher()

    def test_requires_deployment_owned_adapter_builder(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            module_path = root / "empty_adapter.py"
            module_path.write_text("VALUE = 1\n", encoding="utf-8")
            with self.assertRaisesRegex(self.launcher.VmDeploymentConfigurationError, "builder_missing"):
                self.launcher.build_vm_server(
                    PROJECT_ROOT / "deployment-profile.example.json",
                    adapter_module="empty_adapter",
                    adapter_dir=root,
                )

    def test_injected_adapter_starts_loopback_without_local_control_plane_creation(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            store_root = root / "store"
            control_path = root / "local-control.db"
            audit_path = root / "audit.jsonl"
            SQLiteStore(store_root).initialize()
            profile = json.loads((PROJECT_ROOT / "deployment-profile.example.json").read_text(encoding="utf-8"))
            profile["storage"]["root"] = str(store_root)
            profile["control_plane"]["path"] = str(control_path)
            profile["api"]["audit_path"] = str(audit_path)
            profile_path = root / "profile.json"
            profile_path.write_text(json.dumps(profile), encoding="utf-8")
            module_path = root / "injected_adapter.py"
            module_path.write_text(
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
            server, startup = self.launcher.build_vm_server(
                profile_path,
                adapter_module="injected_adapter",
                adapter_dir=root,
                port=0,
            )
            try:
                self.assertEqual(startup["status"], "SERVING_LOOPBACK_ONLY")
                self.assertEqual(server.server_address[0], "127.0.0.1")
                self.assertFalse(control_path.exists())
            finally:
                server.server_close()

    def test_encrypted_profile_requires_blob_cipher_builder(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            store_root = root / "store"
            SQLiteStore(store_root).initialize()
            profile = json.loads((PROJECT_ROOT / "deployment-profile.example.json").read_text(encoding="utf-8"))
            profile["storage"]["root"] = str(store_root)
            profile["storage"]["content_encryption"] = "AES_GCM_BLOB_ADAPTER"
            profile_path = root / "profile.json"
            profile_path.write_text(json.dumps(profile), encoding="utf-8")
            module_path = root / "adapter_without_cipher.py"
            module_path.write_text(
                "from pmiri.server import ServerAuthorizationAdapters\n"
                "from pmiri.request_auth import FixedWindowRateLimiter, ReplayGuard\n"
                "class Registry:\n"
                "    def resolve(self, authentication_ref): return None\n"
                "    def register(self, principal): pass\n"
                "    def revoke(self, authentication_ref): pass\n"
                "class Epoch:\n"
                "    def get(self): return 0\n"
                "    def advance(self, new_epoch): pass\n"
                "def build_authorization_adapters(config):\n"
                "    return ServerAuthorizationAdapters(Registry(), ReplayGuard(), FixedWindowRateLimiter(), Epoch())\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(self.launcher.VmDeploymentConfigurationError, "content_encryption_adapter_missing"):
                self.launcher.build_vm_server(
                    profile_path,
                    adapter_module="adapter_without_cipher",
                    adapter_dir=root,
                )

    def test_explicit_local_candidate_adapter_starts_with_its_own_control_plane(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            store_root = root / "store"
            control_path = root / "local-control.db"
            audit_path = root / "audit.jsonl"
            SQLiteStore(store_root).initialize()
            profile = json.loads((PROJECT_ROOT / "deployment-profile.example.json").read_text(encoding="utf-8"))
            profile["storage"]["root"] = str(store_root)
            profile["control_plane"]["path"] = str(control_path)
            profile["api"]["audit_path"] = str(audit_path)
            profile_path = root / "profile.json"
            profile_path.write_text(json.dumps(profile), encoding="utf-8")
            config_path = root / "adapter-config.json"
            config_path.write_text(json.dumps({"control_plane_path": str(control_path)}), encoding="utf-8")

            server, startup = self.launcher.build_vm_server(
                profile_path,
                adapter_module="deployment.vm.local_candidate_adapters",
                adapter_dir=PROJECT_ROOT,
                adapter_config=config_path,
                port=0,
            )
            try:
                self.assertEqual(startup["status"], "SERVING_LOOPBACK_ONLY")
                self.assertEqual(startup["adapter_module"], "deployment.vm.local_candidate_adapters")
                self.assertEqual(server.server_address[0], "127.0.0.1")
                self.assertTrue(control_path.exists())
            finally:
                server.server_close()


if __name__ == "__main__":
    unittest.main()
