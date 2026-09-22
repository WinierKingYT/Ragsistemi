from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import unittest
from http.client import HTTPConnection
from pathlib import Path
from tempfile import TemporaryDirectory

import pmiri
from pmiri.audit import JsonlAuditSink
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

    def test_cli_starts_host_native_deployment_process_on_loopback(self):
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
            (root / "cli_adapter.py").write_text(
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
            environment = os.environ.copy()
            # Run outside the checkout so CI exercises the installed wheel.
            # Locally, this resolves to the source package and keeps the test
            # runnable without a separate installation step.
            package_root = Path(pmiri.__file__).resolve().parent.parent
            expected_install = os.environ.get("PMIRI_INSTALLED_TARGET")
            if expected_install:
                self.assertEqual(package_root, Path(expected_install).resolve())
            environment["PYTHONPATH"] = str(package_root) + os.pathsep + environment.get("PYTHONPATH", "")
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "pmiri.cli",
                    "serve-deployment",
                    "--profile",
                    str(profile_path),
                    "--adapter-module",
                    "cli_adapter",
                    "--adapter-dir",
                    str(root),
                    "--port",
                    "0",
                ],
                cwd=root,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                assert process.stdout is not None
                startup_line = process.stdout.readline()
                self.assertTrue(startup_line)
                startup = json.loads(startup_line)
                self.assertEqual(startup["status"], "SERVING_LOOPBACK_ONLY")
                self.assertEqual(startup["host"], "127.0.0.1")
                port = int(startup["port"])
                self.assertGreater(port, 0)
                self.assertEqual(startup["adapter_module"], "cli_adapter")
                self.assertFalse(control_path.exists())

                def request(method: str, path: str, body: dict | None = None, headers: dict[str, str] | None = None):
                    connection = HTTPConnection("127.0.0.1", port, timeout=3)
                    try:
                        encoded = None if body is None else json.dumps(body).encode("utf-8")
                        connection.request(method, path, body=encoded, headers=headers or {})
                        response = connection.getresponse()
                        return response.status, json.loads(response.read().decode("utf-8"))
                    finally:
                        connection.close()

                status, health = request("GET", "/healthz")
                self.assertEqual(status, 200)
                self.assertEqual(health, {"status": "OK", "transport": "LOOPBACK_ONLY"})
                status, _ = request("GET", "/metrics")
                self.assertEqual(status, 200)
                status, denied = request(
                    "POST",
                    "/v1/read/search",
                    {"request_id": "host-deployment-1", "project_constraint": "project", "query": "release"},
                    {"Content-Type": "application/json"},
                )
                self.assertEqual(status, 401)
                self.assertEqual(denied, {"error": {"code": "REQUEST_REJECTED"}})
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                process.communicate(timeout=5)

            events = JsonlAuditSink(audit_path).read_verified()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["outcome"], "REJECTED")
            self.assertEqual(events[0]["status_code"], 401)


if __name__ == "__main__":
    unittest.main()
