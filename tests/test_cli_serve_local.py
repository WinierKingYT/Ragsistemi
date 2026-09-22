from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
import unittest
from http.client import HTTPConnection
from pathlib import Path
from tempfile import TemporaryDirectory

import pmiri
from pmiri.audit import JsonlAuditSink
from pmiri.integrity import sha256_json
from pmiri.store import SQLiteStore


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class ServeLocalCliTests(unittest.TestCase):
    def test_cli_starts_loopback_health_metrics_audit_and_teardown(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            store_root = root / "store"
            control_plane = root / "control.db"
            audit_path = root / "audit.jsonl"
            SQLiteStore(store_root).initialize()
            environment = os.environ.copy()
            package_root = Path(pmiri.__file__).resolve().parent.parent
            environment["PYTHONPATH"] = str(package_root) + os.pathsep + environment.get("PYTHONPATH", "")
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "pmiri.cli",
                    "serve-local",
                    str(store_root),
                    "--control-plane",
                    str(control_plane),
                    "--audit",
                    str(audit_path),
                    "--port",
                    "0",
                ],
                cwd=root,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            output: queue.Queue[str] = queue.Queue()

            def read_stdout() -> None:
                assert process.stdout is not None
                for line in process.stdout:
                    output.put(line)

            reader = threading.Thread(target=read_stdout, daemon=True)
            reader.start()
            try:
                try:
                    startup = json.loads(output.get(timeout=5))
                except queue.Empty as exc:
                    self.fail(f"serve-local did not announce readiness; returncode={process.poll()}")
                    raise AssertionError from exc
                self.assertEqual(startup["status"], "SERVING_LOOPBACK_ONLY")
                self.assertEqual(startup["host"], "127.0.0.1")
                port = int(startup["port"])
                self.assertGreater(port, 0)

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
                    {"request_id": "cli-server-1", "project_constraint": "project", "query": "release"},
                    {"Content-Type": "application/json"},
                )
                self.assertEqual(status, 401)
                self.assertEqual(denied, {"error": {"code": "REQUEST_REJECTED"}})

                status, metrics = request("GET", "/metrics")
                self.assertEqual(status, 200)
                self.assertEqual(metrics["metrics"]["http_requests_total"], 4)
                self.assertEqual(metrics["metrics"]["http_requests_rejected_total"], 1)
                self.assertEqual(metrics["metrics"]["http_requests_emitted_total"], 0)
                metrics_text = json.dumps(metrics, ensure_ascii=False).casefold()
                self.assertNotIn("authentication", metrics_text)
                self.assertNotIn("project", metrics_text)
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
            event_text = json.dumps(events[0], ensure_ascii=False).casefold()
            self.assertNotIn("cli-server-1", event_text)
            self.assertNotIn("project-alpha", event_text)
            self.assertNotIn("authentication", event_text)

    def test_cli_profile_supplies_storage_control_plane_and_audit_paths(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            profile = json.loads((PROJECT_ROOT / "deployment-profile.example.json").read_text(encoding="utf-8"))
            profile["storage"]["root"] = "profile-store"
            profile["control_plane"]["path"] = "profile-control.db"
            profile["api"]["audit_path"] = "profile-audit.jsonl"
            profile_path = root / "profile.json"
            profile_path.write_text(json.dumps(profile), encoding="utf-8")
            SQLiteStore(root / "profile-store").initialize()
            environment = os.environ.copy()
            package_root = Path(pmiri.__file__).resolve().parent.parent
            environment["PYTHONPATH"] = str(package_root) + os.pathsep + environment.get("PYTHONPATH", "")
            process = subprocess.Popen(
                [sys.executable, "-m", "pmiri.cli", "serve-local", "--profile", str(profile_path), "--port", "0"],
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
                self.assertEqual(startup["audit"], str((root / "profile-audit.jsonl").resolve()))
                self.assertEqual(startup["profile_id"], profile["profile_id"])
                self.assertEqual(startup["profile_fingerprint"], sha256_json(profile))
                self.assertEqual(startup["storage"], str((root / "profile-store").resolve()))
                self.assertEqual(startup["control_plane"], str((root / "profile-control.db").resolve()))
                self.assertTrue((root / "profile-control.db").is_file())
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
