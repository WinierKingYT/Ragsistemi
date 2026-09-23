"""Run the host-native deployment assembly smoke.

This command exercises only the loopback server assembled with an explicitly
supplied deployment adapter module. It proves health, metrics, unauthenticated
read rejection/redaction and audit teardown; it never enables external
provider, connector or network execution and never creates evidence for the
external closure gate.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
from http.client import HTTPConnection
from pathlib import Path
from typing import Any

# Keep the documented ``python scripts/smoke_host_deployment.py`` form usable
# from a source checkout.  Python otherwise places only ``scripts`` on
# sys.path, so the sibling ``pmiri`` package cannot be imported.
if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pmiri.audit import JsonlAuditSink
from pmiri.deployment_server import DeploymentConfigurationError, build_deployment_server


class HostDeploymentSmokeError(RuntimeError):
    """Raised when the host-native assembly smoke contract is not met."""


def _request(port: int, method: str, path: str, body: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
    connection = HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        payload = None if body is None else json.dumps(body).encode("utf-8")
        headers = {"Content-Type": "application/json"} if payload is not None else {}
        connection.request(method, path, body=payload, headers=headers)
        response = connection.getresponse()
        raw = response.read().decode("utf-8")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise HostDeploymentSmokeError("host_deployment_smoke_response_invalid") from exc
        if not isinstance(parsed, dict):
            raise HostDeploymentSmokeError("host_deployment_smoke_response_shape_invalid")
        return response.status, parsed
    finally:
        connection.close()


def run_host_deployment_smoke(
    profile_path: str | Path,
    *,
    adapter_module: str,
    adapter_dir: str | Path | None = None,
    adapter_config: str | Path | None = None,
    adapter_sha256: str | None = None,
) -> dict[str, Any]:
    """Start, probe and tear down one host-native deployment server."""

    server = None
    thread = None
    try:
        server, startup = build_deployment_server(
            profile_path,
            adapter_module=adapter_module,
            adapter_dir=adapter_dir,
            adapter_config=adapter_config,
            adapter_sha256=adapter_sha256,
            port=0,
        )
        thread = threading.Thread(target=server.serve_forever, name="pmiri-host-smoke", daemon=True)
        thread.start()
        port = int(startup["port"])

        health_status, health = _request(port, "GET", "/healthz")
        if health_status != 200 or health != {"status": "OK", "transport": "LOOPBACK_ONLY"}:
            raise HostDeploymentSmokeError("host_deployment_smoke_health_invalid")

        metrics_status, metrics = _request(port, "GET", "/metrics")
        if metrics_status != 200 or metrics.get("status") != "OK" or not isinstance(metrics.get("metrics"), dict):
            raise HostDeploymentSmokeError("host_deployment_smoke_metrics_invalid")

        read_status, denied = _request(
            port,
            "POST",
            "/v1/read/search",
            {"request_id": "host-native-smoke-1", "project_constraint": "project-alpha", "query": "release"},
        )
        if read_status != 401 or denied != {"error": {"code": "REQUEST_REJECTED"}}:
            raise HostDeploymentSmokeError("host_deployment_smoke_unauthenticated_read_invalid")

        return {
            "status": "HOST_NATIVE_DEPLOYMENT_SMOKE_PASS",
            "health": health,
            "metrics": metrics,
            "unauthenticated_read_status": read_status,
            "adapter_module": startup["adapter_module"],
            "host": startup["host"],
            "port": port,
            "audit_path": startup["audit"],
            "teardown": "PROCESS_STOPPED_IN_FINALLY",
        }
    except (DeploymentConfigurationError, OSError) as exc:
        raise HostDeploymentSmokeError(str(exc)) from exc
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=5)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Smoke the PMIRI host-native deployment assembly")
    parser.add_argument("--profile", required=True, help="closed JSON deployment profile")
    parser.add_argument("--adapter-module", required=True, help="module exposing build_authorization_adapters(config)")
    parser.add_argument("--adapter-dir", help="directory containing the adapter module")
    parser.add_argument("--adapter-config", help="JSON object of deployment-owned references")
    parser.add_argument("--adapter-sha256", help="expected SHA-256 of the loaded adapter module")
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        result = run_host_deployment_smoke(
            args.profile,
            adapter_module=args.adapter_module,
            adapter_dir=args.adapter_dir,
            adapter_config=args.adapter_config,
            adapter_sha256=args.adapter_sha256,
        )
        events = JsonlAuditSink(result["audit_path"]).read_verified()
        if not events or events[-1].get("outcome") != "REJECTED" or events[-1].get("status_code") != 401:
            raise HostDeploymentSmokeError("host_deployment_smoke_audit_invalid")
        result["audit"] = "REJECTED_401_REDACTED"
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except HostDeploymentSmokeError as exc:
        print(json.dumps({"status": "HOST_NATIVE_DEPLOYMENT_SMOKE_BLOCKED", "error": str(exc)}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
