"""Start the PMIRI loopback read server with deployment-owned VM adapters.

This launcher is intentionally small and fail-closed. It does not create a
local identity database, generate credentials, enable public binding, or make
provider/network calls. The adapter module is supplied by the authorized
deployment and must return an initialized ``ServerAuthorizationAdapters`` set.
"""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Mapping


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pmiri.canonical import sha256_json  # noqa: E402
from pmiri.readiness import ReadinessContractError, load_profile  # noqa: E402
from pmiri.server import (  # noqa: E402
    LocalServerConfigurationError,
    ServerAuthorizationAdapters,
    build_local_read_server,
)


class VmDeploymentConfigurationError(ValueError):
    """Raised when VM deployment inputs cannot be accepted safely."""


def _resolve_path(profile_path: Path, value: str | None) -> Path | None:
    if value is None:
        return None
    candidate = Path(value)
    return candidate.resolve() if candidate.is_absolute() else (profile_path.parent / candidate).resolve()


def _module_name_is_valid(module_name: str) -> bool:
    return bool(module_name) and all(part.isidentifier() for part in module_name.split("."))


def load_adapter_module(module_name: str, adapter_dir: str | Path | None = None) -> ModuleType:
    """Load one trusted, deployment-supplied adapter module without shelling out."""

    if not isinstance(module_name, str) or not _module_name_is_valid(module_name):
        raise VmDeploymentConfigurationError("vm_adapter_module_name_invalid")
    if adapter_dir is not None:
        adapter_root = Path(adapter_dir).resolve()
        if not adapter_root.is_dir():
            raise VmDeploymentConfigurationError("vm_adapter_directory_missing")
        if str(adapter_root) not in sys.path:
            sys.path.insert(0, str(adapter_root))
    try:
        return importlib.import_module(module_name)
    except Exception as exc:  # adapter import errors must not start a partial server
        raise VmDeploymentConfigurationError("vm_adapter_module_import_failed") from exc


def load_adapter_config(path: str | Path | None, profile_path: Path) -> Mapping[str, Any]:
    """Load non-secret adapter configuration; secret values must remain references."""

    if path is None:
        return {}
    config_path = _resolve_path(profile_path, str(path))
    assert config_path is not None
    try:
        value = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VmDeploymentConfigurationError("vm_adapter_config_invalid") from exc
    if not isinstance(value, dict):
        raise VmDeploymentConfigurationError("vm_adapter_config_must_be_object")
    return value


def build_vm_server(
    profile_path: str | Path,
    *,
    adapter_module: str,
    adapter_dir: str | Path | None = None,
    adapter_config: str | Path | None = None,
    port: int | None = None,
    max_request_bytes: int | None = None,
) -> tuple[Any, dict[str, Any]]:
    """Assemble a VM server using only explicitly supplied deployment adapters."""

    profile_source = Path(profile_path).resolve()
    profile = load_profile(profile_source)
    storage = profile["storage"]
    control_plane = profile["control_plane"]
    api = profile["api"]
    if storage.get("backend") != "sqlite" or not isinstance(storage.get("root"), str) or not storage["root"]:
        raise VmDeploymentConfigurationError("vm_storage_profile_unconfigured")

    storage_root = _resolve_path(profile_source, storage["root"])
    assert storage_root is not None
    configured_control_path = control_plane.get("path")
    control_plane_path = _resolve_path(profile_source, configured_control_path)
    if control_plane_path is None:
        # The injected adapter set owns the control plane. This path is never
        # opened by the builder, but keeps the common server contract explicit.
        control_plane_path = (profile_source.parent / ".pmiri-control" / "deployment-owned.db").resolve()
    audit_path = _resolve_path(profile_source, api["audit_path"])
    assert audit_path is not None

    effective_port = api["port"] if port is None else port
    effective_limit = api["max_request_bytes"] if max_request_bytes is None else max_request_bytes
    valid_port_range = range(1, 65536) if port is None else range(0, 65536)
    if not isinstance(effective_port, int) or isinstance(effective_port, bool) or effective_port not in valid_port_range:
        raise VmDeploymentConfigurationError("vm_api_port_invalid")
    if not isinstance(effective_limit, int) or isinstance(effective_limit, bool) or not 1 <= effective_limit <= 8 * 1024 * 1024:
        raise VmDeploymentConfigurationError("vm_api_request_limit_invalid")

    module = load_adapter_module(adapter_module, adapter_dir)
    builder = getattr(module, "build_authorization_adapters", None)
    if not callable(builder):
        raise VmDeploymentConfigurationError("vm_authorization_adapter_builder_missing")
    config = load_adapter_config(adapter_config, profile_source)
    try:
        adapters = builder(config)
    except Exception as exc:  # deployment adapter failures must fail before bind
        raise VmDeploymentConfigurationError("vm_authorization_adapter_build_failed") from exc
    if not isinstance(adapters, ServerAuthorizationAdapters):
        raise VmDeploymentConfigurationError("vm_authorization_adapters_invalid")

    blob_cipher = None
    blob_builder = getattr(module, "build_blob_cipher", None)
    if blob_builder is not None:
        if not callable(blob_builder):
            raise VmDeploymentConfigurationError("vm_blob_cipher_builder_invalid")
        try:
            blob_cipher = blob_builder(config)
        except Exception as exc:  # key/KMS adapter failures must fail closed
            raise VmDeploymentConfigurationError("vm_blob_cipher_build_failed") from exc
    if storage.get("content_encryption") == "AES_GCM_BLOB_ADAPTER" and blob_cipher is None:
        raise VmDeploymentConfigurationError("vm_content_encryption_adapter_missing")

    try:
        server = build_local_read_server(
            storage_root,
            control_plane_path,
            port=effective_port,
            audit_path=audit_path,
            max_request_bytes=effective_limit,
            authorization_adapters=adapters,
            blob_cipher=blob_cipher,
        )
    except (LocalServerConfigurationError, OSError) as exc:
        raise VmDeploymentConfigurationError("vm_server_assembly_failed") from exc

    startup = {
        "status": "SERVING_LOOPBACK_ONLY",
        "host": "127.0.0.1",
        "port": server.server_port,
        "profile_id": profile["profile_id"],
        "profile_fingerprint": sha256_json(profile),
        "adapter_module": adapter_module,
        "storage": str(storage_root),
        "control_plane": str(control_plane_path),
        "audit": str(audit_path),
    }
    return server, startup


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="PMIRI Windows VM deployment-owned loopback server")
    parser.add_argument("--profile", required=True, help="closed PMIRI deployment profile JSON")
    parser.add_argument("--adapter-module", required=True, help="trusted module exposing build_authorization_adapters(config)")
    parser.add_argument("--adapter-dir", help="directory containing the trusted adapter module")
    parser.add_argument("--adapter-config", help="JSON object of deployment-owned references, resolved beside the profile")
    parser.add_argument("--port", type=int, help="optional profile port override")
    parser.add_argument("--max-request-bytes", type=int, help="optional profile request-size override")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    server = None
    try:
        server, startup = build_vm_server(
            args.profile,
            adapter_module=args.adapter_module,
            adapter_dir=args.adapter_dir,
            adapter_config=args.adapter_config,
            port=args.port,
            max_request_bytes=args.max_request_bytes,
        )
    except (VmDeploymentConfigurationError, ReadinessContractError) as exc:
        print(json.dumps({"status": "VM_DEPLOYMENT_BLOCKED", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2

    print(json.dumps(startup, ensure_ascii=False), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
