"""Explicit local-candidate adapters for the isolated VM smoke path.

This module is intentionally not a production deployment adapter. It wires the
existing crash-safe SQLite control-plane implementations into the VM launcher
so the loopback server can be exercised after offline bootstrap. Production
must replace it with deployment-owned identity, revocation, coordination and
key-escrow integrations.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from pmiri.control_plane import SQLiteAuthenticationRegistry, SQLitePolicyEpoch, SQLiteRateLimiter, SQLiteReplayGuard
from pmiri.server import ServerAuthorizationAdapters


def _control_plane_path(config: Mapping[str, Any]) -> Path:
    value = config.get("control_plane_path")
    if not isinstance(value, str) or not value.strip():
        raise ValueError("local_candidate_control_plane_path_required")
    return Path(value).expanduser().resolve()


def build_authorization_adapters(config: Mapping[str, Any]) -> ServerAuthorizationAdapters:
    """Build and initialize the explicitly configured local control plane."""

    if not isinstance(config, Mapping):
        raise ValueError("local_candidate_adapter_config_invalid")
    path = _control_plane_path(config)
    registry = SQLiteAuthenticationRegistry(path)
    replay_guard = SQLiteReplayGuard(path)
    rate_limiter = SQLiteRateLimiter(path)
    policy_epoch = SQLitePolicyEpoch(path)
    registry.initialize()
    replay_guard.initialize()
    rate_limiter.initialize()
    policy_epoch.initialize()
    return ServerAuthorizationAdapters(registry, replay_guard, rate_limiter, policy_epoch)


__all__ = ["build_authorization_adapters"]
