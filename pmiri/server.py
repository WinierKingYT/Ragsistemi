"""Assembly boundary for the local authenticated read server candidate."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .audit import JsonlAuditSink
from .control_plane import SQLiteAuthenticationRegistry, SQLitePolicyEpoch, SQLiteRateLimiter, SQLiteReplayGuard
from .http_api import DEFAULT_MAX_REQUEST_BYTES, LocalReadHTTPServer
from .read_operations import ReadOperationService
from .read_projection import ReadProjectionService
from .request_auth import RequestAuthorizationService
from .runtime import LocalEvidenceRuntime
from .storage_crypto import BlobCipher
from .store import SQLiteStore


class LocalServerConfigurationError(ValueError):
    """Raised when the local server cannot be assembled safely."""


class AuthorizationRegistryAdapter(Protocol):
    """Deployment-owned identity and revocation port."""

    def resolve(self, authentication_ref: str | None) -> Any:
        ...

    def register(self, principal: Any) -> None:
        ...

    def revoke(self, authentication_ref: str) -> None:
        ...


class ReplayGuardAdapter(Protocol):
    """Deployment-owned single-consumer replay port."""

    def consume(self, *, request_id: str, fingerprint: str, expires_at: str, now: str) -> bool:
        ...


class RateLimiterAdapter(Protocol):
    """Deployment-owned atomic rate-limit port."""

    def consume(self, *, key: str, now: float | None = None) -> bool:
        ...


class PolicyEpochAdapter(Protocol):
    """Deployment-owned monotonic policy invalidation port."""

    def get(self) -> int:
        ...

    def advance(self, new_epoch: int) -> None:
        ...


@dataclass(frozen=True)
class ServerAuthorizationAdapters:
    """Injected identity/revocation and coordination ports for deployment.

    A supplied adapter set is owned and initialized by the deployment.  The
    builder only checks the required method surface and reads the current
    epoch; it never creates local SQLite state when this set is provided.
    """

    registry: AuthorizationRegistryAdapter
    replay_guard: ReplayGuardAdapter
    rate_limiter: RateLimiterAdapter
    policy_epoch_store: PolicyEpochAdapter


def _current_epoch(adapters: ServerAuthorizationAdapters) -> int:
    try:
        required_methods = (
            (adapters.registry, ("resolve", "register", "revoke")),
            (adapters.replay_guard, ("consume",)),
            (adapters.rate_limiter, ("consume",)),
            (adapters.policy_epoch_store, ("get", "advance")),
        )
    except (AttributeError, TypeError) as exc:
        raise LocalServerConfigurationError("authorization_adapters_invalid") from exc
    if any(not callable(getattr(adapter, method, None)) for adapter, methods in required_methods for method in methods):
        raise LocalServerConfigurationError("authorization_adapters_invalid")
    try:
        epoch = adapters.policy_epoch_store.get()
    except Exception as exc:  # deployment adapter outages must fail closed
        raise LocalServerConfigurationError("authorization_epoch_unavailable") from exc
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
        raise LocalServerConfigurationError("authorization_epoch_invalid")
    return epoch


def _validate_blob_cipher(blob_cipher: BlobCipher | None) -> None:
    if blob_cipher is None:
        return
    if not all(callable(getattr(blob_cipher, method, None)) for method in ("encrypt", "decrypt")):
        raise LocalServerConfigurationError("blob_cipher_invalid")


def build_local_read_server(
    storage_root: str | Path,
    control_plane_path: str | Path,
    *,
    port: int = 8765,
    audit_path: str | Path | None = "artifacts/read-audit.jsonl",
    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,
    authorization_adapters: ServerAuthorizationAdapters | None = None,
    blob_cipher: BlobCipher | None = None,
) -> LocalReadHTTPServer:
    """Assemble the loopback server from local or injected adapters.

    The content store must already exist. Control-plane table initialization is
    idempotent and creates no principals, so an empty control plane remains a
    fail-closed server where every authenticated request is rejected.  A
    deployment may inject an independently initialized identity/revocation and
    distributed-coordination adapter set, plus a metadata/blob cipher; these
    ports do not enable external network access by themselves.
    """
    _validate_blob_cipher(blob_cipher)
    store = SQLiteStore(storage_root, blob_cipher=blob_cipher)
    if not store.db_path.is_file():
        raise LocalServerConfigurationError("storage_not_initialized")

    if authorization_adapters is None:
        control_path = Path(control_plane_path)
        registry = SQLiteAuthenticationRegistry(control_path)
        replay_guard = SQLiteReplayGuard(control_path)
        rate_limiter = SQLiteRateLimiter(control_path)
        policy_epoch = SQLitePolicyEpoch(control_path)
        registry.initialize()
        replay_guard.initialize()
        rate_limiter.initialize()
        policy_epoch.initialize()
        adapters = ServerAuthorizationAdapters(registry, replay_guard, rate_limiter, policy_epoch)
    else:
        adapters = authorization_adapters
    current_epoch = _current_epoch(adapters)
    authorization = RequestAuthorizationService(
        adapters.registry,
        current_policy_epoch=current_epoch,
        rate_limiter=adapters.rate_limiter,
        replay_guard=adapters.replay_guard,
        policy_epoch_store=adapters.policy_epoch_store,
    )
    projection = ReadProjectionService(LocalEvidenceRuntime(store), authorization)
    sink = JsonlAuditSink(audit_path) if audit_path is not None else None
    return LocalReadHTTPServer(
        ("127.0.0.1", port),
        ReadOperationService(projection),
        max_request_bytes=max_request_bytes,
        audit_sink=sink,
    )


__all__ = [
    "AuthorizationRegistryAdapter",
    "LocalServerConfigurationError",
    "PolicyEpochAdapter",
    "RateLimiterAdapter",
    "ReplayGuardAdapter",
    "ServerAuthorizationAdapters",
    "build_local_read_server",
]
