"""Gate-D connector credential boundary.

Credential values are intentionally not serializable.  The public boundary
record contains scope and lifecycle metadata only; an opaque handle can inject
the value into an explicitly selected connector sink without exposing it to
models, fetched content, callers, logs, errors or canonical artifacts.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from .canonical import is_sha256, sha256_json
from .decisions import OPERATIONS


INJECTION_CHANNELS = frozenset({"PROCESS_MEMORY_HANDLE", "SIDECAR_SECRET_MOUNT", "DELEGATED_TOKEN_EXCHANGE", "EXPLICIT_PROXY_CREDENTIAL"})
VISIBILITY_PROHIBITIONS = frozenset({
    "SECRET_VALUE_TO_PROVIDER_MODEL",
    "SECRET_VALUE_TO_FETCHED_CONTENT",
    "SECRET_VALUE_TO_CALLER_CONTENT",
    "SECRET_VALUE_TO_LOGS",
    "SECRET_VALUE_TO_ERROR_PAYLOAD",
    "SECRET_VALUE_TO_CANONICAL_ARTIFACT",
})


class CredentialBoundaryViolation(ValueError):
    pass


def _parse_time(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if isinstance(value, str) and value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timestamp_must_be_timezone_aware")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class ConnectorCredentialBoundary:
    boundary_id: str
    connector_subject_ref: str
    operation: str
    connector_process_ref: str
    destination_ref: str
    operation_scope: tuple[str, ...]
    injection_channel: str
    visibility_prohibitions: tuple[str, ...]
    valid_from: str
    valid_until: str
    credential_epoch: int
    rotation_ref: str
    revocation_ref: str
    source_ref: str
    authority_manifest_fingerprint: str
    status: str = "ACTIVE"

    def __post_init__(self) -> None:
        if self.operation not in OPERATIONS or not set(self.operation_scope) <= OPERATIONS:
            raise CredentialBoundaryViolation("operation_scope_invalid")
        if self.operation not in self.operation_scope:
            raise CredentialBoundaryViolation("boundary_operation_not_in_scope")
        if self.injection_channel not in INJECTION_CHANNELS:
            raise CredentialBoundaryViolation("injection_channel_invalid")
        if set(self.visibility_prohibitions) != VISIBILITY_PROHIBITIONS:
            raise CredentialBoundaryViolation("visibility_prohibitions_incomplete")
        if self.credential_epoch < 0 or self.status not in {"ACTIVE", "EXPIRED", "REVOKED", "INVALID"}:
            raise CredentialBoundaryViolation("credential_lifecycle_invalid")
        if not is_sha256(self.authority_manifest_fingerprint):
            raise CredentialBoundaryViolation("authority_manifest_fingerprint_invalid")

    @property
    def fingerprint(self) -> str:
        return sha256_json(self.public_record(include_fingerprint=False))

    def public_record(self, *, include_fingerprint: bool = True) -> dict[str, Any]:
        record = {
            "record_type": "PMIRI_D2_CONNECTOR_CREDENTIAL_BOUNDARY",
            "schema_version": "0.2",
            "boundary_id": self.boundary_id,
            "connector_subject_ref": self.connector_subject_ref,
            "operation": self.operation,
            "audience": {"connector_process_ref": self.connector_process_ref, "destination_ref": self.destination_ref},
            "operation_scope": list(self.operation_scope),
            "injection_channel": self.injection_channel,
            "visibility_prohibitions": list(self.visibility_prohibitions),
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "credential_epoch": self.credential_epoch,
            "rotation_ref": self.rotation_ref,
            "revocation_ref": self.revocation_ref,
            "source_ref": self.source_ref,
            "authority_manifest_fingerprint": self.authority_manifest_fingerprint,
            "status": self.status,
        }
        if include_fingerprint:
            record["boundary_fingerprint"] = self.fingerprint
        return record

    def authorize(self, *, operation: str, connector_process_ref: str, destination_ref: str, current_epoch: int, now: str) -> tuple[bool, str]:
        if self.status != "ACTIVE":
            return False, "CREDENTIAL_SCOPE_INVALID"
        if operation != self.operation or operation not in self.operation_scope:
            return False, "CREDENTIAL_SCOPE_INVALID"
        if connector_process_ref != self.connector_process_ref or destination_ref != self.destination_ref:
            return False, "CREDENTIAL_SCOPE_INVALID"
        if current_epoch != self.credential_epoch:
            return False, "POLICY_EPOCH_CHANGED"
        try:
            if not (_parse_time(self.valid_from) <= _parse_time(now) <= _parse_time(self.valid_until)):
                return False, "CREDENTIAL_SCOPE_INVALID"
        except ValueError:
            return False, "CREDENTIAL_SCOPE_INVALID"
        return True, "NONE"


class OpaqueCredential:
    """A non-serializable secret handle with an intentionally redacted repr."""

    __slots__ = ("__secret", "boundary_fingerprint")

    def __init__(self, secret: bytes, boundary_fingerprint: str):
        if not isinstance(secret, bytes) or not secret:
            raise CredentialBoundaryViolation("secret_missing")
        self.__secret = secret
        self.boundary_fingerprint = boundary_fingerprint

    def __repr__(self) -> str:
        return "OpaqueCredential(<redacted>)"

    def inject(self, sink: Callable[[bytes], Any]) -> Any:
        if not callable(sink):
            raise CredentialBoundaryViolation("credential_sink_invalid")
        return sink(self.__secret)


@dataclass(frozen=True)
class CredentialBindingResult:
    action_result: str
    reason_class: str
    handle: OpaqueCredential | None
    boundary_fingerprint: str

    def public_dict(self) -> dict[str, Any]:
        return {
            "action_result": self.action_result,
            "reason_class": self.reason_class,
            "handle": "OPAQUE_HANDLE" if self.handle is not None else None,
            "boundary_fingerprint": self.boundary_fingerprint,
        }


class CredentialManager:
    def bind(
        self,
        boundary: ConnectorCredentialBoundary,
        secret: bytes,
        *,
        operation: str,
        connector_process_ref: str,
        destination_ref: str,
        current_epoch: int,
        now: str,
    ) -> CredentialBindingResult:
        allowed, reason = boundary.authorize(
            operation=operation,
            connector_process_ref=connector_process_ref,
            destination_ref=destination_ref,
            current_epoch=current_epoch,
            now=now,
        )
        if not allowed:
            return CredentialBindingResult("DENY", reason, None, boundary.fingerprint)
        return CredentialBindingResult("ALLOW", "NONE", OpaqueCredential(secret, boundary.fingerprint), boundary.fingerprint)


__all__ = [
    "ConnectorCredentialBoundary",
    "CredentialBindingResult",
    "CredentialBoundaryViolation",
    "CredentialManager",
    "OpaqueCredential",
]
