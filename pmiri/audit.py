"""Redacted, fingerprinted audit events for the local read boundary.

Audit records deliberately exclude query text, project names, credentials,
authentication references and evidence contents. They prove that a bounded
operation was emitted or rejected and bind successful output to the existing
projection/typed-result fingerprints. This is a local candidate sink; durable
retention, centralized collection and independent audit administration remain
deployment responsibilities.
"""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Iterator, Mapping

from .canonical import is_sha256, sha256_json, utc_now
from .read_operations import READ_OPERATIONS


AUDIT_EVENT_TYPE = "PMIRI_READ_AUDIT_EVENT"
AUDIT_VERSION = "0.1"
_OUTCOMES = {"EMITTED", "REJECTED"}
_TRANSPORTS = {"HTTP_LOOPBACK", "LOCAL"}


class AuditError(ValueError):
    """Raised when an audit event or audit file is invalid."""


def _audit_operation(operation: str | None) -> str:
    return operation if operation in READ_OPERATIONS else "unknown"


@dataclass(frozen=True)
class ReadAuditEvent:
    """A minimal audit record with no caller-controlled sensitive fields."""

    captured_at: str
    transport: str
    operation: str
    outcome: str
    status_code: int
    projection_fingerprint: str | None
    typed_result_fingerprint: str | None
    error_code: str | None
    event_id: str
    event_fingerprint: str

    @classmethod
    def create(
        cls,
        *,
        transport: str,
        operation: str | None,
        outcome: str,
        status_code: int,
        projection_fingerprint: str | None = None,
        typed_result_fingerprint: str | None = None,
        error_code: str | None = None,
        captured_at: str | None = None,
    ) -> "ReadAuditEvent":
        timestamp = captured_at or utc_now()
        operation_value = _audit_operation(operation)
        payload = {
            "artifact_type": AUDIT_EVENT_TYPE,
            "artifact_version": AUDIT_VERSION,
            "captured_at": timestamp,
            "transport": transport,
            "operation": operation_value,
            "outcome": outcome,
            "status_code": status_code,
            "projection_fingerprint": projection_fingerprint,
            "typed_result_fingerprint": typed_result_fingerprint,
            "error_code": error_code,
        }
        event_fingerprint = sha256_json(payload)
        return cls(
            captured_at=timestamp,
            transport=transport,
            operation=operation_value,
            outcome=outcome,
            status_code=status_code,
            projection_fingerprint=projection_fingerprint,
            typed_result_fingerprint=typed_result_fingerprint,
            error_code=error_code,
            event_id="audit_" + event_fingerprint[:32],
            event_fingerprint=event_fingerprint,
        )

    @classmethod
    def emitted(
        cls,
        *,
        operation: str,
        projection_fingerprint: str,
        typed_result_fingerprint: str,
        status_code: int = 200,
        transport: str = "HTTP_LOOPBACK",
        captured_at: str | None = None,
    ) -> "ReadAuditEvent":
        return cls.create(
            transport=transport,
            operation=operation,
            outcome="EMITTED",
            status_code=status_code,
            projection_fingerprint=projection_fingerprint,
            typed_result_fingerprint=typed_result_fingerprint,
            captured_at=captured_at,
        )

    @classmethod
    def rejected(
        cls,
        *,
        operation: str | None,
        status_code: int,
        error_code: str = "REQUEST_REJECTED",
        transport: str = "HTTP_LOOPBACK",
        captured_at: str | None = None,
    ) -> "ReadAuditEvent":
        return cls.create(
            transport=transport,
            operation=operation,
            outcome="REJECTED",
            status_code=status_code,
            error_code=error_code,
            captured_at=captured_at,
        )

    def payload(self) -> dict[str, object]:
        return {
            "artifact_type": AUDIT_EVENT_TYPE,
            "artifact_version": AUDIT_VERSION,
            "captured_at": self.captured_at,
            "transport": self.transport,
            "operation": self.operation,
            "outcome": self.outcome,
            "status_code": self.status_code,
            "projection_fingerprint": self.projection_fingerprint,
            "typed_result_fingerprint": self.typed_result_fingerprint,
            "error_code": self.error_code,
        }

    def structured(self) -> dict[str, object]:
        return {**self.payload(), "event_id": self.event_id, "event_fingerprint": self.event_fingerprint}


def validate_audit_event(event: Mapping[str, object]) -> tuple[str, ...]:
    required = {
        "artifact_type", "artifact_version", "captured_at", "transport",
        "operation", "outcome", "status_code", "projection_fingerprint",
        "typed_result_fingerprint", "error_code", "event_id", "event_fingerprint",
    }
    errors = ["event_shape_invalid"] if set(event) != required else []
    if event.get("artifact_type") != AUDIT_EVENT_TYPE or event.get("artifact_version") != AUDIT_VERSION:
        errors.append("event_identity_invalid")
    if not isinstance(event.get("captured_at"), str) or not event["captured_at"]:
        errors.append("captured_at_invalid")
    if event.get("transport") not in _TRANSPORTS:
        errors.append("transport_invalid")
    if event.get("operation") not in (*READ_OPERATIONS, "unknown"):
        errors.append("operation_invalid")
    if event.get("outcome") not in _OUTCOMES:
        errors.append("outcome_invalid")
    status = event.get("status_code")
    if not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599:
        errors.append("status_code_invalid")
    for field in ("projection_fingerprint", "typed_result_fingerprint"):
        value = event.get(field)
        if value is not None and not is_sha256(value):
            errors.append("fingerprint_invalid:" + field)
    if event.get("outcome") == "EMITTED":
        if not is_sha256(event.get("projection_fingerprint")) or not is_sha256(event.get("typed_result_fingerprint")):
            errors.append("emitted_fingerprints_missing")
        if event.get("error_code") is not None:
            errors.append("emitted_error_present")
    elif event.get("outcome") == "REJECTED":
        if event.get("projection_fingerprint") is not None or event.get("typed_result_fingerprint") is not None:
            errors.append("rejected_fingerprints_present")
        if event.get("error_code") != "REQUEST_REJECTED":
            errors.append("rejected_error_invalid")
    event_id = event.get("event_id")
    claimed = event.get("event_fingerprint")
    if not isinstance(event_id, str) or not event_id.startswith("audit_"):
        errors.append("event_id_invalid")
    unsigned = {key: event.get(key) for key in (
        "artifact_type", "artifact_version", "captured_at", "transport", "operation",
        "outcome", "status_code", "projection_fingerprint", "typed_result_fingerprint", "error_code",
    )}
    if not is_sha256(claimed) or claimed != sha256_json(unsigned):
        errors.append("event_fingerprint_mismatch")
    if isinstance(event_id, str) and is_sha256(claimed) and event_id != "audit_" + claimed[:32]:
        errors.append("event_id_fingerprint_mismatch")
    return tuple(errors)


class JsonlAuditSink:
    """Append-only local JSONL sink with process-safe writer serialization."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        self._thread_lock = Lock()

    @contextmanager
    def _write_lock(self) -> Iterator[None]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._thread_lock:
            with self.lock_path.open("a+b") as handle:
                if os.name == "nt":
                    import msvcrt

                    handle.seek(0, os.SEEK_END)
                    if handle.tell() == 0:
                        handle.write(b"0")
                        handle.flush()
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    if os.name == "nt":
                        import msvcrt

                        handle.seek(0)
                        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def append(self, event: ReadAuditEvent) -> None:
        errors = validate_audit_event(event.structured())
        if errors:
            raise AuditError("audit_event_invalid:" + errors[0])
        line = json.dumps(event.structured(), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        with self._write_lock():
            with self.path.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write(line)
                stream.flush()
                os.fsync(stream.fileno())

    def read_verified(self) -> tuple[dict[str, object], ...]:
        if not self.path.exists():
            return ()
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            raise AuditError("audit_file_unreadable") from exc
        events: list[dict[str, object]] = []
        for line_number, line in enumerate(lines, 1):
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise AuditError(f"audit_line_invalid:{line_number}") from exc
            if not isinstance(event, dict):
                raise AuditError(f"audit_line_shape_invalid:{line_number}")
            errors = validate_audit_event(event)
            if errors:
                raise AuditError(f"audit_line_invalid:{line_number}:{errors[0]}")
            events.append(event)
        return tuple(events)


__all__ = ["AUDIT_EVENT_TYPE", "AUDIT_VERSION", "AuditError", "JsonlAuditSink", "ReadAuditEvent", "validate_audit_event"]
