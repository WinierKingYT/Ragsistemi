"""Durable local control-plane adapters for request authorization.

These adapters provide a crash-safe, multi-process local boundary for
principal revocation, request replay and rate-limit state.  They intentionally
do not verify credentials or claim to be a distributed identity provider.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from time import time
from typing import Any

from .request_auth import (
    ACTIVE,
    AuthenticatedPrincipal,
    AuthenticationRegistry,
    FixedWindowRateLimiter,
    ReplayGuard,
    RequestAuthorizationError,
    TrustZoneAttestation,
)


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(str(path), timeout=5.0, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout=5000")
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


@contextmanager
def _connection(path: Path):
    connection = _connect(path)
    try:
        yield connection
    finally:
        connection.close()


def _timestamp(value: str) -> float:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timestamp_must_be_timezone_aware")
    return parsed.astimezone(timezone.utc).timestamp()


def _principal_payload(principal: AuthenticatedPrincipal) -> dict[str, Any]:
    attestation = principal.trust_zone_attestation
    return {
        "authentication_ref": principal.authentication_ref,
        "principal_ref": principal.principal_ref,
        "principal_type": principal.principal_type,
        "service_principal_ref": principal.service_principal_ref,
        "workload_principal_ref": principal.workload_principal_ref,
        "human_principal_ref": principal.human_principal_ref,
        "trust_zone_attestation": {
            "attestation_id": attestation.attestation_id,
            "principal_ref": attestation.principal_ref,
            "zone_id": attestation.zone_id,
            "issuer_ref": attestation.issuer_ref,
            "evidence_refs": list(attestation.evidence_refs),
            "issued_at": attestation.issued_at,
            "valid_until": attestation.valid_until,
            "status": attestation.status,
            "fingerprint": attestation.fingerprint,
        },
        "allowed_projects": list(principal.allowed_projects),
        "allowed_operations": list(principal.allowed_operations),
        "allowed_purposes": list(principal.allowed_purposes),
        "delegation_grant_refs": list(principal.delegation_grant_refs),
        "policy_bundle_ref": principal.policy_bundle_ref,
        "policy_version": principal.policy_version,
        "policy_epoch": principal.policy_epoch,
        "issued_at": principal.issued_at,
        "valid_until": principal.valid_until,
        "status": principal.status,
        "fingerprint": principal.fingerprint,
    }


def _principal_from_payload(payload: dict[str, Any]) -> AuthenticatedPrincipal:
    raw_attestation = payload.get("trust_zone_attestation")
    if not isinstance(raw_attestation, dict):
        raise RequestAuthorizationError("stored_attestation_invalid")
    normalized_attestation = dict(raw_attestation)
    normalized_attestation["evidence_refs"] = tuple(normalized_attestation.get("evidence_refs", ()))
    attestation = TrustZoneAttestation(**normalized_attestation)
    expected_attestation = TrustZoneAttestation.issue(
        principal_ref=attestation.principal_ref,
        zone_id=attestation.zone_id,
        issuer_ref=attestation.issuer_ref,
        evidence_refs=attestation.evidence_refs,
        issued_at=attestation.issued_at,
        valid_until=attestation.valid_until,
        status=attestation.status,
    )
    if expected_attestation != attestation:
        raise RequestAuthorizationError("stored_attestation_fingerprint_mismatch")
    principal = AuthenticatedPrincipal.verified(
        authentication_ref=payload["authentication_ref"],
        principal_ref=payload["principal_ref"],
        principal_type=payload["principal_type"],
        service_principal_ref=payload["service_principal_ref"],
        workload_principal_ref=payload.get("workload_principal_ref"),
        human_principal_ref=payload.get("human_principal_ref"),
        trust_zone_attestation=attestation,
        allowed_projects=payload["allowed_projects"],
        allowed_operations=payload["allowed_operations"],
        allowed_purposes=payload["allowed_purposes"],
        delegation_grant_refs=payload.get("delegation_grant_refs", ()),
        policy_bundle_ref=payload["policy_bundle_ref"],
        policy_version=payload["policy_version"],
        policy_epoch=payload["policy_epoch"],
        issued_at=payload["issued_at"],
        valid_until=payload["valid_until"],
        status=payload.get("status", ACTIVE),
    )
    if principal.fingerprint != payload.get("fingerprint"):
        raise RequestAuthorizationError("stored_principal_fingerprint_mismatch")
    return principal


class SQLiteAuthenticationRegistry(AuthenticationRegistry):
    """SQLite-backed principal registry with explicit revocation."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).resolve()

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with _connection(self.path) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS authenticated_principals (
                    authentication_ref TEXT PRIMARY KEY,
                    principal_fingerprint TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    revoked_at REAL
                )
                """
            )

    def register(self, principal: AuthenticatedPrincipal) -> None:
        payload = _principal_payload(principal)
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        with _connection(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT principal_fingerprint, revoked_at FROM authenticated_principals WHERE authentication_ref=?",
                (principal.authentication_ref,),
            ).fetchone()
            if row is not None:
                if row["principal_fingerprint"] != principal.fingerprint:
                    connection.rollback()
                    raise RequestAuthorizationError("authentication_reference_rebound")
                if row["revoked_at"] is not None:
                    connection.rollback()
                    raise RequestAuthorizationError("principal_revoked")
                connection.commit()
                return
            connection.execute(
                "INSERT INTO authenticated_principals(authentication_ref, principal_fingerprint, payload_json, revoked_at) VALUES (?, ?, ?, NULL)",
                (principal.authentication_ref, principal.fingerprint, encoded),
            )
            connection.commit()

    def resolve(self, authentication_ref: str | None) -> AuthenticatedPrincipal | None:
        if not isinstance(authentication_ref, str) or not authentication_ref:
            return None
        with _connection(self.path) as connection:
            row = connection.execute(
                "SELECT payload_json FROM authenticated_principals WHERE authentication_ref=? AND revoked_at IS NULL",
                (authentication_ref,),
            ).fetchone()
        if row is None:
            return None
        try:
            payload = json.loads(row["payload_json"])
            return _principal_from_payload(payload)
        except (TypeError, ValueError, KeyError, json.JSONDecodeError, RequestAuthorizationError):
            return None

    def revoke(self, authentication_ref: str) -> bool:
        with _connection(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE authenticated_principals SET revoked_at=? WHERE authentication_ref=? AND revoked_at IS NULL",
                (time(), authentication_ref),
            )
            connection.commit()
            return cursor.rowcount == 1


class SQLiteReplayGuard(ReplayGuard):
    """Crash-safe replay guard that shares state across local workers."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).resolve()

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with _connection(self.path) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS request_replays (request_id TEXT PRIMARY KEY, request_fingerprint TEXT NOT NULL, expires_at REAL NOT NULL)"
            )

    def consume(self, *, request_id: str, fingerprint: str, expires_at: str, now: str) -> bool:
        now_epoch = _timestamp(now)
        expiry_epoch = _timestamp(expires_at)
        with _connection(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM request_replays WHERE expires_at<=?", (now_epoch,))
            row = connection.execute(
                "SELECT request_fingerprint FROM request_replays WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if row is not None:
                connection.commit()
                return False
            connection.execute(
                "INSERT INTO request_replays(request_id, request_fingerprint, expires_at) VALUES (?, ?, ?)",
                (request_id, fingerprint, expiry_epoch),
            )
            connection.commit()
            return True


class SQLiteRateLimiter(FixedWindowRateLimiter):
    """Crash-safe fixed-window limiter shared by local workers."""

    def __init__(self, path: str | Path, *, max_requests: int = 60, window_seconds: int = 60) -> None:
        super().__init__(max_requests=max_requests, window_seconds=window_seconds)
        self.path = Path(path).resolve()

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with _connection(self.path) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS rate_windows (limiter_key TEXT PRIMARY KEY, window_start REAL NOT NULL, request_count INTEGER NOT NULL)"
            )

    def consume(self, *, key: str, now: float | None = None) -> bool:
        current = time() if now is None else now
        with _connection(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT window_start, request_count FROM rate_windows WHERE limiter_key=?",
                (key,),
            ).fetchone()
            start, count = (current, 0) if row is None else (float(row["window_start"]), int(row["request_count"]))
            if current - start >= self.window_seconds:
                start, count = current, 0
            allowed = count < self.max_requests
            if allowed:
                count += 1
            connection.execute(
                "INSERT INTO rate_windows(limiter_key, window_start, request_count) VALUES (?, ?, ?) ON CONFLICT(limiter_key) DO UPDATE SET window_start=excluded.window_start, request_count=excluded.request_count",
                (key, start, count),
            )
            connection.commit()
            return allowed


class SQLitePolicyEpoch:
    """Monotonic shared policy epoch for local authorization workers."""

    def __init__(self, path: str | Path, *, initial_epoch: int = 0) -> None:
        if initial_epoch < 0:
            raise ValueError("policy_epoch_invalid")
        self.path = Path(path).resolve()
        self.initial_epoch = initial_epoch

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with _connection(self.path) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("CREATE TABLE IF NOT EXISTS policy_epoch (singleton INTEGER PRIMARY KEY CHECK(singleton=1), epoch INTEGER NOT NULL)")
            connection.execute("INSERT OR IGNORE INTO policy_epoch(singleton, epoch) VALUES (1, ?)", (self.initial_epoch,))

    def get(self) -> int:
        with _connection(self.path) as connection:
            row = connection.execute("SELECT epoch FROM policy_epoch WHERE singleton=1").fetchone()
        if row is None:
            raise RequestAuthorizationError("policy_epoch_uninitialized")
        return int(row["epoch"])

    def advance(self, new_epoch: int) -> None:
        if new_epoch < 0:
            raise ValueError("policy_epoch_invalid")
        with _connection(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute("SELECT epoch FROM policy_epoch WHERE singleton=1").fetchone()
            if current is None:
                connection.rollback()
                raise RequestAuthorizationError("policy_epoch_uninitialized")
            if new_epoch < int(current["epoch"]):
                connection.rollback()
                raise ValueError("policy_epoch_cannot_move_backwards")
            connection.execute("UPDATE policy_epoch SET epoch=? WHERE singleton=1", (new_epoch,))
            connection.commit()

    def bump(self) -> int:
        """Atomically advance and return the next epoch for decision fences."""
        with _connection(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute("SELECT epoch FROM policy_epoch WHERE singleton=1").fetchone()
            if current is None:
                connection.rollback()
                raise RequestAuthorizationError("policy_epoch_uninitialized")
            next_epoch = int(current["epoch"]) + 1
            connection.execute("UPDATE policy_epoch SET epoch=? WHERE singleton=1", (next_epoch,))
            connection.commit()
            return next_epoch


__all__ = [
    "SQLiteAuthenticationRegistry",
    "SQLitePolicyEpoch",
    "SQLiteRateLimiter",
    "SQLiteReplayGuard",
]
