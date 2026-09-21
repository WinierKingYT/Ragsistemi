"""Trusted-boundary authentication and request authorization.

This module is intentionally an adapter boundary, not an identity provider.
An upstream API gateway, MCP host or local trusted process must first verify
authentication and register the resulting immutable principal.  The read
surface then accepts only the registered authentication reference; all
principal, trust-zone, purpose, scope and policy fields are server-derived.

The service is fail-closed and keeps denial reasons internal.  Callers receive
only an allow/deny evaluation which can be passed to the disclosure projection.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Lock
from time import time
from typing import Any, Callable, Iterable

from .canonical import sha256_json, utc_now
from .models import QueryRequest
from .security import AuthorizationSubjectChain, PurposeBinding


READ_OPERATION = "read"
ACTIVE = "ACTIVE"
AUTHORIZATION_ALLOW = "ALLOW"
AUTHORIZATION_DENY = "DENY"


class RequestAuthorizationError(ValueError):
    """Internal boundary error; never serialize this message to a caller."""


def _parse_time(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timestamp_must_be_timezone_aware")
    return parsed.astimezone(timezone.utc)


def _valid_interval(valid_from: str, valid_until: str, now: str) -> bool:
    try:
        return _parse_time(valid_from) <= _parse_time(now) <= _parse_time(valid_until)
    except (TypeError, ValueError):
        return False


def _epoch_seconds(value: str) -> float:
    return _parse_time(value).timestamp()


@dataclass(frozen=True)
class TrustZoneAttestation:
    """Evidence that a trusted boundary assigned a principal to a zone."""

    attestation_id: str
    principal_ref: str
    zone_id: str
    issuer_ref: str
    evidence_refs: tuple[str, ...]
    issued_at: str
    valid_until: str
    status: str
    fingerprint: str

    @classmethod
    def issue(
        cls,
        *,
        principal_ref: str,
        zone_id: str,
        issuer_ref: str,
        evidence_refs: Iterable[str],
        issued_at: str,
        valid_until: str,
        status: str = ACTIVE,
    ) -> "TrustZoneAttestation":
        refs = tuple(sorted(set(evidence_refs)))
        if not all(isinstance(value, str) and value for value in (principal_ref, zone_id, issuer_ref, issued_at, valid_until)):
            raise RequestAuthorizationError("trust_zone_attestation_missing")
        if not refs or status != ACTIVE or not _valid_interval(issued_at, valid_until, issued_at):
            raise RequestAuthorizationError("trust_zone_attestation_invalid")
        payload = {
            "principal_ref": principal_ref,
            "zone_id": zone_id,
            "issuer_ref": issuer_ref,
            "evidence_refs": list(refs),
            "issued_at": issued_at,
            "valid_until": valid_until,
            "status": status,
        }
        fingerprint = sha256_json(payload)
        return cls(
            attestation_id="trust-attestation://" + fingerprint[:32],
            principal_ref=principal_ref,
            zone_id=zone_id,
            issuer_ref=issuer_ref,
            evidence_refs=refs,
            issued_at=issued_at,
            valid_until=valid_until,
            status=status,
            fingerprint=fingerprint,
        )

    def is_valid(self, *, principal_ref: str, now: str) -> bool:
        return (
            self.status == ACTIVE
            and self.principal_ref == principal_ref
            and _valid_interval(self.issued_at, self.valid_until, now)
        )


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    """Immutable result of upstream authentication plus trusted policy lookup."""

    authentication_ref: str
    principal_ref: str
    principal_type: str
    service_principal_ref: str
    workload_principal_ref: str | None
    human_principal_ref: str | None
    trust_zone_attestation: TrustZoneAttestation
    allowed_projects: tuple[str, ...]
    allowed_operations: tuple[str, ...]
    allowed_purposes: tuple[str, ...]
    delegation_grant_refs: tuple[str, ...]
    policy_bundle_ref: str
    policy_version: str
    policy_epoch: int
    issued_at: str
    valid_until: str
    status: str
    fingerprint: str

    @classmethod
    def verified(
        cls,
        *,
        authentication_ref: str,
        principal_ref: str,
        principal_type: str,
        service_principal_ref: str,
        trust_zone_attestation: TrustZoneAttestation,
        allowed_projects: Iterable[str],
        allowed_operations: Iterable[str] = (READ_OPERATION,),
        allowed_purposes: Iterable[str] = ("local_read",),
        policy_bundle_ref: str,
        policy_version: str,
        policy_epoch: int,
        issued_at: str,
        valid_until: str,
        workload_principal_ref: str | None = None,
        human_principal_ref: str | None = None,
        delegation_grant_refs: Iterable[str] = (),
        status: str = ACTIVE,
    ) -> "AuthenticatedPrincipal":
        projects = tuple(sorted(set(allowed_projects)))
        operations = tuple(sorted(set(allowed_operations)))
        purposes = tuple(sorted(set(allowed_purposes)))
        grants = tuple(sorted(set(delegation_grant_refs)))
        required = (authentication_ref, principal_ref, principal_type, service_principal_ref, policy_bundle_ref, policy_version, issued_at, valid_until)
        if not all(isinstance(value, str) and value for value in required):
            raise RequestAuthorizationError("principal_required_field_missing")
        if not projects or not operations or not purposes or not all(projects + operations + purposes):
            raise RequestAuthorizationError("principal_authority_empty")
        if policy_epoch < 0 or status != ACTIVE:
            raise RequestAuthorizationError("principal_state_invalid")
        if trust_zone_attestation.principal_ref != principal_ref:
            raise RequestAuthorizationError("trust_zone_principal_mismatch")
        if not _valid_interval(issued_at, valid_until, issued_at):
            raise RequestAuthorizationError("principal_validity_invalid")
        payload = {
            "authentication_ref": authentication_ref,
            "principal_ref": principal_ref,
            "principal_type": principal_type,
            "service_principal_ref": service_principal_ref,
            "workload_principal_ref": workload_principal_ref,
            "human_principal_ref": human_principal_ref,
            "trust_zone_attestation_fingerprint": trust_zone_attestation.fingerprint,
            "allowed_projects": list(projects),
            "allowed_operations": list(operations),
            "allowed_purposes": list(purposes),
            "delegation_grant_refs": list(grants),
            "policy_bundle_ref": policy_bundle_ref,
            "policy_version": policy_version,
            "policy_epoch": policy_epoch,
            "issued_at": issued_at,
            "valid_until": valid_until,
            "status": status,
        }
        return cls(
            authentication_ref=authentication_ref,
            principal_ref=principal_ref,
            principal_type=principal_type,
            service_principal_ref=service_principal_ref,
            workload_principal_ref=workload_principal_ref,
            human_principal_ref=human_principal_ref,
            trust_zone_attestation=trust_zone_attestation,
            allowed_projects=projects,
            allowed_operations=operations,
            allowed_purposes=purposes,
            delegation_grant_refs=grants,
            policy_bundle_ref=policy_bundle_ref,
            policy_version=policy_version,
            policy_epoch=policy_epoch,
            issued_at=issued_at,
            valid_until=valid_until,
            status=status,
            fingerprint=sha256_json(payload),
        )

    @property
    def trust_zone(self) -> str:
        return self.trust_zone_attestation.zone_id

    def is_valid(self, *, now: str, current_policy_epoch: int) -> bool:
        return (
            self.status == ACTIVE
            and self.policy_epoch == current_policy_epoch
            and _valid_interval(self.issued_at, self.valid_until, now)
            and self.trust_zone_attestation.is_valid(principal_ref=self.principal_ref, now=now)
        )


class AuthenticationRegistry:
    """Server-side authentication-to-principal registry.

    Registration is deliberately explicit.  A client-supplied authorization
    reference cannot create or alter a principal; only a trusted adapter or
    deployment bootstrap should populate this registry.
    """

    def __init__(self) -> None:
        self._principals: dict[str, AuthenticatedPrincipal] = {}
        self._lock = Lock()

    def register(self, principal: AuthenticatedPrincipal) -> None:
        with self._lock:
            existing = self._principals.get(principal.authentication_ref)
            if existing is not None and existing.fingerprint != principal.fingerprint:
                raise RequestAuthorizationError("authentication_reference_rebound")
            self._principals[principal.authentication_ref] = principal

    def resolve(self, authentication_ref: str | None) -> AuthenticatedPrincipal | None:
        if not isinstance(authentication_ref, str) or not authentication_ref:
            return None
        with self._lock:
            return self._principals.get(authentication_ref)


class ReplayGuard:
    """Bounded, request-id replay guard for one process boundary."""

    def __init__(self, *, max_entries: int = 100_000) -> None:
        if max_entries < 1:
            raise ValueError("replay_guard_capacity_invalid")
        self.max_entries = max_entries
        self._seen: dict[str, tuple[str, float]] = {}
        self._order: deque[str] = deque()
        self._lock = Lock()

    def consume(self, *, request_id: str, fingerprint: str, expires_at: str, now: str) -> bool:
        now_epoch = _epoch_seconds(now)
        expiry = _epoch_seconds(expires_at)
        with self._lock:
            while self._order and self._seen.get(self._order[0], ("", 0.0))[1] <= now_epoch:
                old = self._order.popleft()
                self._seen.pop(old, None)
            if request_id in self._seen:
                return False
            if len(self._seen) >= self.max_entries:
                old = self._order.popleft()
                self._seen.pop(old, None)
            self._seen[request_id] = (fingerprint, expiry)
            self._order.append(request_id)
            return True


class FixedWindowRateLimiter:
    """Atomic per-principal/operation limiter; changing project does not reset it."""

    def __init__(self, *, max_requests: int = 60, window_seconds: int = 60) -> None:
        if max_requests < 1 or window_seconds < 1:
            raise ValueError("rate_limit_policy_invalid")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._windows: dict[str, tuple[float, int]] = {}
        self._lock = Lock()

    def consume(self, *, key: str, now: float | None = None) -> bool:
        current = time() if now is None else now
        with self._lock:
            start, count = self._windows.get(key, (current, 0))
            if current - start >= self.window_seconds:
                start, count = current, 0
            if count >= self.max_requests:
                self._windows[key] = (start, count)
                return False
            self._windows[key] = (start, count + 1)
            return True


@dataclass(frozen=True)
class RequestAuthorizationBinding:
    """Complete server-derived authorization validity tuple for one request."""

    binding_id: str
    request_id: str
    request_fingerprint: str
    authentication_ref: str
    principal_ref: str
    subject_chain_fingerprint: str
    trust_zone_attestation_fingerprint: str
    trust_zone: str
    purpose_binding_fingerprint: str
    operation: str
    purpose: str
    project_constraint: str
    policy_bundle_ref: str
    policy_version: str
    policy_epoch: int
    issued_at: str
    valid_until: str
    fingerprint: str

    def public_lineage(self) -> dict[str, str]:
        """Caller-safe lineage; identity and trust-zone details stay internal."""
        return {
            "authorization_ref": "auth_" + sha256_json({"request_fingerprint": self.request_fingerprint, "scope": "server-derived-local-read"})[:32],
            "request_fingerprint": self.request_fingerprint,
            "scope": self.project_constraint,
        }

    def is_valid(self, *, now: str, current_policy_epoch: int) -> bool:
        return self.policy_epoch == current_policy_epoch and _valid_interval(self.issued_at, self.valid_until, now)

    def integrity_valid(self, request: QueryRequest) -> bool:
        """Verify that this binding is the service-derived binding for *request*."""
        try:
            normalized = request.normalized()
        except (TypeError, ValueError):
            return False
        if self.request_id != request.request_id or self.request_fingerprint != sha256_json(normalized):
            return False
        payload = {
            "request": normalized,
            "authentication_ref": self.authentication_ref,
            "principal_ref": self.principal_ref,
            "subject_chain_fingerprint": self.subject_chain_fingerprint,
            "trust_zone_attestation_fingerprint": self.trust_zone_attestation_fingerprint,
            "trust_zone": self.trust_zone,
            "purpose_binding_fingerprint": self.purpose_binding_fingerprint,
            "operation": self.operation,
            "project_constraint": self.project_constraint,
            "policy_bundle_ref": self.policy_bundle_ref,
            "policy_version": self.policy_version,
            "policy_epoch": self.policy_epoch,
            "issued_at": self.issued_at,
            "valid_until": self.valid_until,
        }
        return self.fingerprint == sha256_json(payload)


@dataclass(frozen=True)
class AuthorizationEvaluation:
    result: str
    reason: str
    binding: RequestAuthorizationBinding | None = None

    @property
    def allowed(self) -> bool:
        return self.result == AUTHORIZATION_ALLOW


class RequestAuthorizationService:
    """Single authorization service shared by API and MCP adapters."""

    def __init__(
        self,
        registry: AuthenticationRegistry,
        *,
        current_policy_epoch: int = 0,
        rate_limiter: FixedWindowRateLimiter | None = None,
        replay_guard: ReplayGuard | None = None,
        operation: str = READ_OPERATION,
        clock: Callable[[], float] | None = None,
        policy_epoch_store: Any | None = None,
    ) -> None:
        if current_policy_epoch < 0:
            raise ValueError("policy_epoch_invalid")
        self.registry = registry
        self.current_policy_epoch = current_policy_epoch
        self.rate_limiter = rate_limiter or FixedWindowRateLimiter()
        self.replay_guard = replay_guard or ReplayGuard()
        self.operation = operation
        self.clock = clock or time
        self.policy_epoch_store = policy_epoch_store
        self._policy_lock = Lock()

    def advance_policy_epoch(self, new_epoch: int) -> None:
        if self.policy_epoch_store is not None:
            self.policy_epoch_store.advance(new_epoch)
            with self._policy_lock:
                self.current_policy_epoch = new_epoch
            return
        with self._policy_lock:
            if new_epoch < self.current_policy_epoch:
                raise ValueError("policy_epoch_cannot_move_backwards")
            self.current_policy_epoch = new_epoch

    def _current_policy_epoch(self) -> int:
        if self.policy_epoch_store is not None:
            return int(self.policy_epoch_store.get())
        with self._policy_lock:
            return self.current_policy_epoch

    def _build_binding(
        self,
        request: QueryRequest,
        principal: AuthenticatedPrincipal,
        *,
        issued_at: str,
    ) -> RequestAuthorizationBinding:
        normalized = request.normalized()
        purpose = PurposeBinding.create(
            operation_ref=f"pmiri://operation/{self.operation}",
            recognized_purpose=request.purpose,
            derivation_ref=principal.policy_bundle_ref,
        )
        purpose.verify_requested_purpose(request.purpose)
        subject = AuthorizationSubjectChain.derive(
            service_principal_ref=principal.service_principal_ref,
            originating_trust_zone_attestation_ref=principal.trust_zone_attestation.attestation_id,
            operation_ref=f"pmiri://operation/{self.operation}",
            purpose_binding_ref=purpose.purpose_binding_id,
            scopes=(
                {
                    "project": principal.allowed_projects,
                    "operation": principal.allowed_operations,
                    "purpose": principal.allowed_purposes,
                },
                {
                    "project": (request.project_constraint,),
                    "operation": (self.operation,),
                    "purpose": (request.purpose,),
                },
            ),
            human_principal_ref=principal.human_principal_ref,
            workload_principal_ref=principal.workload_principal_ref,
            delegation_grant_refs=principal.delegation_grant_refs,
        )
        binding_payload = {
            "request": normalized,
            "authentication_ref": principal.authentication_ref,
            "principal_ref": principal.principal_ref,
            "subject_chain_fingerprint": subject.fingerprint,
            "trust_zone_attestation_fingerprint": principal.trust_zone_attestation.fingerprint,
            "trust_zone": principal.trust_zone,
            "purpose_binding_fingerprint": purpose.fingerprint,
            "operation": self.operation,
            "project_constraint": request.project_constraint,
            "policy_bundle_ref": principal.policy_bundle_ref,
            "policy_version": principal.policy_version,
            "policy_epoch": principal.policy_epoch,
            "issued_at": issued_at,
            "valid_until": principal.valid_until,
        }
        fingerprint = sha256_json(binding_payload)
        return RequestAuthorizationBinding(
            binding_id="request-auth://" + fingerprint[:32],
            request_id=request.request_id,
            request_fingerprint=sha256_json(normalized),
            authentication_ref=principal.authentication_ref,
            principal_ref=principal.principal_ref,
            subject_chain_fingerprint=subject.fingerprint,
            trust_zone_attestation_fingerprint=principal.trust_zone_attestation.fingerprint,
            trust_zone=principal.trust_zone,
            purpose_binding_fingerprint=purpose.fingerprint,
            operation=self.operation,
            purpose=request.purpose,
            project_constraint=request.project_constraint,
            policy_bundle_ref=principal.policy_bundle_ref,
            policy_version=principal.policy_version,
            policy_epoch=principal.policy_epoch,
            issued_at=issued_at,
            valid_until=principal.valid_until,
            fingerprint=fingerprint,
        )

    def evaluate(
        self,
        request: QueryRequest,
        *,
        authentication_ref: str | None,
        now: str | None = None,
    ) -> AuthorizationEvaluation:
        try:
            normalized = request.normalized()
            current = now or utc_now()
            principal = self.registry.resolve(authentication_ref)
            if principal is None:
                return AuthorizationEvaluation(AUTHORIZATION_DENY, "AUTHENTICATION_UNKNOWN")
            current_epoch = self._current_policy_epoch()
            if not principal.is_valid(now=current, current_policy_epoch=current_epoch):
                return AuthorizationEvaluation(AUTHORIZATION_DENY, "AUTHORITY_STALE_OR_INVALID")
            if request.project_constraint not in principal.allowed_projects:
                return AuthorizationEvaluation(AUTHORIZATION_DENY, "SCOPE_MISMATCH")
            if self.operation not in principal.allowed_operations:
                return AuthorizationEvaluation(AUTHORIZATION_DENY, "OPERATION_NOT_ALLOWED")
            if request.purpose not in principal.allowed_purposes:
                return AuthorizationEvaluation(AUTHORIZATION_DENY, "PURPOSE_NOT_ALLOWED")
            if not self.rate_limiter.consume(
                key=f"{principal.principal_ref}:{self.operation}",
                now=self.clock(),
            ):
                return AuthorizationEvaluation(AUTHORIZATION_DENY, "RATE_LIMITED")

            binding = self._build_binding(request, principal, issued_at=current)
            if not self.replay_guard.consume(
                request_id=request.request_id,
                fingerprint=binding.fingerprint,
                expires_at=binding.valid_until,
                now=current,
            ):
                return AuthorizationEvaluation(AUTHORIZATION_DENY, "REQUEST_REPLAY")
            return AuthorizationEvaluation(AUTHORIZATION_ALLOW, "NONE", binding)
        except (RequestAuthorizationError, TypeError, ValueError, KeyError):
            return AuthorizationEvaluation(AUTHORIZATION_DENY, "AUTHORIZATION_INVALID")

    def revalidate(
        self,
        request: QueryRequest,
        binding: RequestAuthorizationBinding,
        *,
        now: str | None = None,
    ) -> bool:
        """Re-check the complete request binding immediately before disclosure."""
        try:
            current = now or utc_now()
            normalized = request.normalized()
            current_epoch = self._current_policy_epoch()
            principal = self.registry.resolve(binding.authentication_ref)
            if principal is None or not principal.is_valid(now=current, current_policy_epoch=current_epoch):
                return False
            if binding.policy_epoch != current_epoch:
                return False
            if binding.request_fingerprint != sha256_json(normalized):
                return False
            if binding.principal_ref != principal.principal_ref:
                return False
            if request.project_constraint not in principal.allowed_projects:
                return False
            if request.purpose not in principal.allowed_purposes or self.operation not in principal.allowed_operations:
                return False
            candidate = self._build_binding(request, principal, issued_at=binding.issued_at)
            return candidate == binding and binding.is_valid(now=current, current_policy_epoch=current_epoch)
        except (RequestAuthorizationError, TypeError, ValueError, KeyError):
            return False


__all__ = [
    "ACTIVE",
    "AUTHORIZATION_ALLOW",
    "AUTHORIZATION_DENY",
    "AuthenticatedPrincipal",
    "AuthenticationRegistry",
    "AuthorizationEvaluation",
    "FixedWindowRateLimiter",
    "READ_OPERATION",
    "ReplayGuard",
    "RequestAuthorizationBinding",
    "RequestAuthorizationError",
    "RequestAuthorizationService",
    "TrustZoneAttestation",
]
