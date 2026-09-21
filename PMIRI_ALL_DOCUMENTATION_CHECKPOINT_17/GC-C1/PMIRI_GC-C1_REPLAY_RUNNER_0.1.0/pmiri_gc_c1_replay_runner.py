"""PMIRI GC-C1 replay runner core, pinned at 0.1.0.

This module is deliberately side-effect free. It does not access the network,
credentials, repository, home directory, connectors or production data. A
future isolated launcher must supply verified attestations and declared input
objects before calling these functions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

RUNNER_ID = "pmiri-gc-c1-replay"
RUNNER_VERSION = "0.1.0"
LATEST_ALIAS_ALLOWED = False
SELF_UPGRADE_ALLOWED = False

ALLOWED_OVERALL_RESULTS = frozenset(
    {"READY_FOR_REPLAY", "BLOCKED", "VALIDATION_ERROR", "ISOLATION_VIOLATION"}
)


class RunnerContractError(ValueError):
    """Raised when a supplied declaration violates the pinned contract."""


@dataclass(frozen=True)
class IsolationAttestation:
    network: str
    credentials: str
    filesystem: str
    determinism: str
    resource_limits: str
    teardown: str


def verify_runner_identity(declaration: Mapping[str, object]) -> None:
    """Fail closed unless the exact pinned runner identity is supplied."""
    if declaration.get("runner_id") != RUNNER_ID:
        raise RunnerContractError("runner_id_mismatch")
    if declaration.get("runner_version") != RUNNER_VERSION:
        raise RunnerContractError("runner_version_mismatch")
    if declaration.get("latest_alias_allowed") is not False:
        raise RunnerContractError("latest_alias_forbidden")
    if declaration.get("self_upgrade_allowed") is not False:
        raise RunnerContractError("self_upgrade_forbidden")


def verify_clean_room(attestation: IsolationAttestation) -> None:
    """Require every isolation dimension to be positively attested."""
    required = {
        "network": "DENIED",
        "credentials": "DENIED",
        "filesystem": "ALLOWLIST_VERIFIED",
        "determinism": "VERIFIED",
        "resource_limits": "VERIFIED",
        "teardown": "AVAILABLE",
    }
    observed = {
        "network": attestation.network,
        "credentials": attestation.credentials,
        "filesystem": attestation.filesystem,
        "determinism": attestation.determinism,
        "resource_limits": attestation.resource_limits,
        "teardown": attestation.teardown,
    }
    for name, expected in required.items():
        if observed[name] != expected:
            raise RunnerContractError(f"isolation_unverified:{name}")


def validate_fingerprints(fingerprints: Mapping[str, object], required: Iterable[str]) -> None:
    """Require lowercase SHA-256 strings for every declared input."""
    for name in required:
        value = fingerprints.get(name)
        if not isinstance(value, str) or len(value) != 64:
            raise RunnerContractError(f"fingerprint_missing_or_malformed:{name}")
        if any(ch not in "0123456789abcdef" for ch in value):
            raise RunnerContractError(f"fingerprint_not_lowercase_sha256:{name}")


def decide_preflight(
    *,
    identity: Mapping[str, object],
    isolation: IsolationAttestation,
    fingerprints: Mapping[str, object],
) -> str:
    """Return readiness only; this function can never return an R-FC result."""
    try:
        verify_runner_identity(identity)
        verify_clean_room(isolation)
        validate_fingerprints(
            fingerprints,
            (
                "runner_source",
                "runner_manifest",
                "authority_bundle",
                "evidence_schema",
                "fixture_catalog",
                "preflight_matrix",
                "preflight_record_schema",
            ),
        )
    except RunnerContractError:
        return "BLOCKED"
    return "READY_FOR_REPLAY"


def assert_allowed_overall_result(value: str) -> None:
    if value not in ALLOWED_OVERALL_RESULTS:
        raise RunnerContractError("invalid_overall_result")


__all__ = [
    "ALLOWED_OVERALL_RESULTS",
    "IsolationAttestation",
    "LATEST_ALIAS_ALLOWED",
    "RUNNER_ID",
    "RUNNER_VERSION",
    "SELF_UPGRADE_ALLOWED",
    "RunnerContractError",
    "assert_allowed_overall_result",
    "decide_preflight",
    "validate_fingerprints",
    "verify_clean_room",
    "verify_runner_identity",
]
