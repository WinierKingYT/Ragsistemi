"""Pinned GC-C1 replay boundary.

The runner can execute only a caller-supplied synthetic case after a verified
preflight. It has no network, credential, production or ambient filesystem
access. In the current workspace the prerequisite is intentionally absent.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

from .canonical import is_sha256
from .clean_room import IsolationObservation, verify_attestation


RUNNER_ID = "pmiri-gc-c1-replay"
RUNNER_VERSION = "0.1.0"


@dataclass(frozen=True)
class ReplayResult:
    case_id: str
    status: str
    disposition: str
    reason: str
    output: Mapping[str, object] | None = None


def verify_identity(identity: Mapping[str, object]) -> None:
    if identity.get("runner_id") != RUNNER_ID or identity.get("runner_version") != RUNNER_VERSION:
        raise ValueError("runner_identity_mismatch")
    if identity.get("latest_alias_allowed") is not False or identity.get("self_upgrade_allowed") is not False:
        raise ValueError("runner_alias_or_upgrade_forbidden")


def run_case(
    *,
    case_id: str,
    identity: Mapping[str, object],
    isolation: Mapping[str, IsolationObservation] | None,
    fingerprints: Mapping[str, object],
    case: Callable[[], Mapping[str, object]],
) -> ReplayResult:
    try:
        verify_identity(identity)
        if isolation is None:
            return ReplayResult(case_id, "BLOCKED", "BLOCKED", "clean_room_attestation_absent")
        ready, status = verify_attestation(isolation)
        if not ready:
            return ReplayResult(case_id, status, status, "clean_room_attestation_not_ready")
        required = ("runner_source", "runner_manifest", "authority_bundle", "evidence_schema", "fixture_catalog", "preflight_matrix", "preflight_record_schema")
        if any(not is_sha256(fingerprints.get(name)) for name in required):
            return ReplayResult(case_id, "BLOCKED", "BLOCKED", "required_fingerprint_missing")
        output = dict(case())
        return ReplayResult(case_id, "RECORDED", str(output.get("disposition", "UNKNOWN")), "synthetic_case_completed", output)
    except Exception as exc:
        return ReplayResult(case_id, "VALIDATION_ERROR", "VALIDATION_ERROR", type(exc).__name__ + ":" + str(exc))
