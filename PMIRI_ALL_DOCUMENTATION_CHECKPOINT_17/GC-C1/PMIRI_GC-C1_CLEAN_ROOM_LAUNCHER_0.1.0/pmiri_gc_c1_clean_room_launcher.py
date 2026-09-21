"""Fail-closed clean-room handoff decision for PMIRI GC-C1.

This module does not create OS isolation. It accepts only externally observed
attestations and returns a preflight outcome. Missing evidence is BLOCKED.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

LAUNCHER_ID = "pmiri-gc-c1-clean-room-launcher"
LAUNCHER_VERSION = "0.1.0"
OUTCOMES = frozenset({"READY_FOR_REPLAY", "BLOCKED", "VALIDATION_ERROR", "ISOLATION_VIOLATION"})


@dataclass(frozen=True)
class Observations:
    network: str
    credentials: str
    filesystem: str
    connectors: str
    determinism: str
    resource_limits: str
    teardown: str


def _sha(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def decide_handoff(*, authorization: str, fingerprints: Mapping[str, object], observations: Observations) -> str:
    """Return only a preflight outcome; never an R-FC result."""
    if authorization != "AUTHORIZED_FOR_CONTROLLED_PREFLIGHT_ONLY":
        return "BLOCKED"
    required = ("runner_source", "runner_manifest", "authority_bundle", "evidence_schema", "fixture_catalog", "preflight_matrix", "profile")
    if any(not _sha(fingerprints.get(key)) for key in required):
        return "BLOCKED"
    expected = {
        "network": "DENIED", "credentials": "DENIED", "filesystem": "ALLOWLIST_VERIFIED",
        "connectors": "DENIED", "determinism": "VERIFIED", "resource_limits": "VERIFIED",
        "teardown": "AVAILABLE",
    }
    observed = observations.__dict__
    if any(observed[key] in {"FAILED", "UNVERIFIED"} for key in expected):
        return "ISOLATION_VIOLATION"
    if any(observed[key] != value for key, value in expected.items()):
        return "BLOCKED"
    return "READY_FOR_REPLAY"


__all__ = ["LAUNCHER_ID", "LAUNCHER_VERSION", "OUTCOMES", "Observations", "decide_handoff"]
