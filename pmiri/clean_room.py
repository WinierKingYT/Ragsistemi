"""GC-C1 isolation evidence boundary.

The module validates externally observed attestations. It does not pretend to
provide OS-level sandboxing; absent or unverified observations remain blocked.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


DOMAINS = (
    "network",
    "credentials",
    "filesystem",
    "connectors",
    "determinism",
    "resource_limits",
    "teardown",
    "privacy",
)
EXPECTED = {
    "network": "DENIED",
    "credentials": "DENIED",
    "filesystem": "ALLOWLIST_VERIFIED",
    "connectors": "DENIED",
    "determinism": "VERIFIED",
    "resource_limits": "VERIFIED",
    "teardown": "AVAILABLE",
    "privacy": "VERIFIED",
}


@dataclass(frozen=True)
class IsolationObservation:
    domain: str
    result: str
    evidence_ref: str
    observation: str


def normalize_observation(raw: Mapping[str, object]) -> IsolationObservation:
    domain, result = raw.get("domain"), raw.get("result")
    ref, observation = raw.get("evidence_ref"), raw.get("observation")
    if domain not in DOMAINS:
        raise ValueError("unknown_isolation_domain")
    if result not in {"VERIFIED", "DENIED", "ALLOWLIST_VERIFIED", "AVAILABLE", "UNVERIFIED", "FAILED"}:
        raise ValueError("invalid_isolation_result")
    if not isinstance(ref, str) or not ref or not isinstance(observation, str) or not observation:
        raise ValueError("isolation_evidence_missing")
    return IsolationObservation(domain, result, ref, observation)


def verify_attestation(evidence: Mapping[str, IsolationObservation]) -> tuple[bool, str]:
    if set(evidence) != set(DOMAINS):
        return False, "BLOCKED"
    for domain in DOMAINS:
        observation = evidence[domain]
        if observation.result in {"FAILED", "UNVERIFIED"}:
            return False, "ISOLATION_VIOLATION"
        if observation.result != EXPECTED[domain]:
            return False, "BLOCKED"
    return True, "READY_FOR_REPLAY"
