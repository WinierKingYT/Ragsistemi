"""Normalize explicit isolation evidence for the fail-closed launcher."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

DOMAINS = ("network", "credentials", "filesystem", "connectors", "determinism", "resource_limits", "teardown", "privacy")

@dataclass(frozen=True)
class Evidence:
    domain: str
    result: str
    evidence_ref: str
    observation: str

def normalize(raw: Mapping[str, object]) -> Evidence:
    domain, result, ref, observation = (raw.get(k) for k in ("domain", "result", "evidence_ref", "observation"))
    if domain not in DOMAINS:
        raise ValueError("unknown_evidence_domain")
    if result not in {"VERIFIED", "DENIED", "UNVERIFIED", "FAILED"}:
        raise ValueError("invalid_evidence_result")
    if result in {"UNVERIFIED", "FAILED"}:
        raise ValueError("unverified_evidence_rejected")
    if not all(isinstance(x, str) and x for x in (ref, observation)):
        raise ValueError("evidence_reference_or_observation_missing")
    return Evidence(domain, result, ref, observation)

def require_complete(evidence: Mapping[str, Evidence]) -> None:
    missing = set(DOMAINS) - set(evidence)
    if missing:
        raise ValueError("missing_evidence:" + ",".join(sorted(missing)))
    for domain in DOMAINS:
        if evidence[domain].result not in {"VERIFIED", "DENIED"}:
            raise ValueError("domain_not_positive:" + domain)

__all__ = ["DOMAINS", "Evidence", "normalize", "require_complete"]
