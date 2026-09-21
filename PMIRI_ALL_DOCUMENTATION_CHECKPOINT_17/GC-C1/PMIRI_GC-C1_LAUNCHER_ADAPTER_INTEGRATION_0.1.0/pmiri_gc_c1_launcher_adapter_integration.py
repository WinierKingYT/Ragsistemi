"""Pure integration boundary between isolation adapters and launcher."""
from __future__ import annotations

from typing import Mapping

OUTCOMES = {"READY_FOR_REPLAY", "BLOCKED", "VALIDATION_ERROR", "ISOLATION_VIOLATION"}
REQUIRED = {"network", "credentials", "filesystem", "connectors", "determinism", "resource_limits", "teardown", "privacy"}

def integrate(adapter_evidence: Mapping[str, Mapping[str, object]], launcher_decision):
    """Normalize adapter evidence, then pass only complete evidence to launcher_decision."""
    if set(adapter_evidence) != REQUIRED:
        return "BLOCKED"
    for domain, item in adapter_evidence.items():
        if item.get("result") not in {"VERIFIED", "DENIED"} or not item.get("evidence_ref"):
            return "ISOLATION_VIOLATION"
    outcome = launcher_decision(adapter_evidence)
    if outcome not in OUTCOMES:
        return "VALIDATION_ERROR"
    return outcome

__all__ = ["integrate", "OUTCOMES", "REQUIRED"]
