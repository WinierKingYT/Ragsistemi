"""Gate-C provider-neutral handoff and final local emission fence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .canonical import sha256_json
from .models import ContextArtifact, Disposition


@dataclass(frozen=True)
class ProviderEnvelope:
    artifact_kind: str
    material: str
    citation_refs: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    authorization_lineage: str
    context_fingerprint: str
    action_result: str
    destination: str

    def structured(self) -> dict[str, Any]:
        return {
            "artifact_kind": self.artifact_kind,
            "material": self.material,
            "citation_refs": list(self.citation_refs),
            "evidence_refs": list(self.evidence_refs),
            "authorization_lineage": self.authorization_lineage,
            "context_fingerprint": self.context_fingerprint,
            "action_result": self.action_result,
            "destination": self.destination,
        }

    @property
    def fingerprint(self) -> str:
        return sha256_json(self.structured())


def compile_provider_neutral(context: ContextArtifact, *, destination: str = "LOCAL_ONLY") -> ProviderEnvelope:
    """Compile only the admitted context; never retrieve or resurrect omitted data."""
    if destination != "LOCAL_ONLY":
        raise PermissionError("external_destination_not_authorized_in_s0")
    if context.disposition == Disposition.EMPTY:
        action = "DENY"
    elif context.disposition in {Disposition.DEGRADED, Disposition.CONFLICT, Disposition.PARTIAL}:
        action = "REQUIRE_REVIEW"
    else:
        action = "LOCAL_ONLY"
    return ProviderEnvelope(
        artifact_kind="ProviderNeutralContextArtifact",
        material=context.text,
        citation_refs=context.citation_refs,
        evidence_refs=context.evidence_refs,
        authorization_lineage=context.authorization_lineage,
        context_fingerprint=context.fingerprint,
        action_result=action,
        destination=destination,
    )


class ExternalEmissionFence:
    """Final fence for any caller attempting to leave the local boundary."""

    def emit(self, envelope: ProviderEnvelope, *, current_context_fingerprint: str, destination: str) -> None:
        if destination != envelope.destination or destination != "LOCAL_ONLY":
            raise PermissionError("external_emission_denied")
        if envelope.context_fingerprint != current_context_fingerprint:
            raise PermissionError("context_revalidation_required")
        if envelope.action_result not in {"LOCAL_ONLY"}:
            raise PermissionError("typed_result_does_not_authorize_emission")

