"""Typed S0 data structures and the stable JSON output contract."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

from .canonical import sha256_json


class Coverage(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class Disposition(StrEnum):
    SUPPORTED = "SUPPORTED"
    EMPTY = "EMPTY"
    PARTIAL = "UNKNOWN_OR_PARTIAL"
    DENIED = "DENIED"
    CONFLICT = "CONFLICT_PRESERVED"
    DEGRADED = "DEGRADED"
    SCHEMA_REJECTED = "SCHEMA_REJECTED"
    TYPE_REJECTED = "TYPE_REJECTED"
    NO_MUTATION = "NO_MUTATION"
    ALLOWED_WITHIN_ENVELOPE = "ALLOWED_WITHIN_ENVELOPE"


@dataclass(frozen=True)
class QueryRequest:
    request_id: str
    project_constraint: str
    query: str
    purpose: str = "local_read"
    max_results: int = 20

    def normalized(self) -> dict[str, Any]:
        if not self.request_id or not self.project_constraint or not self.query.strip():
            raise ValueError("request_requires_id_project_and_query")
        if self.max_results < 1 or self.max_results > 1000:
            raise ValueError("max_results_out_of_bounds")
        return asdict(self)


@dataclass(frozen=True)
class SourceRecord:
    source_id: str
    version_id: str
    project_id: str
    source_name: str
    content_fingerprint: str
    content: str
    capture_time: str
    metadata: dict[str, str] = field(default_factory=dict)

    def public_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "version_id": self.version_id,
            "project_id": self.project_id,
            "source_name": self.source_name,
            "content_fingerprint": self.content_fingerprint,
            "capture_time": self.capture_time,
            "metadata": dict(sorted(self.metadata.items())),
        }


@dataclass(frozen=True)
class EvidenceItem:
    evidence_ref: str
    source_id: str
    version_id: str
    project_id: str
    anchor: str
    text: str
    fingerprint: str
    score: int
    conflict_group: str | None = None

    def public_dict(self) -> dict[str, Any]:
        return {
            "evidence_ref": self.evidence_ref,
            "source_id": self.source_id,
            "version_id": self.version_id,
            "project_id": self.project_id,
            "anchor": self.anchor,
            "fingerprint": self.fingerprint,
            "score": self.score,
            **({"conflict_group": self.conflict_group} if self.conflict_group else {}),
        }


@dataclass(frozen=True)
class EvidenceSet:
    request: QueryRequest
    items: tuple[EvidenceItem, ...]
    coverage: Coverage
    authorization_lineage: str
    conflict_groups: tuple[str, ...] = ()

    @property
    def disposition(self) -> Disposition:
        if not self.items:
            return Disposition.EMPTY
        if self.conflict_groups:
            return Disposition.CONFLICT
        if self.coverage in {Coverage.PARTIAL, Coverage.UNKNOWN}:
            return Disposition.PARTIAL
        return Disposition.SUPPORTED

    def fingerprint(self) -> str:
        return sha256_json(
            {
                "request": self.request.normalized(),
                "items": [item.public_dict() for item in self.items],
                "coverage": self.coverage.value,
                "authorization_lineage": self.authorization_lineage,
            }
        )


@dataclass(frozen=True)
class ContextArtifact:
    artifact_kind: str
    bound: int
    text: str
    coverage: Coverage
    disposition: Disposition
    evidence_refs: tuple[str, ...]
    citation_refs: tuple[str, ...]
    authorization_lineage: str
    omission_ledger: tuple[dict[str, str], ...] = ()

    @property
    def fingerprint(self) -> str:
        return sha256_json(self.public_dict())

    def public_dict(self) -> dict[str, Any]:
        return {
            "artifact_kind": self.artifact_kind,
            "bound": self.bound,
            "text": self.text,
            "coverage": self.coverage.value,
            "disposition": self.disposition.value,
            "evidence_refs": list(self.evidence_refs),
            "citation_refs": list(self.citation_refs),
            "authorization_lineage": self.authorization_lineage,
            "omission_ledger": list(self.omission_ledger),
        }


@dataclass(frozen=True)
class QueryResult:
    request: QueryRequest
    disposition: Disposition
    coverage: Coverage
    evidence: tuple[EvidenceItem, ...]
    authorization_lineage: str
    context: ContextArtifact

    def structured(self) -> dict[str, Any]:
        return {
            "request": self.request.normalized(),
            "result": {
                "disposition": self.disposition.value,
                "coverage": self.coverage.value,
            },
            "evidence": [item.public_dict() for item in self.evidence],
            "lineage": {
                "authorization_ref": self.authorization_lineage,
                "evidence_refs": [item.evidence_ref for item in self.evidence],
            },
            "context": {
                **self.context.public_dict(),
                "fingerprint": self.context.fingerprint,
            },
        }

    def render(self) -> str:
        """Human output is derived exclusively from the typed result."""
        lines = [
            f"Disposition: {self.disposition.value}",
            f"Coverage: {self.coverage.value}",
            f"Project: {self.request.project_constraint}",
        ]
        if self.context.text:
            lines += ["", self.context.text]
        if self.context.citation_refs:
            lines += ["", "Citations: " + ", ".join(self.context.citation_refs)]
        return "\n".join(lines)
