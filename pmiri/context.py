"""Bounded context compilation with citation and conflict preservation."""

from __future__ import annotations

from .models import ContextArtifact, Coverage, Disposition, EvidenceSet


class ContextCompiler:
    def __init__(self, max_chars: int = 4000):
        if max_chars < 128:
            raise ValueError("context_bound_too_small")
        self.max_chars = max_chars

    def compile(self, evidence: EvidenceSet) -> ContextArtifact:
        selected = []
        used = 0
        omitted: list[dict[str, str]] = []
        groups = {group: [item for item in evidence.items if item.conflict_group == group] for group in evidence.conflict_groups}
        handled_groups: set[str] = set()

        for item in evidence.items:
            if item.conflict_group and item.conflict_group in handled_groups:
                continue
            group_items = groups.get(item.conflict_group, [item]) if item.conflict_group else [item]
            block = "\n".join(f"[{entry.evidence_ref} | {entry.anchor}] {entry.text}" for entry in group_items)
            if used + len(block) + (1 if selected else 0) <= self.max_chars:
                selected.extend(group_items)
                used += len(block) + (1 if selected else 0)
            else:
                if item.conflict_group:
                    omitted.append({"reason": "CONFLICT_GROUP_EXCEEDS_CONTEXT_BOUND", "reference": item.conflict_group})
                else:
                    omitted.append({"reason": "CONTEXT_BOUND", "reference": item.evidence_ref})
            if item.conflict_group:
                handled_groups.add(item.conflict_group)

        blocks = [f"[{item.evidence_ref} | {item.anchor}] {item.text}" for item in selected]
        text = "\n".join(blocks)
        disposition = evidence.disposition
        if omitted and disposition != Disposition.EMPTY:
            disposition = Disposition.DEGRADED
        if evidence.disposition == Disposition.EMPTY:
            disposition = Disposition.EMPTY
        return ContextArtifact(
            artifact_kind="CompiledContextArtifact",
            bound=self.max_chars,
            text=text,
            coverage=evidence.coverage,
            disposition=disposition,
            evidence_refs=tuple(item.evidence_ref for item in selected),
            citation_refs=tuple(item.anchor for item in selected),
            authorization_lineage=evidence.authorization_lineage,
            omission_ledger=tuple(omitted),
        )
