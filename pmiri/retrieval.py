"""Deterministic project-bounded lexical retrieval."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .canonical import sha256_json
from .models import Coverage, EvidenceItem, EvidenceSet, QueryRequest
from .store import LocalStore

TOKEN_RE = re.compile(r"[\w'-]+", re.UNICODE)


def tokens(value: str) -> tuple[str, ...]:
    return tuple(token.casefold() for token in TOKEN_RE.findall(value))


def _frontmatter(content: str) -> dict[str, str]:
    """Read a deliberately small YAML-like frontmatter subset as data only."""
    lines = content.split("\n")
    if not lines or lines[0].strip() != "---":
        return {}
    result: dict[str, str] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            break
        if ":" in line:
            key, value = line.split(":", 1)
            if key.strip() and value.strip():
                result[key.strip()] = value.strip().strip('"\'')
    return result


@dataclass(frozen=True)
class RetrievedSpan:
    start_line: int
    end_line: int
    text: str
    score: int


def matching_spans(content: str, query_tokens: tuple[str, ...]) -> tuple[RetrievedSpan, ...]:
    lines = content.splitlines()
    query = set(query_tokens)
    spans: list[RetrievedSpan] = []
    for number, line in enumerate(lines, start=1):
        line_tokens = set(tokens(line))
        score = len(query & line_tokens)
        if score:
            spans.append(RetrievedSpan(number, number, line.strip(), score))
    return tuple(spans)


class Retriever:
    def __init__(self, store: LocalStore):
        self.store = store

    def search(self, request: QueryRequest) -> EvidenceSet:
        request.normalized()
        query_tokens = tokens(request.query)
        if not query_tokens:
            raise ValueError("query_has_no_search_tokens")
        sources = self.store.list_sources(request.project_constraint)
        scored: list[EvidenceItem] = []
        for source in sources:
            meta = _frontmatter(source.content)
            conflict_group = meta.get("conflict_group")
            for span in matching_spans(source.content, query_tokens):
                anchor_payload = {
                    "version_id": source.version_id,
                    "start_line": span.start_line,
                    "end_line": span.end_line,
                    "text": span.text,
                }
                anchor_hash = sha256_json(anchor_payload)
                item_payload = {
                    "source_id": source.source_id,
                    "version_id": source.version_id,
                    "anchor": anchor_hash,
                    "text": span.text,
                }
                scored.append(
                    EvidenceItem(
                        evidence_ref="ev_" + sha256_json(item_payload)[:32],
                        source_id=source.source_id,
                        version_id=source.version_id,
                        project_id=source.project_id,
                        anchor="anchor_" + anchor_hash,
                        text=span.text,
                        fingerprint=sha256_json(item_payload),
                        score=span.score,
                        conflict_group=conflict_group,
                    )
                )
        scored.sort(key=lambda item: (-item.score, item.source_id, item.version_id, item.anchor))
        items = tuple(scored[: request.max_results])
        conflict_groups = tuple(sorted({item.conflict_group for item in items if item.conflict_group}))
        coverage = Coverage.COMPLETE if sources else Coverage.UNKNOWN
        lineage = "auth_" + sha256_json(
            {"project": request.project_constraint, "purpose": request.purpose, "request_id": request.request_id}
        )[:32]
        return EvidenceSet(
            request=request,
            items=items,
            coverage=coverage,
            authorization_lineage=lineage,
            conflict_groups=conflict_groups,
        )
