"""Leak-safe caller projections for read-only results.

The projection deliberately makes an unauthorized read indistinguishable from
an authorized query with no disclosed evidence.  Source existence, counts,
conflict groups and internal denial reasons never cross this boundary.
"""

from __future__ import annotations

from typing import Any, Mapping

from .canonical import sha256_json
from .models import QueryResult


DISCLOSURE_VERSION = "0.1"


def _empty_projection(result: QueryResult) -> dict[str, Any]:
    request = result.request.normalized()
    lineage = "auth_" + sha256_json({"project": request["project_constraint"], "purpose": request["purpose"], "request_id": request["request_id"]})[:32]
    context = {
        "artifact_kind": "CompiledContextArtifact",
        "bound": result.context.bound,
        "text": "",
        "coverage": "unknown",
        "disposition": "EMPTY",
        "evidence_refs": [],
        "citation_refs": [],
        "authorization_lineage": lineage,
        "omission_ledger": [],
    }
    context["fingerprint"] = sha256_json(context)
    return {
        "disclosure_version": DISCLOSURE_VERSION,
        "request": {"request_id": request["request_id"], "project_constraint": request["project_constraint"], "purpose": request["purpose"]},
        "result": {"disposition": "EMPTY", "coverage": "unknown"},
        "evidence": [],
        "lineage": {"authorization_ref": lineage, "evidence_refs": []},
        "context": context,
    }


def project_query_result(result: QueryResult, *, authorized: bool) -> dict[str, Any]:
    """Return a stable caller projection without leaking inaccessible state."""
    if not authorized or not result.evidence:
        return _empty_projection(result)
    structured = result.structured()
    return {
        "disclosure_version": DISCLOSURE_VERSION,
        "request": {
            "request_id": structured["request"]["request_id"],
            "project_constraint": structured["request"]["project_constraint"],
            "purpose": structured["request"]["purpose"],
        },
        "result": structured["result"],
        "evidence": structured["evidence"],
        "lineage": structured["lineage"],
        "context": structured["context"],
    }


def disclosure_fingerprint(projection: Mapping[str, Any]) -> str:
    return sha256_json(dict(projection))


__all__ = ["DISCLOSURE_VERSION", "disclosure_fingerprint", "project_query_result"]
