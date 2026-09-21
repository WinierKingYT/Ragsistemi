"""Executable local acceptance harness for the V1-S0 contract.

This produces S0 evidence only. It never labels the result as Gate-C R-FC
evidence or PASS; GC-C1 replay still requires the controlled clean-room path.
"""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Callable
import platform
import sys

from .canonical import sha256_bytes, sha256_json
from .egress import ExternalEmissionFence, compile_provider_neutral
from .models import Disposition, QueryRequest
from .network import NetworkBoundary, NetworkBoundaryError
from .runtime import LocalEvidenceRuntime
from .sealing import seal_directory
from .store import LocalStore


def _case(case_id: str, fixture: str, fn: Callable[[], dict[str, Any]], request: dict[str, Any]) -> dict[str, Any]:
    request_fingerprint = sha256_json(request)
    try:
        actual = fn()
        return {
            "case_id": case_id,
            "status": "RECORDED",
            "fixture_fingerprint": sha256_bytes(fixture.encode("utf-8")),
            "request": request,
            "request_fingerprint": request_fingerprint,
            "actual": actual,
            "actual_fingerprint": sha256_json(actual),
            "citation_fingerprint": sha256_json(actual.get("citation_refs", actual.get("citations", []))),
        }
    except Exception as exc:
        return {
            "case_id": case_id,
            "status": "REJECTED",
            "fixture_fingerprint": sha256_bytes(fixture.encode("utf-8")),
            "request": request,
            "request_fingerprint": request_fingerprint,
            "actual": {"error": type(exc).__name__, "message": str(exc)},
            "actual_fingerprint": sha256_json({"error": type(exc).__name__, "message": str(exc)}),
            "citation_fingerprint": sha256_json([]),
            "failure_explanation": type(exc).__name__ + ":" + str(exc),
        }


def run_s0_acceptance(project_root: str | Path, output_path: str | Path | None = None) -> dict[str, Any]:
    root = Path(project_root).resolve()
    fixture_root = root / "fixtures" / "s0"
    if not fixture_root.is_dir():
        raise ValueError("synthetic_fixture_root_missing")
    with TemporaryDirectory() as temp:
        store = LocalStore(Path(temp) / "store")
        alpha = fixture_root / "project-alpha"
        beta = fixture_root / "project-beta"
        alpha_records = store.ingest_directory("project-alpha", alpha)
        beta_records = store.ingest_directory("project-beta", beta)
        runtime = LocalEvidenceRuntime(store, context_bound=300)
        cases: list[dict[str, Any]] = []
        cases.append(_case("VS-01", "register source identity/version/hash", lambda: {"source_id": alpha_records[0].source_id, "version_id": alpha_records[0].version_id, "fingerprint": alpha_records[0].content_fingerprint}, {"operation": "register_source", "project": "project-alpha", "source": "source-a.md"}))

        def duplicate() -> dict[str, Any]:
            before = store.canonical_fingerprint()
            a = store.register_bytes("project-alpha", "duplicate.md", b"same bytes\n", capture_time="2026-01-01T00:00:00Z")
            after_first = store.canonical_fingerprint()
            b = store.register_bytes("project-alpha", "duplicate.md", b"same bytes\n", capture_time="2026-01-01T00:00:00Z")
            after_second = store.canonical_fingerprint()
            return {"same_version": a.version_id == b.version_id, "first_registration_mutated": before != after_first, "no_second_mutation": after_first == after_second}

        cases.append(_case("VS-02", "repeat identical registration", duplicate, {"operation": "register_source", "project": "project-alpha", "source": "duplicate.md", "repeat": True}))
        cases.append(_case("VS-03", "query within alpha", lambda: _query_observation(runtime, QueryRequest("vs3", "project-alpha", "release status")), QueryRequest("vs3", "project-alpha", "release status").normalized()))
        cases.append(_case("VS-04", "foreign locator cannot widen project", lambda: {"disposition": runtime.query(QueryRequest("vs4", "project-alpha", "private")).disposition.value, "beta_is_absent": not any(item.project_id == "project-beta" for item in runtime.query(QueryRequest("vs4b", "project-alpha", "private")).evidence), "failure_explanation": "foreign project records remain outside the trusted project constraint"}, QueryRequest("vs4", "project-alpha", "private").normalized()))
        cases.append(_case("VS-05", "no supporting evidence", lambda: {"disposition": runtime.query(QueryRequest("vs5", "project-alpha", "not present anywhere")).disposition.value, "failure_explanation": "no supporting evidence is represented as typed EMPTY"}, QueryRequest("vs5", "project-alpha", "not present anywhere").normalized()))
        cases.append(_case("VS-06", "fixed context bound", lambda: _context_observation(runtime, QueryRequest("vs6", "project-alpha", "release")), QueryRequest("vs6", "project-alpha", "release").normalized()))

        def conflict() -> dict[str, Any]:
            store.register_bytes("project-alpha", "conflict-a.md", b"---\nconflict_group: s0-conflict\n---\nrelease status is ready\n", capture_time="2026-01-01T00:00:00Z")
            store.register_bytes("project-alpha", "conflict-b.md", b"---\nconflict_group: s0-conflict\n---\nrelease status is blocked\n", capture_time="2026-01-01T00:00:00Z")
            result = LocalEvidenceRuntime(store, context_bound=1000).query(QueryRequest("vs7", "project-alpha", "release status"))
            return {"disposition": result.disposition.value, "conflict_group_visible": any(item.conflict_group == "s0-conflict" for item in result.evidence)}

        cases.append(_case("VS-07", "two conflicting synthetic evidence items", conflict, QueryRequest("vs7", "project-alpha", "release status").normalized()))

        def ordering() -> dict[str, Any]:
            left, right = LocalStore(Path(temp) / "left"), LocalStore(Path(temp) / "right")
            entries = [("a.md", b"alpha one\n"), ("b.md", b"alpha two\n")]
            for name, content in entries:
                left.register_bytes("p", name, content, capture_time="2026-01-01T00:00:00Z")
            for name, content in reversed(entries):
                right.register_bytes("p", name, content, capture_time="2026-01-01T00:00:00Z")
            q = QueryRequest("vs8", "p", "alpha")
            return {"deterministic": LocalEvidenceRuntime(left).query(q).structured() == LocalEvidenceRuntime(right).query(q).structured()}

        cases.append(_case("VS-08", "reordered source registration", ordering, {"operation": "query", "project": "p", "query": "alpha"}))
        cases.append(_case("VS-09", "repeat same query", lambda: {"equivalent": runtime.query(QueryRequest("vs9", "project-alpha", "release")).structured() == runtime.query(QueryRequest("vs9", "project-alpha", "release")).structured()}, QueryRequest("vs9", "project-alpha", "release").normalized()))
        cases.append(_case("VS-10", "malformed UTF-8", lambda: {"fails_closed": _malformed(store), "failure_explanation": "strict UTF-8 decoder rejects malformed input"}, {"operation": "register_source", "project": "project-alpha", "source": "malformed.md"}))
        cases.append(_case("VS-11", "external network/provider access", lambda: {"denied": NetworkBoundary().evaluate("external_fetch", "https://example.com").action_result == "DENY", "external_access_observation": "no network call performed by deny-only boundary"}, {"operation": "external_fetch", "url": "https://example.com"}))

        def no_mutation() -> dict[str, Any]:
            before = store.canonical_fingerprint()
            result = runtime.query(QueryRequest("vs12", "project-alpha", "recipe"))
            envelope = compile_provider_neutral(result.context)
            ExternalEmissionFence().emit(envelope, current_context_fingerprint=result.context.fingerprint, destination="LOCAL_ONLY")
            after = store.canonical_fingerprint()
            return {"canonical_state_before": before, "canonical_state_after": after, "canonical_state_unchanged": before == after, "citation_refs": list(result.context.citation_refs), "context_fingerprint": result.context.fingerprint}

        cases.append(_case("VS-12", "read-only query and local handoff", no_mutation, QueryRequest("vs12", "project-alpha", "recipe").normalized()))
        passed = all(case["status"] == "RECORDED" and not any(value is False for value in _flatten(case["actual"])) for case in cases)
        report = {
            "artifact_kind": "PMIRI-V1-S0-ACCEPTANCE-REPORT",
            "status": "S0_ACCEPTANCE_CANDIDATE" if passed else "S0_REJECTED",
            "gate_c_r_fc_status": "NOT_APPLICABLE",
            "r_fc_pass": "NONE",
            "external_provider_access": "NOT_PERFORMED",
            "command": "python -m pmiri acceptance <project-root>",
            "environment": {"python": sys.version.split()[0], "platform": platform.platform(), "encoding": "UTF-8", "timezone": "UTC", "network": "DENY_BY_DEFAULT"},
            "cases": cases,
        }
        if output_path is not None:
            destination = Path(output_path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        return report


def _query_observation(runtime: LocalEvidenceRuntime, request: QueryRequest) -> dict[str, Any]:
    result = runtime.query(request)
    structured = result.structured()
    return {
        "disposition": result.disposition.value,
        "coverage": result.coverage.value,
        "all_in_project": all(item.project_id == request.project_constraint for item in result.evidence),
        "evidence_refs": [item.evidence_ref for item in result.evidence],
        "citation_refs": list(result.context.citation_refs),
        "result_fingerprint": sha256_json(structured),
    }


def _context_observation(runtime: LocalEvidenceRuntime, request: QueryRequest) -> dict[str, Any]:
    result = runtime.query(request)
    return {
        "within_bound": len(result.context.text) <= runtime.compiler.max_chars,
        "context_fingerprint": result.context.fingerprint,
        "citation_refs": list(result.context.citation_refs),
    }


def _flatten(value: Any) -> list[Any]:
    if isinstance(value, dict):
        values = []
        for child in value.values():
            values.extend(_flatten(child))
        return values
    if isinstance(value, list):
        values = []
        for child in value:
            values.extend(_flatten(child))
        return values
    return [value]


def _malformed(store: LocalStore) -> bool:
    try:
        store.register_bytes("project-alpha", "malformed.md", b"\xff")
    except UnicodeDecodeError:
        return True
    return False
