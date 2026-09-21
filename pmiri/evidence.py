"""GC-C1 evidence record construction without synthetic PASS promotion."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

from .canonical import is_sha256, sha256_json, utc_now


RF_CHECKS = {f"R-FC-{index:02d}" for index in range(1, 18)}
EVIDENCE_STATUSES = {"UNVERIFIED", "READY_FOR_REPLAY", "PASS", "FAIL", "BLOCKED"}


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    check_id: str
    matrix_version: str
    authority_refs: tuple[str, ...]
    fixture: Mapping[str, Any]
    action_trace: tuple[Mapping[str, Any], ...]
    oracle: Mapping[str, Any]
    actual: Mapping[str, Any]
    lineage: Mapping[str, Any]
    replay: Mapping[str, Any]
    review: Mapping[str, Any]
    captured_at: str
    status: str

    def structured(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "check_id": self.check_id,
            "matrix_version": self.matrix_version,
            "authority_refs": list(self.authority_refs),
            "fixture": dict(self.fixture),
            "action_trace": [dict(item) for item in self.action_trace],
            "oracle": dict(self.oracle),
            "actual": dict(self.actual),
            "lineage": dict(self.lineage),
            "replay": dict(self.replay),
            "review": dict(self.review),
            "captured_at": self.captured_at,
            "status": self.status,
        }


def create_evidence_record(
    *,
    check_id: str,
    fixture_id: str,
    input_fingerprint: str,
    expected_dispositions: list[str],
    forbidden_dispositions: list[str],
    actual: Mapping[str, Any],
    action_trace: list[Mapping[str, Any]] | None = None,
    authority_refs: list[str] | None = None,
    invariants: list[str] | None = None,
    lineage: Mapping[str, Any] | None = None,
    replay: Mapping[str, Any] | None = None,
    review: Mapping[str, Any] | None = None,
    status: str = "UNVERIFIED",
) -> EvidenceRecord:
    if check_id not in RF_CHECKS or not is_sha256(input_fingerprint):
        raise ValueError("evidence_identity_invalid")
    if status not in EVIDENCE_STATUSES:
        raise ValueError("evidence_status_invalid")
    if status == "PASS" and (replay is None or replay.get("executed") is not True):
        raise ValueError("pass_requires_executed_replay")
    if status == "PASS" and (review is None or review.get("review_result") != "accepted"):
        raise ValueError("pass_requires_independent_review")
    if status == "PASS" and review.get("primary_reviewer") == review.get("independent_reviewer"):
        raise ValueError("pass_requires_reviewer_separation")
    if not isinstance(actual, Mapping):
        raise ValueError("evidence_actual_invalid")
    fixture = {"fixture_id": fixture_id, "input_fingerprint": input_fingerprint, "privacy_class": "SYNTHETIC"}
    oracle = {
        "expected_dispositions": list(expected_dispositions) or ["UNSPECIFIED"],
        "forbidden_dispositions": list(forbidden_dispositions),
        "invariants": list(invariants or []) + ["disposition remains explicit and independently reviewable"],
    }
    trace = [dict(item) for item in (action_trace or [])]
    if not trace:
        trace = [{"step": 1, "operation": "replay_boundary", "input_ref": "fixture://" + fixture_id, "state_change_or_fault": "NO_RUNTIME_REPLAY"}]
    actual_record = {
        "disposition": str(actual.get("disposition", "UNKNOWN")),
        "output_artifact_ref": str(actual.get("output_artifact_ref", "artifact://gc-c1/" + check_id.lower())),
        "output_fingerprint": actual.get("output_fingerprint", sha256_json(dict(actual))),
    }
    if actual.get("notes") is not None:
        actual_record["notes"] = str(actual["notes"])
    lineage_input = dict(lineage or {})
    lineage_record = {
        "authorization_lineage_ref": str(lineage_input.get("authorization_lineage_ref", "lineage://unbound/" + check_id.lower())),
        "evidence_refs": list(lineage_input.get("evidence_refs", [])),
        "citation_refs": list(lineage_input.get("citation_refs", [])),
    }
    if lineage_input.get("boundary_refs") is not None:
        lineage_record["boundary_refs"] = list(lineage_input["boundary_refs"])
    replay_input = dict(replay or {})
    replay_record = {
        "runner_id": str(replay_input.get("runner_id", "runner://pmiri-gc-c1-replay")),
        "runner_version": str(replay_input.get("runner_version", "runner-version://0.1.0")),
        "command_or_workflow_ref": str(replay_input.get("command_or_workflow_ref", "workflow://not-executed")),
        "environment_fingerprint": replay_input.get("environment_fingerprint", sha256_json({"environment": "UNVERIFIED"})),
    }
    review_input = dict(review or {})
    review_record = {
        "primary_reviewer": str(review_input.get("primary_reviewer", "reviewer://not-supplied")),
        "independent_reviewer": str(review_input.get("independent_reviewer", "reviewer://not-supplied")),
        "review_result": str(review_input.get("review_result", "blocked")),
        "review_evidence_ref": str(review_input.get("review_evidence_ref", "review://not-supplied")),
    }
    stable = {"check_id": check_id, "fixture": fixture, "actual": actual_record, "oracle": oracle, "status": status}
    result = EvidenceRecord(
        evidence_id="GC-C1-EV-" + sha256_json(stable)[:16].upper(),
        check_id=check_id,
        matrix_version="0.1",
        authority_refs=tuple(authority_refs or ("authority://gc-c1-evidence-matrix",)),
        fixture=fixture,
        action_trace=tuple(trace),
        oracle=oracle,
        actual=actual_record,
        lineage=lineage_record,
        replay=replay_record,
        review=review_record,
        captured_at=utc_now(),
        status=status,
    )
    errors = validate_evidence_record(result.structured())
    if errors:
        raise ValueError("evidence_record_invalid:" + ",".join(errors))
    return result


def validate_evidence_record(record: Mapping[str, Any]) -> tuple[str, ...]:
    """Validate the GC-C1 evidence-record contract without promoting status."""
    errors: list[str] = []
    required = ("evidence_id", "check_id", "matrix_version", "authority_refs", "fixture", "action_trace", "oracle", "actual", "lineage", "replay", "review", "captured_at", "status")
    errors.extend("missing:" + key for key in required if key not in record)
    if not re.fullmatch(r"GC-C1-EV-[A-Z0-9-]+", str(record.get("evidence_id", ""))):
        errors.append("evidence_id_invalid")
    if record.get("check_id") not in RF_CHECKS or record.get("matrix_version") != "0.1":
        errors.append("evidence_identity_invalid")
    if not isinstance(record.get("authority_refs"), list) or not record["authority_refs"]:
        errors.append("authority_refs_missing")
    fixture = record.get("fixture", {})
    if not isinstance(fixture, dict) or not fixture.get("fixture_id") or not is_sha256(fixture.get("input_fingerprint")) or not fixture.get("privacy_class"):
        errors.append("fixture_invalid")
    trace = record.get("action_trace")
    if not isinstance(trace, list) or not trace:
        errors.append("action_trace_missing")
    else:
        for item in trace:
            if not isinstance(item, dict) or not isinstance(item.get("step"), int) or item["step"] < 1 or not item.get("operation") or not item.get("input_ref") or not item.get("state_change_or_fault"):
                errors.append("action_trace_invalid")
                break
    oracle = record.get("oracle", {})
    if not isinstance(oracle, dict) or not oracle.get("expected_dispositions") or not isinstance(oracle.get("invariants"), list) or not oracle["invariants"]:
        errors.append("oracle_invalid")
    actual = record.get("actual", {})
    if not isinstance(actual, dict) or not actual.get("disposition") or not actual.get("output_artifact_ref") or not is_sha256(actual.get("output_fingerprint")):
        errors.append("actual_invalid")
    lineage = record.get("lineage", {})
    if not isinstance(lineage, dict) or not lineage.get("authorization_lineage_ref") or not isinstance(lineage.get("evidence_refs"), list) or not isinstance(lineage.get("citation_refs"), list):
        errors.append("lineage_invalid")
    replay = record.get("replay", {})
    if not isinstance(replay, dict) or not replay.get("runner_id") or not replay.get("runner_version") or not replay.get("command_or_workflow_ref") or not is_sha256(replay.get("environment_fingerprint")):
        errors.append("replay_invalid")
    review = record.get("review", {})
    if not isinstance(review, dict) or not review.get("primary_reviewer") or not review.get("independent_reviewer") or review.get("review_result") not in {"accepted", "rejected", "blocked"} or not review.get("review_evidence_ref"):
        errors.append("review_invalid")
    if record.get("status") not in EVIDENCE_STATUSES:
        errors.append("status_invalid")
    return tuple(errors)


__all__ = ["EVIDENCE_STATUSES", "EvidenceRecord", "RF_CHECKS", "create_evidence_record", "validate_evidence_record"]
