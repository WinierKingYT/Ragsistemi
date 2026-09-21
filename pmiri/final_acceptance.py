"""Fail-closed final acceptance gate for the PMIRI candidate.

Deployment readiness and final acceptance are intentionally different gates.
The former checks the deployment prerequisites; this module additionally
requires signed evidence for controlled D2 acceptance, R-FC 17/17 PASS,
migration/restore/failover, independent review and operations approval.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from .canonical import canonical_json, is_sha256, sha256_json, utc_now
from .deployment_evidence import (
    FINAL_ACCEPTANCE_ASSERTIONS,
    DeploymentEvidenceError,
    verify_final_acceptance_evidence,
)
from .readiness import validate_readiness_report


FINAL_GATE_KIND = "PMIRI-FINAL-ACCEPTANCE-GATE"
FINAL_GATE_VERSION = "0.1"
FINAL_GATE_READY = "FINAL_ACCEPTANCE_READY"
FINAL_GATE_BLOCKED = "FINAL_ACCEPTANCE_BLOCKED"
FINAL_GATE_REPORT_PATH = "artifacts/final-acceptance-gate.json"

FINAL_GATE_REQUIREMENTS = (
    ("FA-01", "DEPLOYMENT_READINESS"),
    *(item[:2] for item in FINAL_ACCEPTANCE_ASSERTIONS),
)


class FinalAcceptanceError(ValueError):
    """Raised when a final-acceptance report cannot be written safely."""


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _resolve(root: Path, value: str | Path) -> Path:
    path = Path(value)
    return path.resolve() if path.is_absolute() else (root / path).resolve()


def _check(
    check_id: str,
    assertion: str,
    result: str,
    observation: str,
    *evidence_refs: str,
) -> dict[str, Any]:
    unsigned = {
        "check_id": check_id,
        "assertion": assertion,
        "result": result,
        "observation": observation,
        "evidence_refs": list(evidence_refs),
        "severity": "HARD_BLOCK",
    }
    return {**unsigned, "observed_fingerprint": sha256_json(unsigned)}


def _readiness_check(readiness: Mapping[str, Any] | None) -> dict[str, Any]:
    if readiness is None:
        return _check("FA-01", "DEPLOYMENT_READINESS", "BLOCKED", "deployment-readiness report is missing or invalid")
    errors = validate_readiness_report(readiness)
    if errors:
        return _check("FA-01", "DEPLOYMENT_READINESS", "BLOCKED", "deployment-readiness report is invalid:" + errors[0])
    checks = readiness.get("checks")
    external_results = {
        str(item.get("check_id")): item.get("result")
        for item in checks
        if isinstance(item, Mapping) and str(item.get("check_id", "")).startswith("EXT-")
    }
    expected_external_ids = {"EXT-01", "EXT-02", "EXT-03", "EXT-04", "EXT-05", "EXT-06"}
    ext_ready = set(external_results) == expected_external_ids and all(value == "READY" for value in external_results.values())
    if readiness.get("overall_result") == "DEPLOYMENT_READY" and ext_ready:
        return _check("FA-01", "DEPLOYMENT_READINESS", "READY", "deployment-readiness report is READY and all EXT-01..EXT-06 checks are READY", "artifacts/deployment-readiness-report.json")
    blocked = [
        str(item.get("check_id"))
        for item in checks
        if isinstance(item, Mapping) and item.get("result") == "BLOCKED"
    ]
    suffix = ",".join(blocked) if blocked else "readiness_result_not_ready"
    return _check("FA-01", "DEPLOYMENT_READINESS", "BLOCKED", "deployment readiness is not sufficient for final acceptance:" + suffix, "artifacts/deployment-readiness-report.json")


def build_final_acceptance_report(
    project_root: str | Path,
    *,
    readiness_path: str | Path = "artifacts/deployment-readiness-report.json",
    evidence_path: str | Path | None = None,
    public_key_path: str | Path | None = None,
    captured_at: str | None = None,
) -> dict[str, Any]:
    """Build a self-fingerprinted final gate without performing external I/O."""
    root = Path(project_root).resolve()
    readiness = _read_json(_resolve(root, readiness_path))
    readiness_errors = validate_readiness_report(readiness) if readiness is not None else ("readiness_report_missing_or_invalid",)
    if readiness is not None and not readiness_errors:
        try:
            readiness_root = Path(str(readiness["project_root"])).resolve()
        except (OSError, TypeError, ValueError):
            readiness_root = None
        if readiness_root != root:
            readiness_errors = ("readiness_project_root_mismatch",)

    valid_readiness = readiness if not readiness_errors else None
    readiness_check = _readiness_check(valid_readiness)
    unavailable = sha256_json({"status": "UNAVAILABLE"})
    profile_id = str(valid_readiness.get("profile_id", "UNAVAILABLE")) if valid_readiness is not None else "UNAVAILABLE"
    profile_fingerprint = str(valid_readiness.get("profile_fingerprint", unavailable)) if valid_readiness is not None else unavailable
    authority_fingerprint = str(valid_readiness.get("authority_fingerprint", unavailable)) if valid_readiness is not None else unavailable
    readiness_fingerprint = str(valid_readiness.get("report_fingerprint", unavailable)) if valid_readiness is not None else unavailable

    evidence = None
    evidence_status = "NOT_SUPPLIED"
    evidence_reason = "signed final-acceptance evidence is not supplied"
    if evidence_path is None and public_key_path is None:
        pass
    elif evidence_path is None or public_key_path is None:
        evidence_status = "INVALID"
        evidence_reason = "both final-acceptance evidence and its trusted public key are required"
    elif readiness_errors:
        evidence_status = "INVALID"
        evidence_reason = "current readiness report cannot bind final-acceptance evidence:" + readiness_errors[0]
    else:
        try:
            evidence = verify_final_acceptance_evidence(
                _resolve(root, evidence_path),
                trusted_public_key=_resolve(root, public_key_path).read_bytes(),
                profile_id=profile_id,
                profile_fingerprint=profile_fingerprint,
                authority_fingerprint=authority_fingerprint,
                readiness_report_fingerprint=readiness_fingerprint,
            )
        except (DeploymentEvidenceError, OSError, ValueError, TypeError) as exc:
            evidence_status = "INVALID"
            evidence_reason = type(exc).__name__ + ":" + str(exc)
        else:
            evidence_status = "VERIFIED"
            evidence_reason = "signed final-acceptance evidence verified against the current readiness report"

    checks = [readiness_check]
    for check_id, assertion, _ in FINAL_ACCEPTANCE_ASSERTIONS:
        if evidence is None:
            checks.append(_check(check_id, assertion, "BLOCKED", evidence_reason))
        else:
            item = evidence.assertions[check_id]
            checks.append(_check(check_id, assertion, "READY", "signed final-acceptance evidence verified; evidence_fingerprint=" + evidence.evidence_fingerprint, *[str(ref) for ref in item["evidence_refs"]]))

    overall = FINAL_GATE_READY if all(item["result"] == "READY" for item in checks) else FINAL_GATE_BLOCKED
    report: dict[str, Any] = {
        "artifact_kind": FINAL_GATE_KIND,
        "artifact_version": FINAL_GATE_VERSION,
        "status": overall,
        "overall_result": overall,
        "project_root": root.as_posix(),
        "captured_at": captured_at or utc_now(),
        "profile_id": profile_id,
        "profile_fingerprint": profile_fingerprint,
        "authority_fingerprint": authority_fingerprint,
        "readiness_report_fingerprint": readiness_fingerprint,
        "external_evidence_status": evidence_status,
        "external_evidence_fingerprint": evidence.evidence_fingerprint if evidence is not None else None,
        "required_assertions": [{"check_id": check_id, "assertion": assertion} for check_id, assertion in FINAL_GATE_REQUIREMENTS],
        "checks": checks,
    }
    report["report_fingerprint"] = sha256_json(report)
    return report


def validate_final_acceptance_report(
    report: Mapping[str, Any],
    *,
    project_root: str | Path | None = None,
) -> tuple[str, ...]:
    """Validate the final gate shape, derived fingerprints and status.

    When ``project_root`` is supplied, also bind the report to the current
    canonical readiness artifact. This prevents a self-fingerprinted report
    copied or resigned from another workspace from entering the review
    package.
    """
    required = {
        "artifact_kind", "artifact_version", "status", "overall_result", "project_root", "captured_at",
        "profile_id", "profile_fingerprint", "authority_fingerprint", "readiness_report_fingerprint",
        "external_evidence_status", "external_evidence_fingerprint", "required_assertions", "checks",
        "report_fingerprint",
    }
    errors: list[str] = []
    if set(report) != required:
        errors.append("fields_invalid")
    if report.get("artifact_kind") != FINAL_GATE_KIND or report.get("artifact_version") != FINAL_GATE_VERSION:
        errors.append("identity_invalid")
    if report.get("status") != report.get("overall_result") or report.get("status") not in {FINAL_GATE_READY, FINAL_GATE_BLOCKED}:
        errors.append("status_invalid")
    for field in ("profile_fingerprint", "authority_fingerprint", "readiness_report_fingerprint", "report_fingerprint"):
        if not is_sha256(report.get(field)):
            errors.append("fingerprint_invalid:" + field)
    if not isinstance(report.get("project_root"), str) or not report["project_root"] or not isinstance(report.get("captured_at"), str) or not report["captured_at"] or not isinstance(report.get("profile_id"), str) or not report["profile_id"]:
        errors.append("report_identity_fields_invalid")
    if report.get("external_evidence_status") not in {"NOT_SUPPLIED", "INVALID", "VERIFIED"}:
        errors.append("external_evidence_status_invalid")
    evidence_fingerprint = report.get("external_evidence_fingerprint")
    evidence_status = report.get("external_evidence_status")
    if evidence_status == "VERIFIED":
        if not is_sha256(evidence_fingerprint):
            errors.append("verified_evidence_fingerprint_invalid")
    elif evidence_fingerprint is not None:
        errors.append("unverified_evidence_fingerprint_must_be_null")
    required_assertions = report.get("required_assertions")
    expected_requirements = [{"check_id": check_id, "assertion": assertion} for check_id, assertion in FINAL_GATE_REQUIREMENTS]
    if required_assertions != expected_requirements:
        errors.append("required_assertions_invalid")
    checks = report.get("checks")
    expected_ids = [check_id for check_id, _ in FINAL_GATE_REQUIREMENTS]
    if not isinstance(checks, list) or [item.get("check_id") for item in checks if isinstance(item, Mapping)] != expected_ids:
        errors.append("checks_invalid")
    else:
        for item in checks:
            check_required = {"check_id", "assertion", "result", "observation", "evidence_refs", "severity", "observed_fingerprint"}
            if not isinstance(item, Mapping) or set(item) != check_required:
                errors.append("check_shape_invalid")
                continue
            expected_assertion = dict(FINAL_GATE_REQUIREMENTS).get(item.get("check_id"))
            if expected_assertion is None or item.get("assertion") != expected_assertion:
                errors.append("check_identity_invalid:" + str(item.get("check_id")))
            if item["result"] not in {"READY", "BLOCKED"} or item["severity"] != "HARD_BLOCK":
                errors.append("check_value_invalid:" + str(item.get("check_id")))
            if not isinstance(item["evidence_refs"], list) or any(not isinstance(ref, str) or not ref for ref in item["evidence_refs"]):
                errors.append("check_refs_invalid:" + str(item.get("check_id")))
            unsigned = {key: item[key] for key in ("check_id", "assertion", "result", "observation", "evidence_refs", "severity")}
            if item.get("observed_fingerprint") != sha256_json(unsigned):
                errors.append("check_fingerprint_mismatch:" + str(item.get("check_id")))
    if report.get("overall_result") == FINAL_GATE_READY:
        if evidence_status != "VERIFIED":
            errors.append("ready_without_verified_evidence")
        if isinstance(checks, list) and any(item.get("result") != "READY" for item in checks if isinstance(item, Mapping)):
            errors.append("ready_with_blocked_checks")
    if report.get("overall_result") == FINAL_GATE_BLOCKED and isinstance(checks, list) and all(item.get("result") == "READY" for item in checks if isinstance(item, Mapping)):
        errors.append("blocked_without_blocked_checks")
    if project_root is not None:
        expected_root = Path(project_root).resolve()
        observed_root_value = report.get("project_root")
        if not isinstance(observed_root_value, str) or not observed_root_value:
            errors.append("project_root_binding_invalid")
        else:
            try:
                observed_root = Path(observed_root_value).resolve()
            except (OSError, TypeError, ValueError):
                observed_root = None
            if observed_root != expected_root:
                errors.append("project_root_binding_mismatch")
        current_readiness = _read_json(expected_root / "artifacts/deployment-readiness-report.json")
        if current_readiness is None:
            errors.append("current_readiness_missing_or_invalid")
        else:
            readiness_errors = validate_readiness_report(current_readiness)
            if readiness_errors:
                errors.append("current_readiness_invalid:" + readiness_errors[0])
            else:
                try:
                    readiness_root = Path(str(current_readiness["project_root"])).resolve()
                except (OSError, TypeError, ValueError):
                    readiness_root = None
                if readiness_root != expected_root:
                    errors.append("current_readiness_project_root_mismatch")
                for field in ("profile_id", "profile_fingerprint", "authority_fingerprint", "report_fingerprint"):
                    report_field = "readiness_report_fingerprint" if field == "report_fingerprint" else field
                    if report.get(report_field) != current_readiness.get(field):
                        errors.append("readiness_binding_mismatch:" + report_field)
    unsigned_report = {key: report[key] for key in required if key != "report_fingerprint"}
    if report.get("report_fingerprint") != sha256_json(unsigned_report):
        errors.append("report_fingerprint_mismatch")
    return tuple(errors)


def write_final_acceptance_report(report: Mapping[str, Any], output_path: str | Path) -> dict[str, Any]:
    errors = validate_final_acceptance_report(report)
    if errors:
        raise FinalAcceptanceError("final_acceptance_report_invalid:" + errors[0])
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(report) + b"\n")
    return dict(report)


__all__ = [
    "FINAL_GATE_BLOCKED",
    "FINAL_GATE_KIND",
    "FINAL_GATE_READY",
    "FINAL_GATE_REPORT_PATH",
    "FINAL_GATE_REQUIREMENTS",
    "FINAL_GATE_VERSION",
    "FinalAcceptanceError",
    "build_final_acceptance_report",
    "validate_final_acceptance_report",
    "write_final_acceptance_report",
]
