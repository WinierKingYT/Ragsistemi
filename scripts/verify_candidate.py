"""Read-only, fail-closed audit of the PMIRI local release candidate."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

# Running a script by path places ``scripts/`` first on sys.path. Add the
# project root explicitly so the documented command works without installing
# PMIRI into the interpreter environment.
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from pmiri.final_acceptance import validate_final_acceptance_report
from pmiri.handoff import verify_handoff
from pmiri.integrity import validate_documentation_bundle
from pmiri.preflight import validate_preflight_record_shape
from pmiri.d2 import validate_d2_matrix
from pmiri.evidence import RF_CHECKS
from pmiri.readiness import load_profile, validate_readiness_report
from pmiri.r_fc import load_handler_manifest
from pmiri.review_package import validate_review_package
from pmiri.sealing import verify_seal
from pmiri.canonical import sha256_json, utc_now
from scripts.generate_sbom import build_sbom, read_lock, verify_sbom
from scripts.verify_reproducibility import verify_installed


_HANDOFF_RE = re.compile(r"^handoff-release-v([1-9][0-9]*)$")


def _load_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, f"{path.as_posix()}: {type(exc).__name__}"
    if not isinstance(value, dict):
        return None, f"{path.as_posix()}: root_not_object"
    return value, None


def _check(check_id: str, result: str, reason: str, details: Any = None) -> dict[str, Any]:
    item: dict[str, Any] = {"check_id": check_id, "result": result, "reason": reason}
    if details is not None:
        item["details"] = details
    return item


def _latest_handoff(root: Path) -> tuple[Path | None, str | None]:
    artifact_root = root / "artifacts"
    candidates: list[tuple[int, Path]] = []
    if artifact_root.is_dir():
        for directory in artifact_root.iterdir():
            if not directory.is_dir() or directory.is_symlink():
                continue
            match = _HANDOFF_RE.fullmatch(directory.name)
            manifest = directory / "handoff-manifest.json"
            if match and manifest.is_file() and not manifest.is_symlink():
                candidates.append((int(match.group(1)), manifest))
    if not candidates:
        return None, "no_immutable_handoff_manifest"
    return max(candidates, key=lambda item: item[0])[1], None


def _selected_handoff(root: Path, manifest: str | Path | None) -> tuple[Path | None, str | None]:
    if manifest is None:
        return _latest_handoff(root)
    path = Path(manifest)
    if not path.is_absolute():
        path = root / path
    if path.is_symlink():
        return None, "handoff_manifest_symlink_not_allowed"
    path = path.resolve()
    try:
        path.relative_to(root)
    except ValueError:
        return None, "handoff_manifest_outside_project"
    if path.is_symlink() or not path.is_file():
        return None, "handoff_manifest_unavailable"
    return path, None


def _selected_profile(root: Path, profile: str | Path | None) -> tuple[Path | None, str | None]:
    path = root / "deployment-profile.example.json" if profile is None else Path(profile)
    if not path.is_absolute():
        path = root / path
    if path.is_symlink():
        return None, "profile_symlink_not_allowed"
    path = path.resolve()
    try:
        path.relative_to(root)
    except ValueError:
        return None, "profile_outside_project"
    if path.is_symlink() or not path.is_file():
        return None, "profile_unavailable"
    return path, None


def _validate_sbom(root: Path) -> tuple[dict[str, Any], list[str]]:
    """Verify the tracked SBOM against the current lock and release epoch."""
    path = root / "artifacts" / "sbom" / "pmiri-sbom.spdx.json"
    document, error = _load_json(path)
    if document is None:
        return {"path": path.relative_to(root).as_posix()}, [error or "sbom_unavailable"]
    try:
        locked = read_lock()
        expected = build_sbom(locked=locked)
        errors = list(verify_sbom(document, locked=locked, announce=False))
    except (OSError, UnicodeDecodeError, ValueError, TypeError, KeyError) as exc:
        return {"path": path.relative_to(root).as_posix()}, [f"sbom_generation_contract_invalid:{type(exc).__name__}:{exc}"]
    if document != expected:
        errors.append("sbom_not_deterministic_or_stale")
    details = {
        "path": path.relative_to(root).as_posix(),
        "package_count": len(document.get("packages", [])) if isinstance(document.get("packages"), list) else None,
        "creation_time": document.get("creationInfo", {}).get("created") if isinstance(document.get("creationInfo"), dict) else None,
    }
    return details, errors


def _validate_scenario_inventory(root: Path) -> tuple[dict[str, Any], list[str]]:
    artifact_root = root / "artifacts"
    errors: list[str] = []
    summary: dict[str, Any] = {}

    expected_d2_ids: list[str] = []
    try:
        authority_matrix = validate_d2_matrix(root)
        expected_d2_ids = [str(item.get("scenario_id")) for item in authority_matrix.get("cases", [])]
        if authority_matrix.get("status") != "D2_DOCUMENTARY_VALIDATED_RUNTIME_BLOCKED" or len(expected_d2_ids) != 34 or len(set(expected_d2_ids)) != 34:
            errors.append("d2_authority_matrix_contract_invalid")
    except (OSError, UnicodeDecodeError, ValueError, TypeError, KeyError) as exc:
        errors.append(f"d2_authority_matrix_unavailable:{type(exc).__name__}")
    expected_rfc_ids = {f"GC-C1-FC{index:02d}-{kind}" for index in range(1, 18) for kind in ("A", "P")}

    def load(name: str) -> dict[str, Any] | None:
        value, error = _load_json(artifact_root / name)
        if value is None:
            errors.append(error or f"{name}: unavailable")
        return value

    matrix = load("d2-matrix-report.json")
    if matrix is not None:
        summary["d2_matrix_case_count"] = len(matrix.get("cases", []))
        summary["d2_matrix_scenario_count"] = matrix.get("scenario_count")
        matrix_ids = [item.get("scenario_id") for item in matrix.get("cases", []) if isinstance(item, dict)]
        if matrix.get("status") != "D2_DOCUMENTARY_VALIDATED_RUNTIME_BLOCKED":
            errors.append("d2_matrix_status_invalid")
        if len(matrix.get("cases", [])) != 34 or matrix.get("scenario_count") != 34:
            errors.append("d2_matrix_must_cover_34_cases")
        if matrix_ids != expected_d2_ids or len(set(matrix_ids)) != len(matrix_ids):
            errors.append("d2_matrix_case_ids_do_not_match_authority")

    d2_runtime = load("d2-runtime-candidate-report.json")
    if d2_runtime is not None:
        summary["d2_runtime_case_count"] = len(d2_runtime.get("cases", []))
        runtime_ids = [item.get("scenario_id") for item in d2_runtime.get("cases", []) if isinstance(item, dict)]
        if (
            len(d2_runtime.get("cases", [])) != 34
            or d2_runtime.get("scenario_count") != 34
            or d2_runtime.get("all_oracles_match") is not True
            or d2_runtime.get("runtime_execution") != "LOCAL_SYNTHETIC_ONLY"
            or d2_runtime.get("d2_acceptance") != "NOT_CLAIMED"
            or runtime_ids != expected_d2_ids
            or len(set(runtime_ids)) != len(runtime_ids)
            or any(item.get("status") != "ORACLE_MATCH" for item in d2_runtime.get("cases", []) if isinstance(item, dict))
            or d2_runtime.get("report_fingerprint") != sha256_json(d2_runtime.get("cases"))
        ):
            errors.append("d2_runtime_candidate_contract_invalid")

    local_rfc = load("r-fc-local-handler-candidate-report.json")
    if local_rfc is not None:
        summary["local_r_fc_case_count"] = len(local_rfc.get("cases", []))
        local_rfc_ids = [item.get("case_id") for item in local_rfc.get("cases", []) if isinstance(item, dict)]
        local_rfc_unsigned = {key: value for key, value in local_rfc.items() if key != "report_fingerprint"}
        if (
            len(local_rfc.get("cases", [])) != 34
            or local_rfc.get("selected_case_count") != 34
            or local_rfc.get("oracle_match_count") != 34
            or local_rfc.get("all_oracles_match") is not True
            or local_rfc.get("status") != "LOCAL_SYNTHETIC_ONLY"
            or local_rfc.get("r_fc_pass") != "NONE"
            or set(local_rfc_ids) != expected_rfc_ids
            or len(local_rfc_ids) != len(set(local_rfc_ids))
            or any(item.get("status") != "ORACLE_MATCH" or item.get("executed") is not True or item.get("oracle_match") is not True for item in local_rfc.get("cases", []) if isinstance(item, dict))
            or local_rfc.get("report_fingerprint") != sha256_json(local_rfc_unsigned)
        ):
            errors.append("local_r_fc_candidate_contract_invalid")

    blocked_rfc = load("r-fc-blocked-candidate-report.json")
    if blocked_rfc is not None:
        summary["blocked_r_fc_case_count"] = len(blocked_rfc.get("cases", []))
        blocked_ids = [item.get("check_id") for item in blocked_rfc.get("cases", []) if isinstance(item, dict)]
        if (
            len(blocked_rfc.get("cases", [])) != 17
            or blocked_rfc.get("blocked_case_count") != 17
            or blocked_rfc.get("executed_case_count") != 0
            or blocked_rfc.get("status") != "R_FC_REPLAY_BLOCKED"
            or blocked_rfc.get("r_fc_pass") != "NONE"
            or set(blocked_ids) != RF_CHECKS
            or len(blocked_ids) != len(set(blocked_ids))
            or any(item.get("status") != "BLOCKED" or item.get("executed") is not False for item in blocked_rfc.get("cases", []) if isinstance(item, dict))
            or blocked_rfc.get("report_fingerprint") != sha256_json(blocked_rfc.get("cases"))
        ):
            errors.append("blocked_r_fc_inventory_contract_invalid")

    expected_case_ids = {f"GC-C1-FC{index:02d}-{kind}" for index in range(1, 18) for kind in ("A", "P")}
    try:
        handler_manifest = load_handler_manifest(artifact_root / "r-fc-handler-manifest.json")
        handler_ids = set(handler_manifest.get("case_ids", []))
        summary["handler_manifest_case_count"] = len(handler_ids)
        if handler_manifest.get("status") != "READY_FOR_REPLAY" or handler_ids != expected_case_ids:
            errors.append("handler_manifest_must_cover_exact_34_cases")
    except (OSError, UnicodeDecodeError, ValueError, TypeError) as exc:
        errors.append(f"r-fc-handler-manifest-invalid:{type(exc).__name__}")

    preflight = load("preflight-record.json")
    if preflight is not None:
        preflight_errors = list(validate_preflight_record_shape(preflight))
        summary["preflight_check_count"] = len(preflight.get("checks", []))
        if preflight_errors:
            errors.extend("preflight:" + error for error in preflight_errors)
        if [item.get("check_id") for item in preflight.get("checks", [])] != [f"PF-{index:02d}" for index in range(1, 17)]:
            errors.append("preflight_must_cover_ordered_pf_01_to_pf_16")

    return summary, errors


def build_candidate_audit(
    project_root: str | Path = ".",
    handoff_manifest: str | Path | None = None,
    profile: str | Path | None = None,
) -> dict[str, Any]:
    root = Path(project_root).resolve()
    checks: list[dict[str, Any]] = []

    integrity = validate_documentation_bundle(root)
    checks.append(_check("LOCAL-INT-01", "PASS" if integrity.ok else "FAIL", "documentation authority and schema registry", integrity.structured()))

    sbom_details, sbom_errors = _validate_sbom(root)
    checks.append(_check("LOCAL-SBOM-01", "PASS" if not sbom_errors else "FAIL", "deterministic SBOM and locked package inventory", sbom_details if not sbom_errors else sbom_errors))

    try:
        locked = read_lock()
        reproducibility_errors = list(verify_installed(locked, announce=False))
        reproducibility_details: Any = {"locked_package_count": len(locked)}
    except (OSError, UnicodeDecodeError, ValueError, TypeError, KeyError) as exc:
        reproducibility_errors = [f"installed_runtime_check_unavailable:{type(exc).__name__}:{exc}"]
        reproducibility_details = reproducibility_errors
    checks.append(
        _check(
            "LOCAL-REPRO-01",
            "PASS" if not reproducibility_errors else "FAIL",
            "installed runtime matches exact requirements.lock",
            reproducibility_details if not reproducibility_errors else reproducibility_errors,
        )
    )

    readiness_path = root / "artifacts" / "deployment-readiness-report.json"
    readiness, readiness_error = _load_json(readiness_path)
    if readiness is None:
        checks.append(_check("LOCAL-READINESS-01", "FAIL", "readiness report cannot be loaded", readiness_error))
    else:
        errors = list(validate_readiness_report(readiness))
        checks.append(_check("LOCAL-READINESS-01", "PASS" if not errors else "FAIL", "readiness report shape and fingerprints", errors))

    profile_path, profile_error = _selected_profile(root, profile)
    active_profile: dict[str, Any] | None = None
    profile_summary: dict[str, Any] = {"status": "UNAVAILABLE"}
    if profile_path is None:
        checks.append(_check("LOCAL-PROFILE-01", "FAIL", "active deployment profile is unavailable", profile_error))
    else:
        try:
            active_profile = load_profile(profile_path)
            profile_fingerprint = sha256_json(active_profile)
            profile_summary = {
                "path": profile_path.relative_to(root).as_posix(),
                "profile_id": active_profile["profile_id"],
                "profile_fingerprint": profile_fingerprint,
            }
            binding_errors: list[str] = []
            if readiness is None:
                binding_errors.append("readiness_report_unavailable")
            else:
                if readiness.get("profile_id") != active_profile["profile_id"]:
                    binding_errors.append("readiness_profile_id_mismatch")
                if readiness.get("profile_fingerprint") != profile_fingerprint:
                    binding_errors.append("readiness_profile_fingerprint_mismatch")
            checks.append(
                _check(
                    "LOCAL-PROFILE-01",
                    "PASS" if not binding_errors else "FAIL",
                    "active profile contract and readiness binding",
                    profile_summary if not binding_errors else binding_errors,
                )
            )
        except (OSError, UnicodeDecodeError, ValueError, TypeError, KeyError) as exc:
            checks.append(_check("LOCAL-PROFILE-01", "FAIL", "active deployment profile is invalid", f"{type(exc).__name__}:{exc}"))

    final_path = root / "artifacts" / "final-acceptance-gate.json"
    final, final_error = _load_json(final_path)
    if final is None:
        checks.append(_check("LOCAL-FINAL-01", "FAIL", "final-acceptance report cannot be loaded", final_error))
    else:
        errors = list(validate_final_acceptance_report(final, project_root=root))
        checks.append(_check("LOCAL-FINAL-01", "PASS" if not errors else "FAIL", "final-acceptance report shape and fingerprints", errors))

    review_path = root / "artifacts" / "review-package.json"
    review, review_error = _load_json(review_path)
    if review is None:
        checks.append(_check("LOCAL-REVIEW-01", "FAIL", "review package cannot be loaded", review_error))
    else:
        errors = list(validate_review_package(review, project_root=root))
        checks.append(_check("LOCAL-REVIEW-01", "PASS" if not errors else "FAIL", "review package source binding and fingerprints", errors))

    seal_path = root / "artifacts" / "sealed" / "s0-acceptance" / "artifact-manifest.json"
    seal_ok, seal_reason = verify_seal(seal_path, root=root)
    checks.append(_check("LOCAL-SEAL-01", "PASS" if seal_ok else "FAIL", "candidate artifact seal", seal_reason))

    scenario_inventory, scenario_errors = _validate_scenario_inventory(root)
    checks.append(_check("LOCAL-SCENARIOS-01", "PASS" if not scenario_errors else "FAIL", "PF/D2/R-FC candidate inventory and exact coverage", scenario_errors or scenario_inventory))

    handoff_path, handoff_error = _selected_handoff(root, handoff_manifest)
    if handoff_path is None:
        checks.append(_check("LOCAL-HANDOFF-01", "FAIL", "latest immutable handoff is unavailable", handoff_error))
        handoff_summary: dict[str, Any] = {"status": "UNAVAILABLE"}
    else:
        handoff_ok, handoff_reason = verify_handoff(handoff_path, project_root=root)
        handoff_summary = {
            "manifest": handoff_path.relative_to(root).as_posix(),
            "status": "VERIFIED" if handoff_ok else "INVALID",
            "reason": handoff_reason,
        }
        checks.append(_check("LOCAL-HANDOFF-01", "PASS" if handoff_ok else "FAIL", "latest immutable handoff manifest and payload", handoff_summary))

    local_failures = [item for item in checks if item["result"] != "PASS"]
    external_blockers: list[dict[str, Any]] = []
    if readiness is not None:
        external_blockers.extend(
            {
                "check_id": item.get("check_id"),
                "assertion": item.get("assertion"),
                "observation": item.get("observation"),
                "evidence_refs": item.get("evidence_refs", []),
                "severity": item.get("severity"),
            }
            for item in readiness.get("checks", [])
            if isinstance(item, dict) and item.get("category") == "EXTERNAL_PREREQUISITE" and item.get("result") == "BLOCKED"
        )

    return {
        "report_type": "PMIRI-LOCAL-RELEASE-CANDIDATE-AUDIT",
        "report_version": "0.1",
        "project_root": str(root),
        "captured_at": utc_now(),
        "candidate_status": "LOCAL_CANDIDATE_VERIFIED" if not local_failures else "LOCAL_CANDIDATE_INVALID",
        "closure_status": "EXTERNAL_CLOSURE_PENDING" if external_blockers else "EXTERNAL_CLAIMS_REQUIRE_REVIEW",
        "local_failure_count": len(local_failures),
        "external_blocker_count": len(external_blockers),
        "readiness_result": readiness.get("overall_result") if readiness is not None else "UNAVAILABLE",
        "final_acceptance_result": final.get("overall_result") if final is not None else "UNAVAILABLE",
        "active_profile": profile_summary,
        "scenario_inventory": scenario_inventory,
        "latest_handoff": handoff_summary,
        "checks": checks,
        "external_blockers": external_blockers,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="PMIRI project root")
    parser.add_argument("--profile", help="active in-project deployment profile; defaults to deployment-profile.example.json")
    parser.add_argument("--handoff-manifest", help="explicit in-project handoff manifest; defaults to the latest handoff-release-vN")
    args = parser.parse_args(argv)
    report = build_candidate_audit(args.root, args.handoff_manifest, args.profile)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["candidate_status"] == "LOCAL_CANDIDATE_VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
