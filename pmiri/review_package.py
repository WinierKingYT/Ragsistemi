"""Machine-readable review package for the PMIRI candidate handoff.

The package is a compact inventory and acceptance checklist.  It records
fingerprints and bounded status/count summaries from local candidate reports;
it never turns local synthetic execution into external evidence or acceptance.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from .canonical import canonical_json, is_sha256, sha256_bytes, sha256_json
from .deployment_evidence import EXTERNAL_REQUIREMENTS
from .final_acceptance import validate_final_acceptance_report
from .preflight import validate_preflight_record_shape
from .readiness import validate_readiness_report


REVIEW_PACKAGE_KIND = "PMIRI-EXTERNAL-REVIEW-PACKAGE"
REVIEW_PACKAGE_VERSION = "0.2"
REVIEW_PACKAGE_STATUS = "READY_FOR_EXTERNAL_REVIEW"

_REPORT_PATHS = (
    "artifacts/preflight-record.json",
    "artifacts/s0-acceptance-report.json",
    "artifacts/d2-matrix-report.json",
    "artifacts/d2-runtime-candidate-report.json",
    "artifacts/gate-d-runtime-smoke-report.json",
    "artifacts/r-fc-blocked-candidate-report.json",
    "artifacts/r-fc-local-handler-candidate-report.json",
    "artifacts/r-fc-handler-manifest.json",
    "artifacts/deployment-smoke-report.json",
    "artifacts/deployment-readiness-report.json",
    "artifacts/final-acceptance-gate.json",
)

_LOCAL_CLOSURE_REQUIREMENTS = (
    {
        "requirement_id": "LOCAL-REL-01",
        "area": "RELEASE_HARDENING",
        "assertion": "locked reproducibility, SBOM, supply-chain and CI gates are implemented",
        "state": "IMPLEMENTED_LOCAL",
        "source_refs": (
            "pyproject.toml",
            "requirements.lock",
            "scripts/verify_reproducibility.py",
            "scripts/generate_sbom.py",
            "scripts/verify_supply_chain.py",
            ".github/workflows/pmiri.yml",
        ),
        "report_refs": (),
        "verification": "verify_reproducibility.py --check-installed; generate_sbom.py --check; CI workflow contract",
        "next_action": "re-run the same gates in the authorized deployment build environment",
    },
    {
        "requirement_id": "LOCAL-CANDIDATE-01",
        "area": "DEPLOYABLE_LOCAL_CANDIDATE",
        "assertion": "loopback API, health/metrics/audit, SQLite recovery and operations controls are implemented",
        "state": "CANDIDATE_VERIFIED_LOCAL",
        "source_refs": (
            "pmiri/server.py",
            "pmiri/http_api.py",
            "pmiri/deployment_smoke.py",
            "OPERATIONS_RUNBOOK.md",
        ),
        "report_refs": (
            "artifacts/deployment-smoke-report.json",
            "artifacts/deployment-readiness-report.json",
        ),
        "verification": "deployment-smoke; source test suite; integrity",
        "next_action": "repeat migration, restore and failover rehearsal with deployment-owned services",
    },
    {
        "requirement_id": "LOCAL-SECURITY-01",
        "area": "SECURITY_DEPLOYMENT_ADAPTERS",
        "assertion": "authorization, revocation, epoch, encryption, TLS seam and fail-closed transport controls are implemented",
        "state": "CANDIDATE_VERIFIED_LOCAL",
        "source_refs": (
            "pmiri/request_auth.py",
            "pmiri/control_plane.py",
            "pmiri/storage_crypto.py",
            "pmiri/transports.py",
            "pmiri/gate_d.py",
        ),
        "report_refs": (
            "artifacts/gate-d-runtime-smoke-report.json",
            "artifacts/deployment-readiness-report.json",
        ),
        "verification": "source test suite; Gate-D runtime smoke; transport binding tests",
        "next_action": "replace local adapters with approved deployed identity, distributed coordination and key escrow",
    },
    {
        "requirement_id": "LOCAL-VERIFICATION-01",
        "area": "VERIFICATION_HANDOFF",
        "assertion": "sealed candidate, pinned local handlers, review package and clean-room handoff are materialized",
        "state": "READY_FOR_EXTERNAL_REVIEW",
        "source_refs": (
            "pmiri/sealing.py",
            "pmiri/handoff.py",
            "pmiri/review_package.py",
            "pmiri/r_fc_handlers.py",
        ),
        "report_refs": (
            "artifacts/r-fc-handler-manifest.json",
            "artifacts/r-fc-local-handler-candidate-report.json",
        ),
        "verification": "review-package; seal verification; handoff verification",
        "next_action": "transfer the fresh handoff to the authorized clean-room and obtain independent review",
    },
)

_EXTERNAL_CLOSURE_ACTIONS = (
    {
        "requirement_id": "EXT-01",
        "area": "INDEPENDENT_CLEAN_ROOM",
        "assertion": "independently observed OS/filesystem/network isolation attestation",
        "required_result": "READY",
        "evidence_boundary": "AUTHORIZED_DEPLOYMENT_AND_INDEPENDENT_REVIEW_REQUIRED",
        "report_refs": ("artifacts/preflight-record.json", "artifacts/deployment-readiness-report.json"),
        "next_action": "run PF-01..PF-16 in the authorized clean-room and provide signed attestation",
    },
    {
        "requirement_id": "EXT-02",
        "area": "DEPLOYED_IDENTITY_PROVIDER",
        "assertion": "deployed identity and revocation service is independently observed",
        "required_result": "READY",
        "evidence_boundary": "AUTHORIZED_DEPLOYMENT_AND_INDEPENDENT_REVIEW_REQUIRED",
        "report_refs": ("artifacts/deployment-readiness-report.json",),
        "next_action": "inject the approved identity/revocation adapter and provide signed deployment evidence",
    },
    {
        "requirement_id": "EXT-03",
        "area": "DISTRIBUTED_CONTROL_PLANE",
        "assertion": "distributed control-plane consistency and failover are independently observed",
        "required_result": "READY",
        "evidence_boundary": "AUTHORIZED_DEPLOYMENT_AND_INDEPENDENT_REVIEW_REQUIRED",
        "report_refs": ("artifacts/deployment-readiness-report.json", "artifacts/final-acceptance-gate.json"),
        "next_action": "run multi-node epoch/revocation/replay/rate-limit failover and supply signed evidence",
    },
    {
        "requirement_id": "EXT-04",
        "area": "METADATA_ENCRYPTION_AND_KEY_ESCROW",
        "assertion": "metadata/volume encryption and approved key escrow lifecycle are independently observed",
        "required_result": "READY",
        "evidence_boundary": "AUTHORIZED_DEPLOYMENT_AND_INDEPENDENT_REVIEW_REQUIRED",
        "report_refs": ("artifacts/deployment-readiness-report.json", "artifacts/final-acceptance-gate.json"),
        "next_action": "exercise deployment KMS/DPAPI key creation, rotation, escrow and restore evidence",
    },
    {
        "requirement_id": "EXT-05",
        "area": "REAL_PROVIDER_CONNECTOR_AUTHORIZATION",
        "assertion": "authorized provider/connector, credential, DNS/TLS and network execution is independently observed",
        "required_result": "READY",
        "evidence_boundary": "AUTHORIZED_DEPLOYMENT_AND_INDEPENDENT_REVIEW_REQUIRED",
        "report_refs": ("artifacts/deployment-readiness-report.json", "artifacts/final-acceptance-gate.json"),
        "next_action": "perform the approved real endpoint run with selected-address pinning and TLS/revalidation evidence",
    },
    {
        "requirement_id": "EXT-06",
        "area": "INDEPENDENT_GATE_D_RECHECK",
        "assertion": "independent Gate-D R2 recheck and acceptance evidence",
        "required_result": "READY",
        "evidence_boundary": "AUTHORIZED_DEPLOYMENT_AND_INDEPENDENT_REVIEW_REQUIRED",
        "report_refs": ("artifacts/gate-d-runtime-smoke-report.json", "artifacts/deployment-readiness-report.json"),
        "next_action": "have an independent reviewer recheck Gate-D and sign the external evidence bundle",
    },
)

_FINAL_CLOSURE_ACTIONS = (
    {
        "requirement_id": "FA-01",
        "area": "DEPLOYMENT_READINESS",
        "assertion": "readiness is DEPLOYMENT_READY and EXT-01..EXT-06 are READY",
        "report_refs": ("artifacts/deployment-readiness-report.json",),
        "next_action": "complete EXT-01..EXT-06 and rerun readiness",
    },
    {
        "requirement_id": "FA-02",
        "area": "D2_CONTROLLED_ACCEPTANCE",
        "assertion": "34 controlled D2 scenarios are accepted",
        "report_refs": ("artifacts/d2-runtime-candidate-report.json", "artifacts/final-acceptance-gate.json"),
        "next_action": "run the 34 scenarios in the authorized controlled environment and obtain signed acceptance",
    },
    {
        "requirement_id": "FA-03",
        "area": "R_FC_17_OF_17_PASS",
        "assertion": "all 17 R-FC obligations pass under controlled replay",
        "report_refs": ("artifacts/r-fc-blocked-candidate-report.json", "artifacts/final-acceptance-gate.json"),
        "next_action": "run all pinned handlers with clean-room attestation and independent review",
    },
    {
        "requirement_id": "FA-04",
        "area": "MIGRATION_RESTORE_FAILOVER_ACCEPTED",
        "assertion": "migration, restore and failover are accepted",
        "report_refs": ("artifacts/deployment-smoke-report.json", "artifacts/final-acceptance-gate.json"),
        "next_action": "repeat the rehearsal against deployment-owned storage and control-plane services",
    },
    {
        "requirement_id": "FA-05",
        "area": "INDEPENDENT_D2_R_FC_REVIEW",
        "assertion": "independent D2 and R-FC review is accepted",
        "report_refs": ("artifacts/r-fc-local-handler-candidate-report.json", "artifacts/final-acceptance-gate.json"),
        "next_action": "obtain distinct reviewer identity, signed review record and evidence binding",
    },
    {
        "requirement_id": "FA-06",
        "area": "OPERATIONS_APPROVAL",
        "assertion": "operations owner approves promotion",
        "report_refs": ("artifacts/final-acceptance-gate.json",),
        "next_action": "record deployment-owner approval in the separately signed final evidence bundle",
    },
)


class ReviewPackageError(ValueError):
    """Raised when the local candidate cannot produce a review package."""


def _read_json(root: Path, relative: str) -> tuple[dict[str, Any], bytes]:
    path = root / relative
    try:
        raw = path.read_bytes()
        data = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReviewPackageError("review_report_invalid:" + relative) from exc
    if not isinstance(data, dict):
        raise ReviewPackageError("review_report_shape_invalid:" + relative)
    return data, raw


def _artifact_summary(relative: str, data: Mapping[str, Any], raw: bytes) -> dict[str, Any]:
    return {
        "path": relative,
        "sha256": sha256_bytes(raw),
        "artifact_kind": data.get("artifact_kind", data.get("report_type", "UNDECLARED")),
        "status": data.get("status", data.get("overall_result", "UNDECLARED")),
        "report_fingerprint": data.get("report_fingerprint"),
    }


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ReviewPackageError(reason)


def _build_closure_matrix(
    root: Path,
    *,
    external_results: Mapping[str, str],
    final_results: Mapping[str, str],
) -> dict[str, list[dict[str, Any]]]:
    """Build the explicit local/external/final closure plan for handoff."""
    local_candidate: list[dict[str, Any]] = []
    for item in _LOCAL_CLOSURE_REQUIREMENTS:
        source_refs = list(item["source_refs"])
        report_refs = list(item["report_refs"])
        _require(all((root / ref).is_file() for ref in source_refs), "closure_source_missing:" + item["requirement_id"])
        _require(all((root / ref).is_file() for ref in report_refs), "closure_report_missing:" + item["requirement_id"])
        local_candidate.append(
            {
                "requirement_id": item["requirement_id"],
                "area": item["area"],
                "assertion": item["assertion"],
                "state": item["state"],
                "source_refs": source_refs,
                "report_refs": report_refs,
                "verification": item["verification"],
                "next_action": item["next_action"],
            }
        )

    external_readiness: list[dict[str, Any]] = []
    for item in _EXTERNAL_CLOSURE_ACTIONS:
        external_readiness.append(
            {
                "requirement_id": item["requirement_id"],
                "area": item["area"],
                "assertion": item["assertion"],
                "state": "BLOCKED_EXTERNAL" if external_results.get(item["requirement_id"]) != "READY" else "READY_EXTERNAL",
                "observed_result": external_results.get(item["requirement_id"], "MISSING"),
                "required_result": item["required_result"],
                "evidence_boundary": item["evidence_boundary"],
                "report_refs": list(item["report_refs"]),
                "next_action": item["next_action"],
            }
        )

    final_acceptance: list[dict[str, Any]] = []
    for item in _FINAL_CLOSURE_ACTIONS:
        observed = final_results.get(item["requirement_id"], "MISSING")
        final_acceptance.append(
            {
                "requirement_id": item["requirement_id"],
                "area": item["area"],
                "assertion": item["assertion"],
                "state": "BLOCKED_EXTERNAL" if observed != "READY" else "READY_EXTERNAL",
                "observed_result": observed,
                "required_result": "READY",
                "evidence_boundary": "AUTHORIZED_DEPLOYMENT_AND_INDEPENDENT_REVIEW_REQUIRED",
                "report_refs": list(item["report_refs"]),
                "next_action": item["next_action"],
            }
        )
    return {
        "local_candidate": local_candidate,
        "external_readiness": external_readiness,
        "final_acceptance": final_acceptance,
    }


def _validate_closure_matrix(matrix: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(matrix, Mapping) or set(matrix) != {"local_candidate", "external_readiness", "final_acceptance"}:
        return ["closure_matrix_shape_invalid"]

    local = matrix.get("local_candidate")
    expected_local_ids = [item["requirement_id"] for item in _LOCAL_CLOSURE_REQUIREMENTS]
    if not isinstance(local, list) or [item.get("requirement_id") for item in local if isinstance(item, Mapping)] != expected_local_ids:
        errors.append("local_closure_requirements_invalid")
    else:
        for item, expected in zip(local, _LOCAL_CLOSURE_REQUIREMENTS):
            if any(
                item.get(key) != (list(expected[key]) if key in {"source_refs", "report_refs"} else expected[key])
                for key in ("area", "assertion", "state", "source_refs", "report_refs", "verification", "next_action")
            ):
                errors.append("local_closure_entry_mismatch")

    external = matrix.get("external_readiness")
    expected_external_ids = [item["requirement_id"] for item in _EXTERNAL_CLOSURE_ACTIONS]
    if not isinstance(external, list) or [item.get("requirement_id") for item in external if isinstance(item, Mapping)] != expected_external_ids:
        errors.append("external_closure_requirements_invalid")
    else:
        for item, expected in zip(external, _EXTERNAL_CLOSURE_ACTIONS):
            if any(
                item.get(key) != (list(expected[key]) if key == "report_refs" else expected[key])
                for key in ("area", "assertion", "required_result", "evidence_boundary", "report_refs", "next_action")
            ):
                errors.append("external_closure_contract_invalid")
            if item.get("state") not in {"BLOCKED_EXTERNAL", "READY_EXTERNAL"} or (item.get("state") == "READY_EXTERNAL") != (item.get("observed_result") == "READY"):
                errors.append("external_closure_state_invalid")

    final = matrix.get("final_acceptance")
    expected_final_ids = [item["requirement_id"] for item in _FINAL_CLOSURE_ACTIONS]
    if not isinstance(final, list) or [item.get("requirement_id") for item in final if isinstance(item, Mapping)] != expected_final_ids:
        errors.append("final_closure_requirements_invalid")
    else:
        for item, expected in zip(final, _FINAL_CLOSURE_ACTIONS):
            if any(
                item.get(key) != (list(expected[key]) if key == "report_refs" else expected[key])
                for key in ("area", "assertion", "report_refs", "next_action")
            ):
                errors.append("final_closure_contract_invalid")
            if item.get("state") not in {"BLOCKED_EXTERNAL", "READY_EXTERNAL"} or item.get("required_result") != "READY" or item.get("evidence_boundary") != "AUTHORIZED_DEPLOYMENT_AND_INDEPENDENT_REVIEW_REQUIRED" or (item.get("state") == "READY_EXTERNAL") != (item.get("observed_result") == "READY"):
                errors.append("final_closure_state_invalid")
    return errors


def build_review_package(project_root: str | Path) -> dict[str, Any]:
    """Build a bounded, fingerprinted review inventory from local reports."""
    root = Path(project_root).resolve()
    reports: dict[str, dict[str, Any]] = {}
    raw_reports: dict[str, bytes] = {}
    for relative in _REPORT_PATHS:
        reports[relative], raw_reports[relative] = _read_json(root, relative)

    readiness = reports["artifacts/deployment-readiness-report.json"]
    readiness_errors = validate_readiness_report(readiness)
    _require(not readiness_errors, "readiness_report_invalid:" + str(readiness_errors[0]) if readiness_errors else "")

    preflight = reports["artifacts/preflight-record.json"]
    s0 = reports["artifacts/s0-acceptance-report.json"]
    d2_matrix = reports["artifacts/d2-matrix-report.json"]
    d2_runtime = reports["artifacts/d2-runtime-candidate-report.json"]
    gate_d = reports["artifacts/gate-d-runtime-smoke-report.json"]
    rfc_blocked = reports["artifacts/r-fc-blocked-candidate-report.json"]
    rfc_local = reports["artifacts/r-fc-local-handler-candidate-report.json"]
    handler_manifest = reports["artifacts/r-fc-handler-manifest.json"]
    recovery = reports["artifacts/deployment-smoke-report.json"]
    final_gate = reports["artifacts/final-acceptance-gate.json"]

    preflight_checks = preflight.get("checks")
    _require(isinstance(preflight_checks, list) and len(preflight_checks) == 16, "preflight_inventory_incomplete")
    preflight_errors = validate_preflight_record_shape(preflight)
    _require(not preflight_errors, "preflight_record_invalid:" + preflight_errors[0] if preflight_errors else "")
    d2_cases = d2_runtime.get("cases")
    _require(isinstance(d2_cases, list) and len(d2_cases) == 34 and d2_runtime.get("all_oracles_match") is True, "d2_runtime_inventory_incomplete")
    _require(d2_matrix.get("scenario_count") == 34, "d2_matrix_inventory_incomplete")
    _require(s0.get("artifact_kind") == "PMIRI-V1-S0-ACCEPTANCE-REPORT" and isinstance(s0.get("cases"), list) and len(s0["cases"]) == 12, "s0_inventory_incomplete")
    _require(rfc_blocked.get("blocked_case_count") == 17 and rfc_blocked.get("executed_case_count") == 0 and rfc_blocked.get("r_fc_pass") == "NONE", "rfc_blocked_inventory_invalid")
    _require(rfc_local.get("selected_case_count") == 34 and rfc_local.get("executed_case_count") == 34 and rfc_local.get("oracle_match_count") == 34 and rfc_local.get("all_oracles_match") is True and rfc_local.get("r_fc_pass") == "NONE", "rfc_local_inventory_incomplete")
    _require(handler_manifest.get("status") == "READY_FOR_REPLAY" and isinstance(handler_manifest.get("case_ids"), list) and len(handler_manifest["case_ids"]) == 34, "handler_manifest_incomplete")
    _require(recovery.get("external_access") == "NOT_PERFORMED", "recovery_report_claims_external_access")
    _require(gate_d.get("external_network_access") == "NOT_PERFORMED" and gate_d.get("external_provider_access") == "NOT_PERFORMED", "gate_d_report_claims_external_access")
    final_gate_errors = validate_final_acceptance_report(final_gate, project_root=root)
    _require(not final_gate_errors, "final_acceptance_gate_invalid:" + final_gate_errors[0] if final_gate_errors else "")

    checks = readiness.get("checks", [])
    external_results = {str(item.get("check_id")): str(item.get("result")) for item in checks if isinstance(item, Mapping) and str(item.get("check_id", "")).startswith("EXT-")}
    final_results = {str(item.get("check_id")): str(item.get("result")) for item in final_gate.get("checks", []) if isinstance(item, Mapping)}
    closure_matrix = _build_closure_matrix(root, external_results=external_results, final_results=final_results)
    external_actions = [
        {
            "check_id": check_id,
            "assertion": assertion,
            "required_result": "READY",
            "observed_result": external_results.get(check_id, "MISSING"),
            "evidence_boundary": "AUTHORIZED_DEPLOYMENT_AND_INDEPENDENT_REVIEW_REQUIRED",
        }
        for check_id, assertion in EXTERNAL_REQUIREMENTS
    ]
    package: dict[str, Any] = {
        "artifact_kind": REVIEW_PACKAGE_KIND,
        "artifact_version": REVIEW_PACKAGE_VERSION,
        "status": REVIEW_PACKAGE_STATUS,
        "scope": "LOCAL_CANDIDATE_AND_EXTERNAL_REVIEW_CHECKLIST",
        "external_execution": "NOT_PERFORMED",
        "promotion_result": readiness.get("overall_result"),
        "captured_at": readiness.get("captured_at"),
        "profile_id": readiness.get("profile_id"),
        "profile_fingerprint": readiness.get("profile_fingerprint"),
        "authority_fingerprint": readiness.get("authority_fingerprint"),
        "acceptance_inventory": {
            "preflight": {
                "required_checks": 16,
                "observed_checks": len(preflight_checks),
                "overall_result": preflight.get("overall_result"),
                "check_results": [{"check_id": item.get("check_id"), "status": item.get("status")} for item in preflight_checks if isinstance(item, Mapping)],
            },
            "s0": {"required_cases": 12, "observed_cases": len(s0["cases"]), "status": s0.get("status")},
            "d2": {"required_scenarios": 34, "observed_scenarios": len(d2_cases), "oracle_match": d2_runtime.get("all_oracles_match"), "runtime_execution": d2_runtime.get("runtime_execution"), "acceptance": d2_runtime.get("d2_acceptance")},
            "r_fc": {"required_obligations": 17, "blocked_obligations": rfc_blocked.get("blocked_case_count"), "pass": rfc_blocked.get("r_fc_pass"), "runtime_execution": rfc_blocked.get("runtime_execution")},
            "local_r_fc_handlers": {"required_cases": 34, "executed_cases": rfc_local.get("executed_case_count"), "oracle_matches": rfc_local.get("oracle_match_count"), "status": rfc_local.get("status"), "pass": rfc_local.get("r_fc_pass")},
            "deployment_recovery": {"status": recovery.get("status"), "external_access": recovery.get("external_access"), "readiness_status": recovery.get("readiness_status"), "source_count": recovery.get("source_count")},
            "readiness": {"overall_result": readiness.get("overall_result"), "blocked_checks": [item.get("check_id") for item in checks if isinstance(item, Mapping) and item.get("result") == "BLOCKED"]},
            "final_acceptance": {"overall_result": final_gate.get("overall_result"), "blocked_checks": [item.get("check_id") for item in final_gate.get("checks", []) if isinstance(item, Mapping) and item.get("result") == "BLOCKED"], "external_evidence_status": final_gate.get("external_evidence_status")},
        },
            "evidence_inventory": [_artifact_summary(relative, reports[relative], raw_reports[relative]) for relative in _REPORT_PATHS],
        "closure_matrix": closure_matrix,
        "external_actions": external_actions,
        "independent_review": {"required": True, "status": "NOT_SUPPLIED"},
        "local_candidate_non_claims": ["NO_EXTERNAL_ATTESTATION", "NO_PRODUCTION_AUTHORIZATION", "NO_D2_ACCEPTANCE", "NO_R_FC_PASS"],
    }
    package["review_package_fingerprint"] = sha256_json(package)
    return package


def validate_review_package(package: Mapping[str, Any], *, project_root: str | Path | None = None) -> tuple[str, ...]:
    """Validate package shape, self-fingerprint and optional on-disk inputs."""
    errors: list[str] = []
    required = {
        "artifact_kind", "artifact_version", "status", "scope", "external_execution", "promotion_result", "captured_at",
        "profile_id", "profile_fingerprint", "authority_fingerprint", "acceptance_inventory", "evidence_inventory", "closure_matrix",
        "external_actions", "independent_review", "local_candidate_non_claims", "review_package_fingerprint",
    }
    if set(package) != required:
        errors.append("fields_invalid")
    if package.get("artifact_kind") != REVIEW_PACKAGE_KIND or package.get("artifact_version") != REVIEW_PACKAGE_VERSION or package.get("status") != REVIEW_PACKAGE_STATUS:
        errors.append("identity_invalid")
    if package.get("external_execution") != "NOT_PERFORMED":
        errors.append("external_execution_claim_invalid")
    if not is_sha256(package.get("profile_fingerprint")) or not is_sha256(package.get("authority_fingerprint")):
        errors.append("binding_fingerprint_invalid")
    unsigned = {key: value for key, value in package.items() if key != "review_package_fingerprint"}
    if package.get("review_package_fingerprint") != sha256_json(unsigned):
        errors.append("self_fingerprint_mismatch")

    if project_root is not None:
        try:
            expected = build_review_package(project_root)
        except ReviewPackageError as exc:
            errors.append("project_inputs_invalid:" + str(exc))
        else:
            expected_unsigned = {key: value for key, value in expected.items() if key != "review_package_fingerprint"}
            if unsigned != expected_unsigned:
                errors.append("project_binding_mismatch")

    inventory = package.get("evidence_inventory")
    if not isinstance(inventory, list) or [item.get("path") for item in inventory if isinstance(item, Mapping)] != list(_REPORT_PATHS):
        errors.append("evidence_inventory_invalid")
    else:
        for item in inventory:
            if not isinstance(item, Mapping) or not is_sha256(item.get("sha256")):
                errors.append("evidence_inventory_entry_invalid")
                continue
            if project_root is not None:
                path = Path(project_root).resolve() / str(item["path"])
                try:
                    if sha256_bytes(path.read_bytes()) != item["sha256"]:
                        errors.append("evidence_inventory_fingerprint_mismatch:" + str(item["path"]))
                except OSError:
                    errors.append("evidence_inventory_missing:" + str(item["path"]))

    errors.extend(_validate_closure_matrix(package.get("closure_matrix")))

    actions = package.get("external_actions")
    expected_ids = [check_id for check_id, _ in EXTERNAL_REQUIREMENTS]
    if not isinstance(actions, list) or [item.get("check_id") for item in actions if isinstance(item, Mapping)] != expected_ids:
        errors.append("external_actions_invalid")
    elif any(item.get("required_result") != "READY" or item.get("evidence_boundary") != "AUTHORIZED_DEPLOYMENT_AND_INDEPENDENT_REVIEW_REQUIRED" for item in actions):
        errors.append("external_action_contract_invalid")
    if package.get("independent_review") != {"required": True, "status": "NOT_SUPPLIED"}:
        errors.append("independent_review_state_invalid")
    return tuple(errors)


def write_review_package(package: Mapping[str, Any], output_path: str | Path) -> dict[str, Any]:
    """Write a canonical review package and return its JSON mapping."""
    errors = validate_review_package(package)
    if errors:
        raise ReviewPackageError("review_package_invalid:" + errors[0])
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(package) + b"\n")
    return dict(package)


__all__ = [
    "REVIEW_PACKAGE_KIND",
    "REVIEW_PACKAGE_STATUS",
    "REVIEW_PACKAGE_VERSION",
    "ReviewPackageError",
    "build_review_package",
    "validate_review_package",
    "write_review_package",
]
