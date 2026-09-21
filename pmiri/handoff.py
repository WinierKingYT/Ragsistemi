"""Materialized, fingerprinted clean-room handoff bundle for local evidence."""

from __future__ import annotations

import json
import shutil
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping

from .canonical import canonical_json, is_sha256, sha256_bytes, sha256_json, utc_now


HANDOFF_KIND = "PMIRI-CLEAN-ROOM-HANDOFF-BUNDLE"
HANDOFF_VERSION = "0.1"
HANDOFF_STATUS = "HANDOFF_READY_FOR_EXTERNAL_REVIEW"

_STATIC_FILES = (
    "requirements.lock",
    "pyproject.toml",
    ".github/workflows/pmiri.yml",
    "deployment-profile.example.json",
    "README.md",
    "IMPLEMENTATION_PLAN.md",
    "IMPLEMENTATION_STATUS.md",
    "TECHNOLOGY_DECISIONS.md",
    "OPERATIONS_RUNBOOK.md",
    "EXTERNAL_CLOSURE_CHECKLIST.md",
    "PMIRI_ALL_DOCUMENTATION_CHECKPOINT_17/CHECKSUMS_SHA256.txt",
    "PMIRI_ALL_DOCUMENTATION_CHECKPOINT_17/ARCHIVE_SOURCES/PMIRI_v1.0_Gate_C_Accepted.zip",
    "PMIRI_ALL_DOCUMENTATION_CHECKPOINT_17/ARCHIVE_SOURCES/PMIRI_v1.1.1_Gate_D_R1_Accepted.zip",
    "artifacts/local-runner-identity.json",
    "artifacts/preflight-record.json",
    "artifacts/s0-acceptance-report.json",
    "artifacts/d2-matrix-report.json",
    "artifacts/d2-runtime-candidate-report.json",
    "artifacts/gate-d-runtime-smoke-report.json",
    "artifacts/r-fc-blocked-candidate-report.json",
    "artifacts/r-fc-local-handler-candidate-report.json",
    "artifacts/r-fc-handler-manifest.json",
    "artifacts/review-package.json",
    "artifacts/deployment-readiness-report.json",
    "artifacts/final-acceptance-gate.json",
    "artifacts/deployment-smoke-report.json",
    "artifacts/sbom/pmiri-sbom.spdx.json",
    "artifacts/sealed/s0-acceptance/artifact-manifest.json",
)
_SOURCE_DIRECTORIES = (
    "pmiri",
    "tests",
    "scripts",
    "deployment/vm",
    "fixtures/s0/project-alpha",
    "PMIRI_ALL_DOCUMENTATION_CHECKPOINT_17/GC-C1",
    "PMIRI_ALL_DOCUMENTATION_CHECKPOINT_17/GATE-D-R2",
)
_EXTERNAL_ACTIONS = (
    "supply_independent_clean_room_attestation",
    "supply_ready_for_replay_preflight_per_case",
    "supply_verified_external_replay_observations",
    "supply_independent_gate_d_r2_review",
    "supply_independent_r_fc_review",
)


class HandoffError(ValueError):
    """Raised when a handoff destination or payload is invalid."""


def _relative(value: str | Path) -> str:
    return PurePosixPath(str(value).replace("\\", "/")).as_posix()


def _safe_payload_path(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("payload/"):
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and ".." not in path.parts


def _safe_source_path(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and ".." not in path.parts


def _collect_sources(root: Path) -> tuple[tuple[str, Path], ...]:
    selected: dict[str, Path] = {}
    for relative in _STATIC_FILES:
        path = root / relative
        if not path.is_file():
            raise HandoffError("handoff_source_missing:" + relative)
        selected[relative] = path
    for directory in _SOURCE_DIRECTORIES:
        base = root / directory
        if not base.is_dir():
            raise HandoffError("handoff_source_directory_missing:" + directory)
        for path in base.rglob("*"):
            if not path.is_file() or path.is_symlink() or "__pycache__" in path.parts or path.suffix.casefold() == ".pyc":
                continue
            relative = path.relative_to(root).as_posix()
            selected[relative] = path
    return tuple((relative, selected[relative]) for relative in sorted(selected))


def _role(relative: str) -> str:
    normalized = relative.casefold()
    if normalized.startswith("pmiri/"):
        return "implementation_source"
    if normalized.startswith("tests/"):
        return "verification_source"
    if normalized.startswith("scripts/"):
        return "verification_tool"
    if normalized.startswith("fixtures/"):
        return "synthetic_fixture"
    if "/gc-c1/" in normalized:
        return "gc_c1_authority"
    if "/gate-d-r2/" in normalized:
        return "gate_d_authority"
    if normalized.endswith("requirements.lock") or normalized.endswith("pyproject.toml"):
        return "reproducibility_contract"
    if normalized.startswith("artifacts/"):
        return "candidate_evidence"
    return "handoff_contract"


def _preflight_status(root: Path) -> str:
    try:
        data = json.loads((root / "artifacts/preflight-record.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return "UNAVAILABLE"
    return str(data.get("overall_result", "UNAVAILABLE"))


def create_handoff_bundle(
    project_root: str | Path,
    output_dir: str | Path,
    *,
    selected_fixture_id: str = "GC-C1-FC01",
    selected_case_id: str = "GC-C1-FC01-P",
) -> dict[str, Any]:
    """Copy the local candidate inputs into a new, independently verifiable bundle."""
    root = Path(project_root).resolve()
    destination = Path(output_dir).resolve()
    if destination == root or root not in destination.parents:
        raise HandoffError("handoff_destination_must_be_inside_project")
    if destination.exists():
        raise HandoffError("handoff_destination_exists")
    sources = _collect_sources(root)
    payload_root = destination / "payload"
    entries: list[dict[str, Any]] = []
    for relative, source in sources:
        payload_path = payload_root / relative
        payload_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, payload_path)
        entries.append({
            "source_path": relative,
            "payload_path": "payload/" + relative,
            "role": _role(relative),
            "byte_length": payload_path.stat().st_size,
            "sha256": sha256_bytes(payload_path.read_bytes()),
        })
    unsigned: dict[str, Any] = {
        "artifact_kind": HANDOFF_KIND,
        "artifact_version": HANDOFF_VERSION,
        "status": HANDOFF_STATUS,
        "created_at": utc_now(),
        "selected_fixture_id": selected_fixture_id,
        "selected_case_id": selected_case_id,
        "payload_policy": "SYNTHETIC_INPUTS_ONLY",
        "external_execution": "NOT_PERFORMED",
        "preflight_status": _preflight_status(root),
        "review_status": "NOT_SUPPLIED",
        "required_external_actions": list(_EXTERNAL_ACTIONS),
        "entries": entries,
    }
    unsigned["handoff_fingerprint"] = sha256_json(unsigned)
    manifest_path = destination / "handoff-manifest.json"
    manifest_path.write_bytes(canonical_json(unsigned) + b"\n")
    valid, reason = verify_handoff(manifest_path, project_root=root)
    if not valid:
        raise HandoffError("handoff_self_verification_failed:" + reason)
    return {**unsigned, "manifest_path": manifest_path.as_posix(), "payload_count": len(entries)}


def verify_handoff(manifest_path: str | Path, *, project_root: str | Path | None = None) -> tuple[bool, str]:
    """Verify a handoff and optionally bind it to the current source tree."""
    path = Path(manifest_path).resolve()
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False, "manifest_invalid"
    required = {
        "artifact_kind", "artifact_version", "status", "created_at", "selected_fixture_id",
        "selected_case_id", "payload_policy", "external_execution", "preflight_status",
        "review_status", "required_external_actions", "entries", "handoff_fingerprint",
    }
    if set(manifest) != required:
        return False, "manifest_shape_invalid"
    if manifest.get("artifact_kind") != HANDOFF_KIND or manifest.get("artifact_version") != HANDOFF_VERSION:
        return False, "manifest_identity_invalid"
    if manifest.get("status") != HANDOFF_STATUS or manifest.get("external_execution") != "NOT_PERFORMED":
        return False, "handoff_status_invalid"
    if manifest.get("payload_policy") != "SYNTHETIC_INPUTS_ONLY" or manifest.get("review_status") != "NOT_SUPPLIED":
        return False, "handoff_policy_invalid"
    actions = manifest.get("required_external_actions")
    if actions != list(_EXTERNAL_ACTIONS):
        return False, "external_action_inventory_invalid"
    claimed = manifest.get("handoff_fingerprint")
    unsigned = {key: value for key, value in manifest.items() if key != "handoff_fingerprint"}
    if not is_sha256(claimed) or claimed != sha256_json(unsigned):
        return False, "manifest_fingerprint_mismatch"
    entries = manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        return False, "entries_invalid"
    payload_paths: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"source_path", "payload_path", "role", "byte_length", "sha256"}:
            return False, "entry_shape_invalid"
        payload_value = entry["payload_path"]
        if not _safe_payload_path(payload_value) or payload_value in payload_paths:
            return False, "entry_path_invalid_or_duplicate"
        payload_paths.add(payload_value)
        if not isinstance(entry["source_path"], str) or not entry["source_path"] or not isinstance(entry["role"], str) or not entry["role"]:
            return False, "entry_identity_invalid"
        if not isinstance(entry["byte_length"], int) or entry["byte_length"] < 0 or not is_sha256(entry["sha256"]):
            return False, "entry_fingerprint_invalid"
        payload = (path.parent / payload_value).resolve()
        if path.parent not in payload.parents or not payload.is_file():
            return False, "payload_missing_or_outside_bundle"
        if payload.stat().st_size != entry["byte_length"] or sha256_bytes(payload.read_bytes()) != entry["sha256"]:
            return False, "payload_fingerprint_mismatch:" + payload_value
    actual_paths = {
        candidate.relative_to(path.parent).as_posix()
        for candidate in (path.parent / "payload").rglob("*")
        if candidate.is_file()
    } if (path.parent / "payload").is_dir() else set()
    if actual_paths != payload_paths:
        return False, "payload_inventory_mismatch"
    if project_root is not None:
        root = Path(project_root).resolve()
        source_paths: set[str] = set()
        for entry in entries:
            source_value = entry["source_path"]
            if not _safe_source_path(source_value):
                return False, "source_path_invalid"
            source_paths.add(source_value)
            source = root.joinpath(*PurePosixPath(source_value).parts)
            if source.is_symlink() or not source.is_file():
                return False, "current_source_missing_or_symlink:" + source_value
            if source.stat().st_size != entry["byte_length"] or sha256_bytes(source.read_bytes()) != entry["sha256"]:
                return False, "current_source_fingerprint_mismatch:" + source_value
        try:
            expected_sources = {relative for relative, _ in _collect_sources(root)}
        except HandoffError as exc:
            return False, "current_source_inventory_unavailable:" + str(exc)
        if source_paths != expected_sources:
            return False, "current_source_inventory_mismatch"
    return True, "VERIFIED"


__all__ = ["HANDOFF_KIND", "HANDOFF_STATUS", "HANDOFF_VERSION", "HandoffError", "create_handoff_bundle", "verify_handoff"]
