"""Case-scoped artifact manifest and deterministic sealing.

``verify_seal`` proves byte-level integrity only.  A manifest may still be
``INCOMPLETE`` when external environment, privacy or independent-review roles
are absent; that distinction is retained in the manifest itself.
"""

from __future__ import annotations

import json
from pathlib import Path

from .canonical import canonical_json, sha256_bytes, sha256_json, utc_now


REQUIRED_ROLES = (
    "runner_source",
    "runner_manifest",
    "authority_bundle",
    "evidence_schema",
    "fixture_catalog",
    "preflight_matrix",
    "preflight_spec",
    "preflight_contract",
    "preflight_record_schema",
    "selected_fixture",
    "selected_case",
    "preflight_record",
    "environment_evidence",
    "privacy_record",
    "review_attestation",
    "seal_attestation",
)

# Workspace analysis and interpreter caches are not case evidence.  Excluding
# them keeps a previously sealed case stable when a developer refreshes the
# local knowledge graph or runs the test suite afterwards.
_NON_EVIDENCE_DIRECTORIES = {
    ".git",
    "graphify-out",
    ".codebase-memory",
    ".pytest_cache",
    ".mypy_cache",
    ".pmiri-sqlite",
    ".pmiri-control",
    "build",
    "pmiri.egg-info",
    ".venv",
    "venv",
}
_NON_EVIDENCE_FILES = {
    "artifacts/deployment-readiness-report.json",
    "artifacts/deployment-smoke-report.json",
    "artifacts/read-audit.jsonl",
    "artifacts/review-package.json",
}


def _is_non_evidence(path: Path, root: Path) -> bool:
    relative = path.relative_to(root).as_posix()
    return (
        relative in _NON_EVIDENCE_FILES
        or relative.casefold().startswith("artifacts/handoff")
        or relative.casefold().startswith("artifacts/package-")
        or any(
            part in _NON_EVIDENCE_DIRECTORIES
            or part.casefold().startswith(".venv-")
            or part.startswith(".pmiri-deployment-smoke-")
            for part in path.parts
        )
    )


def _role_for_path(relative: str) -> str:
    normalized = relative.casefold()
    if normalized.endswith("pmiri_gc_c1_replay_runner.py"):
        return "runner_source"
    if normalized.endswith("pmiri_gc-c1_replay_runner_0.1.0/runner-manifest.json"):
        return "runner_manifest"
    if normalized.endswith("pmiri_gd-r2_authority_bundle_manifest_v0.1.json"):
        return "authority_bundle"
    if normalized.endswith("pmiri_gc-c1-02_evidence_record.schema.json"):
        return "evidence_schema"
    if normalized.endswith("pmiri_gc-c1-02_replay_fixture_catalog.json"):
        return "fixture_catalog"
    if normalized.endswith("pmiri_gc-c1-05_controlled_preflight_scenario_matrix.json"):
        return "preflight_matrix"
    if normalized.endswith("pmiri_gc-c1-04_preflight_check_spec.json"):
        return "preflight_spec"
    if normalized.endswith("pmiri_gc-c1-04_preflight_validator_contract_v0.1.md"):
        return "preflight_contract"
    if normalized.endswith("pmiri_gc-c1-06_preflight_record.schema.json"):
        return "preflight_record_schema"
    if normalized.startswith("fixtures/") and normalized.endswith((".md", ".txt", ".markdown")):
        return "selected_fixture"
    if normalized.endswith("artifacts/s0-acceptance-report.json"):
        return "selected_case"
    if normalized.endswith("artifacts/preflight-record.json"):
        return "preflight_record"
    return "not_applicable"


def file_sha256(path: str | Path) -> str:
    return sha256_bytes(Path(path).read_bytes())


def seal_directory(root: str | Path, *, case_id: str, output_dir: str | Path | None = None) -> dict:
    root = Path(root).resolve()
    destination = Path(output_dir or root / "artifacts" / case_id).resolve()
    if root not in destination.parents and destination != root:
        raise ValueError("seal_output_outside_root")
    destination.mkdir(parents=True, exist_ok=True)
    entries = []
    present_roles: set[str] = set()
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file() or destination in path.parents or _is_non_evidence(path, root) or "__pycache__" in path.parts or path.suffix.casefold() == ".pyc":
            continue
        relative = path.relative_to(root).as_posix()
        role = _role_for_path(relative)
        present_roles.add(role)
        entries.append({
            "entry_id": "entry_" + sha256_json({"path": relative})[:32],
            "role": role,
            "path": relative,
            "byte_length": path.stat().st_size,
            "sha256": file_sha256(path),
            "presence": "PRESENT",
        })
    for role in REQUIRED_ROLES:
        if role not in present_roles:
            entries.append({
                "entry_id": "entry_" + sha256_json({"role": role, "case_id": case_id})[:32],
                "role": role,
                "presence": "NOT_APPLICABLE",
                "not_applicable_reason": "not supplied by this local candidate bundle",
            })
    entries.sort(key=lambda item: (item.get("path", ""), item["role"], item["entry_id"]))
    captured_at = utc_now()
    complete = all(role in present_roles for role in REQUIRED_ROLES)
    manifest = {
        "bundle_id": "bundle_" + sha256_json({"case_id": case_id, "root": root.as_posix()})[:32],
        "contract_version": "0.1",
        "status": "SEALED" if complete else "INCOMPLETE",
        "created_at": captured_at,
        "sealed_at": captured_at,
        "sealing_procedure_version": "PMIRI-SHA256-CANONICAL-MANIFEST-0.2",
        "entries": entries,
        "required_roles": list(REQUIRED_ROLES),
        "completeness": "COMPLETE" if complete else "INCOMPLETE",
        "invalidation_history": [],
    }
    manifest["manifest_payload_sha256"] = sha256_json(manifest)
    manifest["bundle_sha256"] = sha256_json({"manifest_payload_sha256": manifest["manifest_payload_sha256"], "entries": entries})
    manifest["seal"] = {
        "method": "SHA256_CANONICAL_MANIFEST_V0.1",
        "result": "SEALED" if complete else "UNVERIFIED",
        "attestation_ref": "attestation://not-supplied",
        "review_manifest_sha256": sha256_json({"review": "not-supplied"}),
    }
    manifest_path = destination / "artifact-manifest.json"
    manifest_path.write_bytes(canonical_json(manifest) + b"\n")
    return {**manifest, "manifest_path": manifest_path.as_posix()}


def verify_seal(manifest_path: str | Path, *, root: str | Path | None = None) -> tuple[bool, str]:
    """Recompute every entry and the bundle digest before accepting a seal."""
    path = Path(manifest_path).resolve()
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False, "manifest_invalid"
    if root is not None:
        base = Path(root).resolve()
    elif manifest.get("root"):
        base = Path(manifest["root"]).resolve()
    else:
        entry_paths = [entry.get("path") for entry in manifest.get("entries", []) if entry.get("presence") == "PRESENT" and isinstance(entry.get("path"), str)]
        inferred_root = next(
            (candidate for candidate in path.parents if entry_paths and all((candidate / relative).is_file() for relative in entry_paths)),
            path.parents[2] if len(path.parents) > 2 else path.parent,
        )
        base = inferred_root.resolve()
    claimed_payload = manifest.get("manifest_payload_sha256")
    payload = {key: value for key, value in manifest.items() if key not in {"manifest_payload_sha256", "bundle_sha256", "seal"}}
    if claimed_payload != sha256_json(payload):
        return False, "manifest_payload_fingerprint_mismatch"
    claimed_bundle = manifest.get("bundle_sha256")
    if claimed_bundle != sha256_json({"manifest_payload_sha256": claimed_payload, "entries": manifest.get("entries")}):
        return False, "bundle_fingerprint_mismatch"
    entries = manifest.get("entries")
    if not isinstance(entries, list):
        return False, "entries_invalid"
    entry_ids = [entry.get("entry_id") for entry in entries]
    paths = [entry.get("path") for entry in entries if entry.get("presence") == "PRESENT"]
    if len(entry_ids) != len(set(entry_ids)) or len(paths) != len(set(paths)):
        return False, "entry_identity_duplicate"
    if set(manifest.get("required_roles", [])) != set(REQUIRED_ROLES):
        return False, "required_roles_incomplete"
    listed_paths = set(paths)
    actual_paths: set[str] = set()
    for candidate in base.rglob("*"):
        if candidate.is_symlink() or not candidate.is_file() or path.parent in candidate.parents or _is_non_evidence(candidate, base) or "__pycache__" in candidate.parts or candidate.suffix.casefold() == ".pyc":
            continue
        actual_paths.add(candidate.relative_to(base).as_posix())
    if actual_paths != listed_paths:
        missing = sorted(listed_paths - actual_paths)
        extra = sorted(actual_paths - listed_paths)
        return False, "filesystem_inventory_mismatch:" + ("missing=" + missing[0] if missing else "extra=" + extra[0])
    for entry in manifest.get("entries", []):
        relative = entry.get("path")
        if entry.get("presence") == "NOT_APPLICABLE":
            if entry.get("path") is not None or not entry.get("not_applicable_reason"):
                return False, "not_applicable_entry_invalid"
            continue
        if entry.get("presence") != "PRESENT" or not isinstance(relative, str):
            return False, "entry_path_invalid"
        candidate = (base / relative).resolve()
        if base not in candidate.parents and candidate != base:
            return False, "entry_outside_root"
        if not candidate.is_file() or candidate.stat().st_size != entry.get("byte_length") or file_sha256(candidate) != entry.get("sha256"):
            return False, "entry_fingerprint_mismatch:" + relative
    return True, "SEALED"
