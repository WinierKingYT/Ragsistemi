"""GC-C1 PF-01..PF-16 preflight record generation.

The checks are executable, but a local invocation intentionally stays BLOCKED
unless an authorized, independently observed clean-room environment is
provided. A preflight record is readiness evidence, never an R-FC PASS.
"""

from __future__ import annotations

import json
import posixpath
from zipfile import BadZipFile, ZipFile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

from .canonical import is_sha256, sha256_bytes, sha256_json, utc_now
from .clean_room import DOMAINS, IsolationObservation, verify_attestation


RUNNER_ID = "pmiri-gc-c1-replay"
RUNNER_VERSION = "0.1.0"
CHECKS = (
    ("PF-01", "RUNNER_IDENTITY", "BLOCKED"),
    ("PF-02", "RUNNER_PACKAGE_INTEGRITY", "BLOCKED"),
    ("PF-03", "MANIFEST_INTEGRITY", "VALIDATION_ERROR"),
    ("PF-04", "AUTHORITY_BUNDLE_INTEGRITY", "BLOCKED"),
    ("PF-05", "SCHEMA_INTEGRITY", "VALIDATION_ERROR"),
    ("PF-06", "FIXTURE_CATALOG_INTEGRITY", "VALIDATION_ERROR"),
    ("PF-07", "MATRIX_CATALOG_COVERAGE", "BLOCKED"),
    ("PF-08", "CLEAN_ROOM_CAPABILITY", "ISOLATION_VIOLATION"),
    ("PF-09", "NETWORK_CREDENTIAL_DENIAL", "ISOLATION_VIOLATION"),
    ("PF-10", "FILESYSTEM_ALLOWLIST", "ISOLATION_VIOLATION"),
    ("PF-11", "RESOURCE_LIMITS", "BLOCKED"),
    ("PF-12", "DETERMINISTIC_RUNTIME", "BLOCKED"),
    ("PF-13", "OUTPUT_PATH_AND_SEALING", "BLOCKED"),
    ("PF-14", "PRIVACY_CONTROLS", "BLOCKED"),
    ("PF-15", "EVIDENCE_SCHEMA_READINESS", "VALIDATION_ERROR"),
    ("PF-16", "REVIEW_SEPARATION", "BLOCKED"),
)


@dataclass(frozen=True)
class CheckResult:
    check_id: str
    name: str
    status: str
    failure_result: str
    reason: str
    evidence_ref: str | None = None


@dataclass(frozen=True)
class PreflightRecord:
    preflight_id: str
    spec_version: str
    status: str
    runner: dict[str, Any]
    inputs: dict[str, Any]
    selected_fixture_id: str
    selected_case_id: str
    environment: dict[str, Any]
    checks: tuple[CheckResult, ...]
    artifacts: dict[str, Any]
    overall_result: str
    captured_at: str

    def structured(self) -> dict[str, Any]:
        result = asdict(self)
        result["checks"] = []
        for check in self.checks:
            check_result = "READY" if check.status == "PASS" else check.failure_result
            item = {
                "check_id": check.check_id,
                "severity": "HARD_BLOCK",
                "result": check_result,
                "assertion": check.name,
                "observation": check.reason,
                "evidence_refs": [check.evidence_ref] if check.evidence_ref else [],
                "observed_fingerprints": [sha256_json({"check_id": check.check_id, "observation": check.reason})],
            }
            if check_result != "READY":
                item["failure_reason"] = check.reason
            result["checks"].append(item)
        return result


def _check(check_id: str, name: str, expected: str, status: str, reason: str, ref: str | None = None) -> CheckResult:
    return CheckResult(check_id, name, status, expected, reason, ref)


def _json_file(path: Path) -> tuple[bool, str]:
    try:
        json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False, "file_missing_or_invalid_json"
    return True, "parsed"


def _safe_member_name(value: str) -> str | None:
    """Return a canonical archive member name, rejecting traversal."""
    normalized = value.replace("\\", "/")
    if normalized.startswith("/") or ":" in normalized.split("/", 1)[0]:
        return None
    collapsed = posixpath.normpath(normalized)
    if collapsed in {"", "."} or collapsed == ".." or collapsed.startswith("../"):
        return None
    return collapsed


def _archive_for_source(base_dir: Path, source_archive: str) -> Path:
    """Resolve an authority archive without trusting its embedded path."""
    declared = Path(source_archive)
    candidates = (
        base_dir.parent / "ARCHIVE_SOURCES" / declared.name,
        base_dir.parent / source_archive,
        base_dir / source_archive,
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return candidates[0]


def _verify_declared_members(manifest_path: Path, base_dir: Path) -> tuple[bool, str]:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False, "manifest_missing_or_invalid_json"

    direct_members = list(manifest.get("candidate_members", []))
    if not isinstance(manifest.get("candidate_members", []), list):
        return False, "candidate_members_malformed"
    archive_sections = []
    for section_name, section in manifest.get("accepted_authorities", {}).items():
        if not isinstance(section, dict) or not isinstance(section.get("members"), list):
            return False, "accepted_authority_section_malformed:" + str(section_name)
        source_archive = section.get("source_archive")
        if not isinstance(source_archive, dict):
            return False, "accepted_authority_archive_missing:" + str(section_name)
        archive_sections.append((section_name, source_archive, section["members"]))

    declared_paths: set[str] = set()
    for member in direct_members:
        relative = member.get("path") if isinstance(member, dict) else None
        if not isinstance(relative, str):
            return False, "manifest_member_malformed"
        canonical = _safe_member_name(relative)
        if canonical is None or canonical in declared_paths:
            return False, "manifest_member_path_invalid_or_duplicate"
        declared_paths.add(canonical)

    for section_name, source_archive, members in archive_sections:
        archive_path_value = source_archive.get("path")
        archive_hash = source_archive.get("sha256")
        if not isinstance(archive_path_value, str) or not is_sha256(archive_hash):
            return False, "accepted_authority_archive_malformed:" + str(section_name)
        archive_path = _archive_for_source(base_dir, archive_path_value)
        if not archive_path.is_file():
            return False, "authority_archive_missing:" + archive_path.name
        if sha256_bytes(archive_path.read_bytes()) != archive_hash:
            return False, "authority_archive_hash_mismatch:" + archive_path.name
        try:
            archive = ZipFile(archive_path)
        except (OSError, BadZipFile):
            return False, "authority_archive_invalid:" + archive_path.name
        with archive:
            names = set(archive.namelist())
            for member in members:
                relative = member.get("path") if isinstance(member, dict) else None
                expected = member.get("sha256") if isinstance(member, dict) else None
                if not isinstance(relative, str) or not is_sha256(expected):
                    return False, "manifest_member_malformed"
                canonical = _safe_member_name(relative)
                if canonical is None or canonical in declared_paths:
                    return False, "manifest_member_path_invalid_or_duplicate"
                declared_paths.add(canonical)
                if canonical not in names:
                    return False, "authority_member_missing:" + canonical
                try:
                    actual = sha256_bytes(archive.read(canonical))
                except KeyError:
                    return False, "authority_member_missing:" + canonical
                if actual != expected:
                    return False, "authority_member_hash_mismatch:" + canonical

    missing = []
    mismatched = []
    for member in direct_members:
        relative = member.get("path") if isinstance(member, dict) else None
        expected = member.get("sha256") if isinstance(member, dict) else None
        if not isinstance(relative, str) or not is_sha256(expected):
            return False, "manifest_member_malformed"
        candidate = base_dir / relative
        if not candidate.exists():
            missing.append(relative)
        elif sha256_bytes(candidate.read_bytes()) != expected:
            mismatched.append(relative)
    if missing:
        return False, "manifest_member_missing:" + str(len(missing))
    if mismatched:
        return False, "manifest_member_hash_mismatch:" + str(len(mismatched))
    return True, "all_manifest_member_hashes_match"


def _verify_runner_package(manifest_path: Path) -> tuple[bool, str]:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False, "runner_manifest_missing_or_invalid_json"
    if manifest.get("manifest_format") != "PMIRI_GC_C1_REPLAY_RUNNER" or manifest.get("manifest_version") != "0.1":
        return False, "runner_manifest_identity_invalid"
    if manifest.get("status") not in {"DESIGN_ONLY", "READY_FOR_REPLAY"}:
        return False, "runner_manifest_status_invalid"
    runner = manifest.get("runner", {})
    if not isinstance(runner, dict) or set(runner) != {"runner_id", "runner_version", "source_fingerprint", "manifest_fingerprint", "latest_alias_allowed", "self_upgrade_allowed", "dependency_download_allowed"}:
        return False, "runner_identity_shape_invalid"
    if runner.get("runner_id") != RUNNER_ID or runner.get("runner_version") != RUNNER_VERSION:
        return False, "runner_identity_mismatch"
    if not is_sha256(runner.get("source_fingerprint")) or not is_sha256(runner.get("manifest_fingerprint")):
        return False, "runner_fingerprint_invalid"
    if runner.get("latest_alias_allowed") is not False or runner.get("self_upgrade_allowed") is not False or runner.get("dependency_download_allowed") is not False:
        return False, "runner_mutation_or_dependency_download_allowed"
    package_files = manifest.get("package_files")
    expected_paths = {"pmiri_gc_c1_replay_runner.py", "README.md", "runner-manifest.json"}
    if not isinstance(package_files, list) or len(package_files) != len(expected_paths):
        return False, "runner_package_inventory_invalid"
    seen: set[str] = set()
    for package_file in package_files:
        if not isinstance(package_file, dict) or set(package_file) != {"path", "sha256"}:
            return False, "runner_package_member_shape_invalid"
        relative, expected = package_file.get("path"), package_file.get("sha256")
        if not isinstance(relative, str) or relative in seen or relative not in expected_paths:
            return False, "runner_package_inventory_invalid"
        seen.add(relative)
        if relative == "runner-manifest.json":
            if expected != "SELF_HASH_EXCLUDED_FROM_PACKAGE_FINGERPRINT":
                return False, "runner_manifest_self_hash_marker_invalid"
            continue
        if not is_sha256(expected):
            return False, "runner_package_fingerprint_invalid"
        path = manifest_path.parent / relative
        if not path.is_file() or sha256_bytes(path.read_bytes()) != expected:
            return False, "runner_package_fingerprint_mismatch"
    if seen != expected_paths:
        return False, "runner_package_inventory_invalid"
    if manifest.get("clean_room_required") is not True or manifest.get("network_allowed") is not False or manifest.get("credentials_allowed") is not False or manifest.get("production_access_allowed") is not False or manifest.get("r_fc_replay_performed") is not False or manifest.get("execution_authorization") != "NOT_GRANTED":
        return False, "runner_package_boundary_invalid"
    return True, "pinned_runner_package_matches"


def _verify_fixture_selection(catalog_path: Path, fixture_id: str | None, case_id: str | None) -> tuple[bool, str]:
    if not fixture_id or not case_id:
        return False, "controlled_fixture_and_case_selection_not_supplied"
    try:
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False, "fixture_catalog_missing_or_invalid_json"
    for fixture in catalog.get("fixtures", []):
        if fixture.get("fixture_id") != fixture_id:
            continue
        if any(case.get("case_id") == case_id for case in fixture.get("cases", [])):
            return True, "fixture_and_case_selection_is_declared"
        return False, "selected_case_not_in_fixture"
    return False, "selected_fixture_not_in_catalog"


def run_preflight(
    project_root: str | Path,
    *,
    identity: Mapping[str, Any] | None = None,
    isolation: Mapping[str, IsolationObservation] | None = None,
    independent_reviewer: str | None = None,
    operator: str | None = None,
    selected_fixture_id: str | None = None,
    selected_case_id: str | None = None,
) -> PreflightRecord:
    root = Path(project_root).resolve()
    docs = root / "PMIRI_ALL_DOCUMENTATION_CHECKPOINT_17"
    checks: list[CheckResult] = []
    identity = identity or {}
    identity_ok = identity.get("runner_id") == RUNNER_ID and identity.get("runner_version") == RUNNER_VERSION
    checks.append(_check("PF-01", "RUNNER_IDENTITY", "BLOCKED", "PASS" if identity_ok else "UNVERIFIED", "identity matches" if identity_ok else "exact pinned runner identity not supplied"))

    manifest = docs / "GC-C1" / "PMIRI_GC-C1_REPLAY_RUNNER_0.1.0" / "runner-manifest.json"
    manifest_ok, manifest_reason = _verify_runner_package(manifest)
    checks.append(_check("PF-02", "RUNNER_PACKAGE_INTEGRITY", "BLOCKED", "PASS" if manifest_ok else "UNVERIFIED", manifest_reason))
    checks.append(_check("PF-03", "MANIFEST_INTEGRITY", "VALIDATION_ERROR", "PASS" if manifest_ok else "FAIL", manifest_reason))

    authority_manifest = docs / "GATE-D-R2" / "PMIRI_GD-R2_AUTHORITY_BUNDLE_MANIFEST_v0.1.json"
    authority_ok, authority_reason = _json_file(authority_manifest)
    if authority_ok:
        authority_ok, authority_reason = _verify_declared_members(authority_manifest, authority_manifest.parent)
    checks.append(_check("PF-04", "AUTHORITY_BUNDLE_INTEGRITY", "BLOCKED", "PASS" if authority_ok else "UNVERIFIED", authority_reason))

    evidence_schema = docs / "GC-C1" / "PMIRI_GC-C1-02_EVIDENCE_RECORD.schema.json"
    schema_ok, schema_reason = _json_file(evidence_schema)
    checks.append(_check("PF-05", "SCHEMA_INTEGRITY", "VALIDATION_ERROR", "PASS" if schema_ok else "FAIL", schema_reason))

    fixture_catalog = docs / "GC-C1" / "PMIRI_GC-C1-02_REPLAY_FIXTURE_CATALOG.json"
    fixture_ok, fixture_reason = _json_file(fixture_catalog)
    checks.append(_check("PF-06", "FIXTURE_CATALOG_INTEGRITY", "VALIDATION_ERROR", "PASS" if fixture_ok else "FAIL", fixture_reason))
    selection_ok, selection_reason = _verify_fixture_selection(fixture_catalog, selected_fixture_id, selected_case_id)
    checks.append(_check("PF-07", "MATRIX_CATALOG_COVERAGE", "BLOCKED", "PASS" if selection_ok else "UNVERIFIED", selection_reason))

    if isolation is None:
        isolation_status, isolation_reason = False, "no externally observed clean-room attestation"
    else:
        isolation_status, isolation_reason = verify_attestation(isolation)
    for check_id, name, domain in (
        ("PF-08", "CLEAN_ROOM_CAPABILITY", "filesystem"),
        ("PF-09", "NETWORK_CREDENTIAL_DENIAL", "network"),
        ("PF-10", "FILESYSTEM_ALLOWLIST", "filesystem"),
        ("PF-11", "RESOURCE_LIMITS", "resource_limits"),
        ("PF-12", "DETERMINISTIC_RUNTIME", "determinism"),
        ("PF-13", "OUTPUT_PATH_AND_SEALING", "teardown"),
        ("PF-14", "PRIVACY_CONTROLS", "privacy"),
    ):
        status = "PASS" if isolation_status else "UNVERIFIED"
        checks.append(_check(check_id, name, dict(CHECKS)[check_id] if False else next(item[2] for item in CHECKS if item[0] == check_id), status, isolation_reason, None))

    checks.append(_check("PF-15", "EVIDENCE_SCHEMA_READINESS", "VALIDATION_ERROR", "PASS" if schema_ok else "FAIL", "schema reference available" if schema_ok else schema_reason))
    review_ok = bool(operator and independent_reviewer and operator != independent_reviewer)
    checks.append(_check("PF-16", "REVIEW_SEPARATION", "BLOCKED", "PASS" if review_ok else "UNVERIFIED", "distinct identities supplied" if review_ok else "operator and independent reviewer identities are not separated"))

    overall = "READY_FOR_REPLAY" if all(check.status == "PASS" for check in checks) else "BLOCKED"
    runner_manifest_data = {}
    try:
        runner_manifest_data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        pass
    runner_source = manifest.parent / "pmiri_gc_c1_replay_runner.py"
    c1_authority_manifest = docs / "GC-C1" / "PMIRI_GC-C1-08_AUTHORITY_BUNDLE_MANIFEST.json"
    authority_input_manifest = authority_manifest if authority_manifest.exists() else c1_authority_manifest
    preflight_matrix = docs / "GC-C1" / "PMIRI_GC-C1-05_CONTROLLED_PREFLIGHT_SCENARIO_MATRIX.json"
    fixture_catalog = docs / "GC-C1" / "PMIRI_GC-C1-02_REPLAY_FIXTURE_CATALOG.json"
    environment_values = {domain: "UNVERIFIED" for domain in ("network", "credentials", "filesystem", "determinism", "resource_limits", "teardown")}
    if isolation:
        for domain, observation in isolation.items():
            if domain in environment_values:
                environment_values[domain] = observation.result
    record = PreflightRecord(
        preflight_id="pf_" + sha256_json({"root": root.as_posix(), "captured_at": utc_now()})[:32],
        spec_version="0.1",
        status="RECORDED",
        runner={"runner_id": RUNNER_ID, "runner_version": RUNNER_VERSION, "source_fingerprint": sha256_bytes(runner_source.read_bytes()) if runner_source.exists() else None, "manifest_fingerprint": runner_manifest_data.get("runner", {}).get("manifest_fingerprint")},
        inputs={"authority_bundle_fingerprint": sha256_bytes(authority_input_manifest.read_bytes()) if authority_input_manifest.exists() else sha256_json({"status": "MISSING"}), "schema_fingerprint": sha256_bytes(evidence_schema.read_bytes()) if evidence_schema.exists() else sha256_json({"status": "MISSING"}), "catalog_fingerprint": sha256_bytes(fixture_catalog.read_bytes()) if fixture_catalog.exists() else sha256_json({"status": "MISSING"}), "matrix_fingerprint": sha256_bytes(preflight_matrix.read_bytes()) if preflight_matrix.exists() else sha256_json({"status": "MISSING"})},
        selected_fixture_id=selected_fixture_id or "NONE",
        selected_case_id=selected_case_id or "NONE",
        environment={"environment_fingerprint": sha256_json(environment_values), **environment_values},
        checks=tuple(checks),
        artifacts={"output_fingerprint": None, "artifact_manifest_fingerprint": None, "isolation_attestation_ref": None, "privacy_record_ref": None, "seal_status": "UNSEALED"},
        overall_result=overall,
        captured_at=utc_now(),
    )
    return record


def validate_preflight_record_shape(record: Mapping[str, Any]) -> tuple[str, ...]:
    """Validate the contract-level shape without claiming positive evidence."""
    required = ("preflight_id", "spec_version", "status", "runner", "inputs", "selected_fixture_id", "selected_case_id", "environment", "checks", "artifacts", "overall_result", "captured_at")
    errors = ["missing:" + key for key in required if key not in record]
    if record.get("spec_version") != "0.1" or record.get("status") not in {"DESIGN_ONLY", "RECORDED", "INVALIDATED"}:
        errors.append("root_status_invalid")
    for section, fields in {
        "runner": ("runner_id", "runner_version", "source_fingerprint", "manifest_fingerprint"),
        "inputs": ("authority_bundle_fingerprint", "schema_fingerprint", "catalog_fingerprint", "matrix_fingerprint"),
        "environment": ("environment_fingerprint", "network", "credentials", "filesystem", "determinism", "resource_limits", "teardown"),
        "artifacts": ("output_fingerprint", "artifact_manifest_fingerprint", "isolation_attestation_ref", "privacy_record_ref", "seal_status"),
    }.items():
        value = record.get(section)
        if not isinstance(value, dict):
            errors.append(section + "_must_be_object")
            continue
        errors.extend(section + ".missing:" + field for field in fields if field not in value)
    runner = record.get("runner", {})
    if runner.get("runner_id") != RUNNER_ID or runner.get("runner_version") != RUNNER_VERSION:
        errors.append("runner_identity_invalid")
    inputs = record.get("inputs", {})
    errors.extend("inputs.invalid_fingerprint:" + field for field in ("authority_bundle_fingerprint", "schema_fingerprint", "catalog_fingerprint", "matrix_fingerprint") if not is_sha256(inputs.get(field)))
    environment = record.get("environment", {})
    allowed_environment = {"network": {"DENIED", "UNVERIFIED"}, "credentials": {"DENIED", "UNVERIFIED"}, "filesystem": {"ALLOWLIST_VERIFIED", "UNVERIFIED"}, "determinism": {"VERIFIED", "UNVERIFIED"}, "resource_limits": {"VERIFIED", "UNVERIFIED"}, "teardown": {"AVAILABLE", "UNVERIFIED"}}
    errors.extend("environment.invalid:" + field for field, allowed in allowed_environment.items() if environment.get(field) not in allowed)
    if record.get("artifacts", {}).get("seal_status") not in {"SEALED", "INVALID", "UNSEALED"}:
        errors.append("artifacts.seal_status_invalid")
    checks = record.get("checks")
    if not isinstance(checks, list) or len(checks) != 16:
        errors.append("checks_must_contain_16")
    else:
        ids = [item.get("check_id") for item in checks]
        if ids != [f"PF-{index:02d}" for index in range(1, 17)]:
            errors.append("check_ids_not_complete_or_ordered")
        for item in checks:
            if item.get("severity") != "HARD_BLOCK" or not item.get("assertion") or not item.get("observation"):
                errors.append("check_shape_invalid:" + str(item.get("check_id")))
            if item.get("result") not in {"READY", "BLOCKED", "VALIDATION_ERROR", "ISOLATION_VIOLATION"}:
                errors.append("check_result_invalid:" + str(item.get("check_id")))
            if item.get("result") != "READY" and not item.get("failure_reason"):
                errors.append("check_failure_reason_missing:" + str(item.get("check_id")))
            if any(not is_sha256(fingerprint) for fingerprint in item.get("observed_fingerprints", [])):
                errors.append("check_fingerprint_invalid:" + str(item.get("check_id")))
    return tuple(errors)


def write_preflight(record: PreflightRecord, path: str | Path) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(record.structured(), ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
