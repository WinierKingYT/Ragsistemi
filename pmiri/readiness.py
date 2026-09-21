"""Fail-closed deployment-readiness evidence for the PMIRI workspace.

The readiness report is an operational candidate, not a production approval.
It checks the local evidence that can be verified in this repository and keeps
external prerequisites as hard blockers.  A profile is configuration input,
not authority: it cannot turn an external dependency into verified evidence.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

from .canonical import is_sha256, sha256_bytes, sha256_json, utc_now
from .deployment_evidence import DeploymentEvidenceError, VerifiedDeploymentEvidence, verify_external_evidence
from .integrity import authority_fingerprint, validate_documentation_bundle
from .network import NetworkBoundary
from .preflight import validate_preflight_record_shape
from .r_fc import CATALOG_PATH, HANDLER_MANIFEST_KIND, HANDLER_MANIFEST_VERSION, load_handler_manifest
from .schema import SchemaRegistry, SchemaValidationError
from .sealing import verify_seal


REPORT_TYPE = "PMIRI_DEPLOYMENT_READINESS_REPORT"
REPORT_VERSION = "0.1"

_PROFILE_FIELDS = {"profile_version", "profile_id", "storage", "control_plane", "network", "api"}
_STORAGE_FIELDS = {"backend", "root", "content_encryption", "metadata_protection", "key_escrow"}
_CONTROL_PLANE_FIELDS = {"backend", "path"}
_NETWORK_FIELDS = {"mode", "external_execution"}
_API_FIELDS = {"transport", "bind_host", "port", "max_request_bytes", "audit_path"}

_DEFAULT_PROFILE: dict[str, Any] = {
    "profile_version": REPORT_VERSION,
    "profile_id": "workspace-local-candidate",
    "storage": {
        "backend": "sqlite",
        "root": ".pmiri-sqlite",
        "content_encryption": "UNCONFIGURED",
        "metadata_protection": "UNCONFIGURED",
        "key_escrow": "UNCONFIGURED",
    },
    "control_plane": {
        "backend": "sqlite-local",
        "path": ".pmiri-control/control.db",
    },
    "network": {
        "mode": "DENY_BY_DEFAULT",
        "external_execution": "DISABLED",
    },
    "api": {
        "transport": "HTTP_LOOPBACK",
        "bind_host": "127.0.0.1",
        "port": 8765,
        "max_request_bytes": 1024 * 1024,
        "audit_path": "artifacts/read-audit.jsonl",
    },
}

_EXTERNAL_BLOCKERS = (
    ("EXT-01", "INDEPENDENT_CLEAN_ROOM", "independently observed OS/filesystem/network isolation attestation is not supplied"),
    ("EXT-02", "DEPLOYED_IDENTITY_PROVIDER", "deployed identity, revocation and gateway integration is not configured"),
    ("EXT-03", "DISTRIBUTED_CONTROL_PLANE", "only the local SQLite control-plane adapter exists; distributed failover is not verified"),
    ("EXT-04", "METADATA_ENCRYPTION_AND_KEY_ESCROW", "metadata/volume encryption, key escrow and rotation operations require deployment authority"),
    ("EXT-05", "REAL_PROVIDER_CONNECTOR_AUTHORIZATION", "real provider/connector, DNS, TLS and external network execution is disabled"),
    ("EXT-06", "INDEPENDENT_GATE_D_RECHECK", "independent Gate-D R2 recheck and acceptance evidence is not supplied"),
)


class ReadinessContractError(ValueError):
    """Raised when readiness configuration or evidence has an invalid shape."""


@dataclass(frozen=True)
class ReadinessCheck:
    check_id: str
    category: str
    assertion: str
    result: str
    observation: str
    evidence_refs: tuple[str, ...] = ()

    def structured(self) -> dict[str, Any]:
        item = asdict(self)
        item["evidence_refs"] = list(self.evidence_refs)
        item["severity"] = "HARD_BLOCK"
        item["observed_fingerprint"] = sha256_json(
            {
                "check_id": self.check_id,
                "category": self.category,
                "assertion": self.assertion,
                "result": self.result,
                "observation": self.observation,
                "evidence_refs": list(self.evidence_refs),
            }
        )
        return item


@dataclass(frozen=True)
class DeploymentReadinessReport:
    report_id: str
    report_type: str
    report_version: str
    project_root: str
    profile_id: str
    profile_fingerprint: str
    authority_fingerprint: str
    captured_at: str
    checks: tuple[ReadinessCheck, ...]
    required_external_evidence: tuple[dict[str, str], ...]
    overall_result: str

    def structured(self) -> dict[str, Any]:
        unsigned = {
            "report_id": self.report_id,
            "report_type": self.report_type,
            "report_version": self.report_version,
            "project_root": self.project_root,
            "profile_id": self.profile_id,
            "profile_fingerprint": self.profile_fingerprint,
            "authority_fingerprint": self.authority_fingerprint,
            "captured_at": self.captured_at,
            "checks": [check.structured() for check in self.checks],
            "required_external_evidence": [dict(item) for item in self.required_external_evidence],
            "overall_result": self.overall_result,
        }
        return {**unsigned, "report_fingerprint": sha256_json(unsigned)}


def default_profile() -> dict[str, Any]:
    """Return a detached, safe local-candidate profile."""
    return json.loads(json.dumps(_DEFAULT_PROFILE))


def load_profile(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReadinessContractError("readiness_profile_invalid_json") from exc
    validate_profile(value)
    return value


def validate_profile(profile: Mapping[str, Any]) -> None:
    if not isinstance(profile, Mapping) or set(profile) != _PROFILE_FIELDS:
        raise ReadinessContractError("readiness_profile_shape_invalid")
    if profile.get("profile_version") != REPORT_VERSION or not isinstance(profile.get("profile_id"), str) or not profile["profile_id"]:
        raise ReadinessContractError("readiness_profile_identity_invalid")
    storage = profile.get("storage")
    control_plane = profile.get("control_plane")
    network = profile.get("network")
    api = profile.get("api")
    if not isinstance(storage, Mapping) or set(storage) != _STORAGE_FIELDS:
        raise ReadinessContractError("readiness_storage_profile_shape_invalid")
    if not isinstance(control_plane, Mapping) or set(control_plane) != _CONTROL_PLANE_FIELDS:
        raise ReadinessContractError("readiness_control_plane_profile_shape_invalid")
    if not isinstance(network, Mapping) or set(network) != _NETWORK_FIELDS:
        raise ReadinessContractError("readiness_network_profile_shape_invalid")
    if not isinstance(api, Mapping) or set(api) != _API_FIELDS:
        raise ReadinessContractError("readiness_api_profile_shape_invalid")
    if storage.get("backend") not in {"sqlite", "UNCONFIGURED"}:
        raise ReadinessContractError("readiness_storage_backend_invalid")
    if storage.get("root") is not None and (not isinstance(storage.get("root"), str) or not storage["root"]):
        raise ReadinessContractError("readiness_storage_root_invalid")
    if storage.get("content_encryption") not in {"AES_GCM_BLOB_ADAPTER", "UNCONFIGURED"}:
        raise ReadinessContractError("readiness_content_encryption_invalid")
    if storage.get("metadata_protection") not in {"EXTERNAL_VOLUME_ENCRYPTION", "UNCONFIGURED"}:
        raise ReadinessContractError("readiness_metadata_protection_invalid")
    if storage.get("key_escrow") not in {"EXTERNAL_KMS", "UNCONFIGURED"}:
        raise ReadinessContractError("readiness_key_escrow_invalid")
    if control_plane.get("backend") not in {"sqlite-local", "UNCONFIGURED"}:
        raise ReadinessContractError("readiness_control_plane_backend_invalid")
    if control_plane.get("path") is not None and (not isinstance(control_plane.get("path"), str) or not control_plane["path"]):
        raise ReadinessContractError("readiness_control_plane_path_invalid")
    if network.get("mode") != "DENY_BY_DEFAULT" or network.get("external_execution") != "DISABLED":
        raise ReadinessContractError("readiness_network_must_remain_deny_by_default")
    if api.get("transport") != "HTTP_LOOPBACK" or api.get("bind_host") != "127.0.0.1":
        raise ReadinessContractError("readiness_api_must_remain_loopback")
    if not isinstance(api.get("port"), int) or isinstance(api.get("port"), bool) or not 1 <= api["port"] <= 65535:
        raise ReadinessContractError("readiness_api_port_invalid")
    if not isinstance(api.get("max_request_bytes"), int) or isinstance(api.get("max_request_bytes"), bool) or not 1 <= api["max_request_bytes"] <= 8 * 1024 * 1024:
        raise ReadinessContractError("readiness_api_request_limit_invalid")
    if not isinstance(api.get("audit_path"), str) or not api["audit_path"]:
        raise ReadinessContractError("readiness_api_audit_path_invalid")


def _check(check_id: str, category: str, assertion: str, result: str, observation: str, *refs: str) -> ReadinessCheck:
    if result not in {"READY", "BLOCKED"}:
        raise ReadinessContractError("readiness_result_invalid")
    return ReadinessCheck(check_id, category, assertion, result, observation, tuple(refs))


def _inside(root: Path, value: str | Path | None) -> Path | None:
    if value is None:
        return None
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root / candidate
    candidate = candidate.resolve()
    if candidate != root and root not in candidate.parents:
        return None
    return candidate


def _json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _candidate_artifact(root: Path, relative: str, *, expected_kind: str, expected_status: str, predicate: Any | None = None) -> ReadinessCheck:
    path = root / relative
    data = _json(path)
    if data is None:
        return _check("LOC-" + sha256_json(relative)[:8], "LOCAL_EVIDENCE", expected_kind, "BLOCKED", relative + " is missing or invalid JSON")
    if data.get("artifact_kind") != expected_kind or data.get("status") != expected_status:
        return _check(
            "LOC-" + sha256_json(relative)[:8],
            "LOCAL_EVIDENCE",
            expected_kind,
            "BLOCKED",
            relative + " does not contain the required candidate status or artifact kind",
        )
    if predicate is not None:
        try:
            valid, reason = predicate(data)
        except Exception:
            valid, reason = False, "candidate artifact predicate failed"
        if not valid:
            return _check("LOC-" + sha256_json(relative)[:8], "LOCAL_EVIDENCE", expected_kind, "BLOCKED", relative + ":" + reason)
    return _check("LOC-" + sha256_json(relative)[:8], "LOCAL_EVIDENCE", expected_kind, "READY", relative + " matches the expected local candidate contract", relative)


def _sqlite_probe(path: Path, expected_tables: set[str]) -> tuple[bool, str]:
    if not path.is_file():
        return False, "database file is missing"
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(path, timeout=2.0, isolation_level=None)
        connection.execute("PRAGMA query_only=ON")
        integrity = connection.execute("PRAGMA integrity_check").fetchone()
        journal = connection.execute("PRAGMA journal_mode").fetchone()
        synchronous = connection.execute("PRAGMA synchronous").fetchone()
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        if not integrity or str(integrity[0]).lower() != "ok":
            return False, "sqlite integrity_check failed"
        missing = sorted(expected_tables - tables)
        if missing:
            return False, "missing tables:" + ",".join(missing)
        if not journal or str(journal[0]).lower() != "wal":
            return False, "journal_mode is not WAL"
        if not synchronous or int(synchronous[0]) != 2:
            return False, "synchronous mode is not FULL"
        return True, "integrity_check=ok;journal_mode=WAL;synchronous=FULL;tables=" + str(len(tables))
    except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
        return False, "sqlite probe failed:" + type(exc).__name__
    finally:
        if connection is not None:
            connection.close()


def _network_default_deny() -> tuple[bool, str]:
    boundary = NetworkBoundary()
    https = boundary.evaluate("external_fetch", "https://example.com/")
    http = boundary.evaluate("external_fetch", "http://example.com/")
    if https.action_result != "DENY" or http.action_result != "DENY":
        return False, "external network boundary did not deny both HTTPS and HTTP probes"
    return True, "HTTPS and HTTP external probes were denied without network I/O"


def _local_r_fc_candidate_valid(data: Mapping[str, Any]) -> tuple[bool, str]:
    unsigned = {key: value for key, value in data.items() if key != "report_fingerprint"}
    valid = (
        data.get("artifact_kind") == "PMIRI-GC-C1-R-FC-LOCAL-HANDLER-CANDIDATE-REPORT"
        and data.get("status") == "LOCAL_SYNTHETIC_ONLY"
        and data.get("runtime_execution") == "LOCAL_SYNTHETIC_ONLY"
        and data.get("selected_case_count") == 34
        and data.get("executed_case_count") == 34
        and data.get("handler_error_count") == 0
        and data.get("oracle_match_count") == 34
        and data.get("all_oracles_match") is True
        and data.get("r_fc_pass") == "NONE"
        and data.get("external_network_access") == "NOT_PERFORMED"
        and is_sha256(data.get("report_fingerprint"))
        and data.get("report_fingerprint") == sha256_json(unsigned)
    )
    return valid, "34 local R-FC handlers and oracle comparisons are not complete" if not valid else ""


def _local_handler_manifest_valid(root: Path, data: Mapping[str, Any]) -> tuple[bool, str]:
    try:
        manifest_path = root / "artifacts" / "r-fc-handler-manifest.json"
        manifest = load_handler_manifest(manifest_path)
        source = manifest["module"]["source_path"]
        source_path = Path(source)
        if not source_path.is_absolute():
            source_path = root / source_path
        catalog = _json(root / CATALOG_PATH)
        expected_ids = {
            str(declared_case["case_id"])
            for fixture in (catalog or {}).get("fixtures", [])
            for declared_case in fixture.get("cases", [])
            if isinstance(fixture, Mapping) and isinstance(declared_case, Mapping) and isinstance(declared_case.get("case_id"), str)
        }
        valid = (
            manifest.get("artifact_kind") == HANDLER_MANIFEST_KIND
            and manifest.get("version") == HANDLER_MANIFEST_VERSION
            and manifest.get("status") == "READY_FOR_REPLAY"
            and manifest.get("module", {}).get("module_id") == "pmiri.r_fc_handlers"
            and manifest.get("case_ids") == sorted(expected_ids)
            and set(manifest.get("handlers", {})) == expected_ids
            and source_path == (root / "pmiri" / "r_fc_handlers.py").resolve()
            and source_path.is_file()
            and manifest["module"].get("source_fingerprint") == sha256_bytes(source_path.read_bytes())
        )
    except (OSError, TypeError, ValueError, KeyError):
        valid = False
    return valid, "standalone pinned R-FC handler manifest is missing or mismatched" if not valid else ""


def _external_check(check_id: str, assertion: str, reason: str) -> ReadinessCheck:
    return _check(check_id, "EXTERNAL_PREREQUISITE", assertion, "BLOCKED", reason)


def _verified_external_check(check_id: str, assertion: str, evidence: VerifiedDeploymentEvidence) -> ReadinessCheck:
    item = evidence.checks[check_id]
    return _check(
        check_id,
        "EXTERNAL_PREREQUISITE",
        assertion,
        "READY",
        "signed external deployment evidence verified against the active profile and authority bundle; bundle_fingerprint=" + evidence.evidence_fingerprint,
        *[str(ref) for ref in item["evidence_refs"]],
    )


def run_deployment_readiness(
    project_root: str | Path,
    *,
    profile: Mapping[str, Any] | None = None,
    captured_at: str | None = None,
    external_evidence_path: str | Path | None = None,
    external_public_key_path: str | Path | None = None,
) -> DeploymentReadinessReport:
    """Create a machine-readable, fail-closed deployment-readiness report.

    This function performs read-only checks.  It never initializes a store,
    changes network policy, executes a provider, or treats profile text as
    external authority.
    """
    root = Path(project_root).resolve()
    active_profile = default_profile() if profile is None else dict(profile)
    validate_profile(active_profile)
    captured_at = captured_at or utc_now()
    checks: list[ReadinessCheck] = []
    checks.append(_check("LOC-0001", "CONFIGURATION", "PROFILE_CONTRACT", "READY", "readiness profile matches the closed versioned contract"))

    try:
        integrity = validate_documentation_bundle(root)
        authority_ref = authority_fingerprint(root)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, SchemaValidationError, ReadinessContractError, ValueError) as exc:
        integrity = None
        authority_ref = sha256_json({"status": "UNAVAILABLE", "reason": type(exc).__name__})
    if integrity is None or not integrity.ok:
        checks.append(_check("LOC-0002", "LOCAL_EVIDENCE", "AUTHORITY_BUNDLE_INTEGRITY", "BLOCKED", "documentation authority or schema registry integrity is not valid"))
    else:
        checks.append(_check("LOC-0002", "LOCAL_EVIDENCE", "AUTHORITY_BUNDLE_INTEGRITY", "READY", "documentation JSON/schema registry is structurally valid", "authority://PMIRI_ALL_DOCUMENTATION_CHECKPOINT_17"))

    external_evidence: VerifiedDeploymentEvidence | None = None
    external_evidence_reason: str | None = None
    if external_evidence_path is None and external_public_key_path is None:
        external_evidence_reason = None
    elif external_evidence_path is None or external_public_key_path is None:
        external_evidence_reason = "both_external_evidence_and_public_key_are_required"
    else:
        try:
            public_key_path = Path(external_public_key_path).resolve()
            external_evidence = verify_external_evidence(
                external_evidence_path,
                trusted_public_key=public_key_path.read_bytes(),
                profile_id=str(active_profile["profile_id"]),
                profile_fingerprint=sha256_json(active_profile),
                authority_fingerprint=authority_ref,
            )
        except (DeploymentEvidenceError, OSError, ValueError, TypeError) as exc:
            external_evidence_reason = type(exc).__name__ + ":" + str(exc)

    try:
        SchemaRegistry(root)
        checks.append(_check("LOC-0003", "LOCAL_EVIDENCE", "STANDARDS_SCHEMA_VALIDATOR", "READY", "Draft 2020-12 standards validator and PMIRI URI registry are available"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, SchemaValidationError, ValueError):
        checks.append(_check("LOC-0003", "LOCAL_EVIDENCE", "STANDARDS_SCHEMA_VALIDATOR", "BLOCKED", "standards-complete schema validator is unavailable"))

    checks.append(_candidate_artifact(root, "artifacts/s0-acceptance-report.json", expected_kind="PMIRI-V1-S0-ACCEPTANCE-REPORT", expected_status="S0_ACCEPTANCE_CANDIDATE", predicate=lambda data: (isinstance(data.get("cases"), list) and len(data["cases"]) == 12, "VS-01..VS-12 candidate cases are not complete")))
    checks.append(_candidate_artifact(root, "artifacts/gate-d-runtime-smoke-report.json", expected_kind="PMIRI-GATE-D-RUNTIME-SMOKE-REPORT", expected_status="RUNTIME_SMOKE_CANDIDATE", predicate=lambda data: (data.get("external_network_access") == "NOT_PERFORMED" and data.get("external_provider_access") == "NOT_PERFORMED", "smoke report claims external execution")))
    checks.append(_candidate_artifact(root, "artifacts/d2-runtime-candidate-report.json", expected_kind="PMIRI-GATE-D-D2-RUNTIME-CANDIDATE-REPORT", expected_status="D2_RUNTIME_CANDIDATE", predicate=lambda data: (data.get("fixture_signal_count") == 34 and data.get("all_oracles_match") is True, "34-case oracle comparison is not complete")))
    checks.append(_candidate_artifact(root, "artifacts/r-fc-blocked-candidate-report.json", expected_kind="PMIRI-GC-C1-R-FC-BLOCKED-CANDIDATE-REPORT", expected_status="R_FC_REPLAY_BLOCKED", predicate=lambda data: (data.get("blocked_case_count") == 17 and data.get("executed_case_count") == 0 and data.get("r_fc_pass") == "NONE", "R-FC blocked boundary is not preserved")))
    checks.append(_candidate_artifact(root, "artifacts/r-fc-local-handler-candidate-report.json", expected_kind="PMIRI-GC-C1-R-FC-LOCAL-HANDLER-CANDIDATE-REPORT", expected_status="LOCAL_SYNTHETIC_ONLY", predicate=_local_r_fc_candidate_valid))
    checks.append(_candidate_artifact(root, "artifacts/r-fc-handler-manifest.json", expected_kind=HANDLER_MANIFEST_KIND, expected_status="READY_FOR_REPLAY", predicate=lambda data: _local_handler_manifest_valid(root, data)))

    preflight_path = root / "artifacts" / "preflight-record.json"
    preflight = _json(preflight_path)
    preflight_errors = validate_preflight_record_shape(preflight) if preflight is not None else ("preflight_record_missing_or_invalid",)
    checks.append(_check("LOC-0008", "LOCAL_EVIDENCE", "PREFLIGHT_CONTRACT", "READY" if not preflight_errors else "BLOCKED", "preflight record shape is valid" if not preflight_errors else "preflight record shape invalid:" + str(preflight_errors[0]), "artifacts/preflight-record.json"))

    manifest_path = root / "artifacts" / "sealed" / "s0-acceptance" / "artifact-manifest.json"
    sealed_ok, sealed_reason = verify_seal(manifest_path, root=root)
    checks.append(_check("LOC-0009", "LOCAL_EVIDENCE", "SEALED_ARTIFACT_INTEGRITY", "READY" if sealed_ok else "BLOCKED", "sealed manifest byte inventory verifies" if sealed_ok else "sealed manifest verification failed:" + sealed_reason, "artifacts/sealed/s0-acceptance/artifact-manifest.json"))

    storage = active_profile["storage"]
    storage_root = _inside(root, storage.get("root"))
    storage_db = storage_root / "pmiri.sqlite3" if storage_root is not None else None
    if storage.get("backend") != "sqlite" or storage_db is None:
        checks.append(_check("LOC-0010", "LOCAL_CONFIGURATION", "TRANSACTIONAL_SQLITE_STORAGE", "BLOCKED", "SQLite storage root is not configured inside the project root"))
    else:
        store_ok, store_reason = _sqlite_probe(storage_db, {"schema_meta", "blobs", "sources"})
        checks.append(_check("LOC-0010", "LOCAL_CONFIGURATION", "TRANSACTIONAL_SQLITE_STORAGE", "READY" if store_ok else "BLOCKED", store_reason, storage_db.relative_to(root).as_posix()))

    control = active_profile["control_plane"]
    control_path = _inside(root, control.get("path"))
    if control.get("backend") != "sqlite-local" or control_path is None:
        checks.append(_check("LOC-0011", "LOCAL_CONFIGURATION", "LOCAL_CONTROL_PLANE", "BLOCKED", "local control-plane SQLite path is not configured inside the project root"))
    else:
        control_ok, control_reason = _sqlite_probe(control_path, {"authenticated_principals", "request_replays", "rate_windows", "policy_epoch"})
        checks.append(_check("LOC-0011", "LOCAL_CONFIGURATION", "LOCAL_CONTROL_PLANE", "READY" if control_ok else "BLOCKED", control_reason, control_path.relative_to(root).as_posix()))

    network_ok, network_reason = _network_default_deny()
    checks.append(_check("LOC-0012", "LOCAL_ENFORCEMENT", "NETWORK_DEFAULT_DENY", "READY" if network_ok else "BLOCKED", network_reason))

    api_audit_path = _inside(root, active_profile["api"].get("audit_path"))
    api_ok = api_audit_path is not None
    checks.append(_check("LOC-0013", "LOCAL_CONFIGURATION", "LOOPBACK_READ_SERVER_PROFILE", "READY" if api_ok else "BLOCKED", "HTTP read server profile is loopback-bound with a project-local audit path" if api_ok else "HTTP read server audit path is outside the project root", "api"))

    if external_evidence is not None:
        checks.extend(_verified_external_check(check_id, assertion, external_evidence) for check_id, assertion, _ in _EXTERNAL_BLOCKERS)
    else:
        external_reason = "independently observed deployment evidence is not supplied"
        if external_evidence_reason is not None:
            external_reason = "signed external deployment evidence is not verified:" + external_evidence_reason
        checks.extend(_external_check(check_id, assertion, external_reason if external_evidence_path is not None or external_public_key_path is not None else reason) for check_id, assertion, reason in _EXTERNAL_BLOCKERS)

    required_external = tuple({"check_id": check_id, "assertion": assertion, "reason": reason} for check_id, assertion, reason in _EXTERNAL_BLOCKERS)
    overall = "DEPLOYMENT_READY" if all(item.result == "READY" for item in checks) else "DEPLOYMENT_READINESS_BLOCKED"
    profile_fingerprint = sha256_json(active_profile)
    report_id = "readiness_" + sha256_json({"root": root.as_posix(), "profile": profile_fingerprint, "captured_at": captured_at})[:32]
    return DeploymentReadinessReport(
        report_id=report_id,
        report_type=REPORT_TYPE,
        report_version=REPORT_VERSION,
        project_root=root.as_posix(),
        profile_id=str(active_profile["profile_id"]),
        profile_fingerprint=profile_fingerprint,
        authority_fingerprint=authority_ref,
        captured_at=captured_at,
        checks=tuple(checks),
        required_external_evidence=required_external,
        overall_result=overall,
    )


def validate_readiness_report(report: Mapping[str, Any]) -> tuple[str, ...]:
    """Validate report shape and every derived fingerprint without side effects."""
    required = {"report_id", "report_type", "report_version", "project_root", "profile_id", "profile_fingerprint", "authority_fingerprint", "captured_at", "checks", "required_external_evidence", "overall_result", "report_fingerprint"}
    errors = ["root_shape_invalid"] if set(report) != required else []
    if report.get("report_type") != REPORT_TYPE or report.get("report_version") != REPORT_VERSION:
        errors.append("report_identity_invalid")
    if not isinstance(report.get("report_id"), str) or not report["report_id"].startswith("readiness_"):
        errors.append("report_id_invalid")
    if not isinstance(report.get("project_root"), str) or not report["project_root"]:
        errors.append("project_root_invalid")
    if not isinstance(report.get("profile_id"), str) or not report["profile_id"]:
        errors.append("profile_id_invalid")
    if not isinstance(report.get("captured_at"), str) or not report["captured_at"]:
        errors.append("captured_at_invalid")
    for field in ("profile_fingerprint", "authority_fingerprint", "report_fingerprint"):
        if not is_sha256(report.get(field)):
            errors.append("fingerprint_invalid:" + field)
    checks = report.get("checks")
    if not isinstance(checks, list) or not checks:
        errors.append("checks_invalid")
    else:
        ids: set[str] = set()
        for item in checks:
            if not isinstance(item, dict):
                errors.append("check_not_object")
                continue
            check_required = {"check_id", "category", "assertion", "result", "observation", "evidence_refs", "severity", "observed_fingerprint"}
            if set(item) != check_required:
                errors.append("check_shape_invalid:" + str(item.get("check_id")))
                continue
            if item["check_id"] in ids:
                errors.append("check_id_duplicate:" + item["check_id"])
            ids.add(item["check_id"])
            if any(not isinstance(item.get(field), str) or not item[field] for field in ("check_id", "category", "assertion", "observation")):
                errors.append("check_text_invalid:" + str(item.get("check_id")))
            if item["result"] not in {"READY", "BLOCKED"} or item["severity"] != "HARD_BLOCK" or not isinstance(item["evidence_refs"], list) or any(not isinstance(ref, str) or not ref for ref in item["evidence_refs"]):
                errors.append("check_value_invalid:" + item["check_id"])
            expected = sha256_json({key: item[key] for key in ("check_id", "category", "assertion", "result", "observation", "evidence_refs")})
            if item.get("observed_fingerprint") != expected:
                errors.append("check_fingerprint_mismatch:" + item["check_id"])
    external = report.get("required_external_evidence")
    expected_external_ids = {item[0] for item in _EXTERNAL_BLOCKERS}
    if not isinstance(external, list) or {item.get("check_id") for item in external if isinstance(item, dict)} != expected_external_ids:
        errors.append("external_evidence_requirements_invalid")
    else:
        for item in external:
            if set(item) != {"check_id", "assertion", "reason"} or any(not isinstance(item.get(field), str) or not item[field] for field in ("check_id", "assertion", "reason")):
                errors.append("external_evidence_requirement_shape_invalid:" + str(item.get("check_id")))
    unsigned = {key: report[key] for key in required if key != "report_fingerprint"}
    if report.get("report_fingerprint") != sha256_json(unsigned):
        errors.append("report_fingerprint_mismatch")
    if report.get("overall_result") not in {"DEPLOYMENT_READY", "DEPLOYMENT_READINESS_BLOCKED"}:
        errors.append("overall_result_invalid")
    elif report["overall_result"] == "DEPLOYMENT_READY" and isinstance(checks, list) and any(item.get("result") != "READY" for item in checks if isinstance(item, dict)):
        errors.append("overall_result_claims_ready_with_blocked_checks")
    elif report["overall_result"] == "DEPLOYMENT_READINESS_BLOCKED" and isinstance(checks, list) and all(item.get("result") == "READY" for item in checks if isinstance(item, dict)):
        errors.append("overall_result_blocked_without_blocked_checks")
    return tuple(errors)


def write_readiness(report: DeploymentReadinessReport, path: str | Path) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report.structured(), ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


__all__ = [
    "DeploymentReadinessReport",
    "ReadinessCheck",
    "ReadinessContractError",
    "default_profile",
    "load_profile",
    "run_deployment_readiness",
    "validate_profile",
    "validate_readiness_report",
    "write_readiness",
]
