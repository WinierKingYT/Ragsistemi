"""GC-C1 isolation-attestation artifact builder."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from .canonical import is_sha256, sha256_json, utc_now
from .clean_room import DOMAINS, IsolationObservation, normalize_observation, verify_attestation


LAUNCHER_ID = "pmiri-gc-c1-clean-room-launcher"
LAUNCHER_VERSION = "0.1.0"


def create_attestation(
    *,
    authorization_id: str,
    case_id: str,
    launcher: Mapping[str, Any],
    fingerprints: Mapping[str, str],
    observations: Mapping[str, IsolationObservation],
    case_root_policy: str = "UNVERIFIED",
    case_root_fingerprint: str | None = None,
) -> dict[str, Any]:
    """Serialize observed evidence; absent/invalid observations fail closed."""
    if not authorization_id or not case_id:
        raise ValueError("attestation_identity_missing")
    if set(launcher) != {"launcher_id", "launcher_version"}:
        raise ValueError("launcher_shape_invalid")
    if launcher.get("launcher_id") != LAUNCHER_ID or launcher.get("launcher_version") != LAUNCHER_VERSION:
        raise ValueError("launcher_identity_invalid")
    if case_root_policy not in {"FRESH_CASE_ROOT", "UNVERIFIED"}:
        raise ValueError("case_root_policy_invalid")
    if case_root_fingerprint is None:
        case_root_fingerprint = sha256_json({"case_id": case_id, "root_policy": case_root_policy})
    if not is_sha256(case_root_fingerprint):
        raise ValueError("case_root_fingerprint_invalid")
    required_fingerprints = {"runner_source", "runner_manifest", "authority_bundle", "evidence_schema", "fixture_catalog", "preflight_matrix", "profile"}
    if set(fingerprints) != required_fingerprints:
        raise ValueError("attestation_fingerprint_set_invalid")
    if any(not is_sha256(fingerprints.get(key)) for key in required_fingerprints):
        raise ValueError("attestation_fingerprint_missing_or_invalid")
    if set(observations) != set(DOMAINS):
        raise ValueError("attestation_domains_incomplete")
    ready, outcome = verify_attestation(observations)
    if ready and case_root_policy != "FRESH_CASE_ROOT":
        ready, outcome = False, "BLOCKED"
    status = "VERIFIED" if ready else ("FAILED" if outcome == "ISOLATION_VIOLATION" else "UNVERIFIED")
    record: dict[str, Any] = {
        "attestation_id": "att_" + sha256_json({"authorization_id": authorization_id, "case_id": case_id, "fingerprints": dict(sorted(fingerprints.items()))})[:32],
        "version": "0.1",
        "status": status,
        "launcher": {"launcher_id": LAUNCHER_ID, "launcher_version": LAUNCHER_VERSION},
        "case": {"case_id": case_id, "root_policy": case_root_policy, "root_fingerprint": case_root_fingerprint},
        "authorization_id": authorization_id,
        "fingerprints": dict(sorted(fingerprints.items())),
        "outcome": outcome,
        "captured_at": utc_now(),
    }
    for domain in DOMAINS:
        record[domain] = {
            "result": observations[domain].result,
            "evidence_ref": observations[domain].evidence_ref,
            "observation": observations[domain].observation,
        }
    if not ready:
        record["failure_reason"] = "isolation_evidence_not_ready"
    record["attestation_sha256"] = sha256_json({key: value for key, value in record.items() if key != "attestation_sha256"})
    return record


def write_attestation(record: Mapping[str, Any], path: str | Path) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(dict(record), ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def load_attestation(path: str | Path) -> tuple[dict[str, Any], dict[str, IsolationObservation]]:
    """Load and independently recompute an attestation's digest and status."""
    source = Path(path)
    try:
        record = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("attestation_missing_or_invalid_json") from exc
    if not isinstance(record, dict) or record.get("version") != "0.1":
        raise ValueError("attestation_version_invalid")
    claimed = record.get("attestation_sha256")
    unsigned = {key: value for key, value in record.items() if key != "attestation_sha256"}
    if not is_sha256(claimed) or claimed != sha256_json(unsigned):
        raise ValueError("attestation_digest_mismatch")
    launcher = record.get("launcher", {})
    if set(launcher) != {"launcher_id", "launcher_version"}:
        raise ValueError("launcher_shape_invalid")
    if launcher.get("launcher_id") != LAUNCHER_ID or launcher.get("launcher_version") != LAUNCHER_VERSION:
        raise ValueError("launcher_identity_invalid")
    case = record.get("case", {})
    if set(case) != {"case_id", "root_policy", "root_fingerprint"}:
        raise ValueError("case_shape_invalid")
    if case.get("root_policy") not in {"FRESH_CASE_ROOT", "UNVERIFIED"} or not is_sha256(case.get("root_fingerprint")):
        raise ValueError("case_root_invalid")
    fingerprints = record.get("fingerprints", {})
    required = ("runner_source", "runner_manifest", "authority_bundle", "evidence_schema", "fixture_catalog", "preflight_matrix", "profile")
    if set(fingerprints) != set(required):
        raise ValueError("attestation_fingerprint_set_invalid")
    if any(not is_sha256(fingerprints.get(key)) for key in required):
        raise ValueError("attestation_fingerprint_missing_or_invalid")
    observations: dict[str, IsolationObservation] = {}
    for domain in DOMAINS:
        raw = record.get(domain)
        if not isinstance(raw, dict):
            raise ValueError("attestation_domain_missing:" + domain)
        allowed_observation_keys = {"result", "evidence_ref", "observation", "observed_at"}
        if set(raw) - allowed_observation_keys:
            raise ValueError("attestation_domain_shape_invalid:" + domain)
        observations[domain] = normalize_observation({"domain": domain, **raw})
    ready, outcome = verify_attestation(observations)
    expected_ready = ready and case.get("root_policy") == "FRESH_CASE_ROOT"
    expected_status = "VERIFIED" if expected_ready else ("FAILED" if outcome == "ISOLATION_VIOLATION" else "UNVERIFIED")
    expected_outcome = "READY_FOR_REPLAY" if expected_ready else ("BLOCKED" if ready else outcome)
    if record.get("status") != expected_status or record.get("outcome") != expected_outcome:
        raise ValueError("attestation_status_tampered")
    return record, observations


__all__ = ["LAUNCHER_ID", "LAUNCHER_VERSION", "create_attestation", "load_attestation", "write_attestation"]
