"""Build deployment evidence from explicitly supplied observations.

This tool signs deployment-authority assertions but never observes a VM,
identity provider, control plane, KMS or provider itself. Missing observations,
reviewer separation failures and output collisions are hard errors. The private
key is read only for signing and is never copied to the output artifact.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from pathlib import Path
from typing import Any, Mapping


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from pmiri.canonical import canonical_json, is_sha256, sha256_bytes, sha256_json  # noqa: E402
from pmiri.deployment_evidence import (  # noqa: E402
    EXTERNAL_REQUIREMENTS,
    FINAL_ACCEPTANCE_ASSERTIONS,
    EVIDENCE_KIND,
    EVIDENCE_VERSION,
    FINAL_EVIDENCE_KIND,
    FINAL_EVIDENCE_VERSION,
    verify_external_evidence,
    verify_final_acceptance_evidence,
)
from pmiri.integrity import authority_fingerprint  # noqa: E402
from pmiri.readiness import validate_profile, validate_readiness_report  # noqa: E402


class EvidenceBuildError(ValueError):
    """Raised when a supplied evidence input cannot be signed safely."""


def _read_json(path: str | Path, error_code: str) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceBuildError(error_code) from exc
    if not isinstance(value, dict):
        raise EvidenceBuildError(error_code)
    return value


def _load_private_key(path: str | Path) -> Ed25519PrivateKey:
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise EvidenceBuildError("evidence_private_key_unreadable") from exc
    try:
        if raw.startswith(b"-----BEGIN"):
            key = serialization.load_pem_private_key(raw, password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise EvidenceBuildError("evidence_private_key_algorithm_invalid")
            return key
        if len(raw) != 32:
            raise EvidenceBuildError("evidence_private_key_encoding_invalid")
        return Ed25519PrivateKey.from_private_bytes(raw)
    except EvidenceBuildError:
        raise
    except (ValueError, TypeError) as exc:
        raise EvidenceBuildError("evidence_private_key_invalid") from exc


def _required_text(value: Any, error_code: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceBuildError(error_code)
    return value


def _validate_common_manifest(manifest: Mapping[str, Any], checks_key: str, expected_ids: tuple[str, ...]) -> tuple[str, str, str, Mapping[str, Any]]:
    required = {"issuer_principal_id", "reviewer_id", "review_evidence_ref", checks_key}
    if set(manifest) != required:
        raise EvidenceBuildError("evidence_observation_manifest_fields_invalid")
    issuer_id = _required_text(manifest.get("issuer_principal_id"), "evidence_issuer_id_invalid")
    reviewer_id = _required_text(manifest.get("reviewer_id"), "evidence_reviewer_id_invalid")
    review_ref = _required_text(manifest.get("review_evidence_ref"), "evidence_review_reference_invalid")
    if issuer_id == reviewer_id:
        raise EvidenceBuildError("evidence_reviewer_not_independent")
    observations = manifest.get(checks_key)
    if not isinstance(observations, dict) or set(observations) != set(expected_ids):
        raise EvidenceBuildError("evidence_observation_set_invalid")
    return issuer_id, reviewer_id, review_ref, observations


def _observation_fields(value: Any) -> tuple[list[str], str]:
    if not isinstance(value, dict) or set(value) != {"evidence_refs", "observation"}:
        raise EvidenceBuildError("evidence_observation_fields_invalid")
    refs = value.get("evidence_refs")
    if not isinstance(refs, list) or not refs or any(not isinstance(ref, str) or not ref.strip() for ref in refs):
        raise EvidenceBuildError("evidence_observation_refs_invalid")
    observation = _required_text(value.get("observation"), "evidence_observation_text_invalid")
    return refs, observation


def _load_external_inputs(profile_path: str | Path, observations_path: str | Path) -> tuple[dict[str, Any], str, str, str, dict[str, Any]]:
    profile = _read_json(profile_path, "evidence_profile_invalid")
    try:
        validate_profile(profile)
    except ValueError as exc:
        raise EvidenceBuildError("evidence_profile_invalid") from exc
    manifest = _read_json(observations_path, "evidence_observation_manifest_invalid")
    issuer_id, reviewer_id, review_ref, observations = _validate_common_manifest(
        manifest,
        "checks",
        tuple(check_id for check_id, _ in EXTERNAL_REQUIREMENTS),
    )
    for check_id, _ in EXTERNAL_REQUIREMENTS:
        _observation_fields(observations[check_id])
    return profile, issuer_id, reviewer_id, review_ref, observations


def validate_external_observations(profile_path: str | Path, observations_path: str | Path) -> dict[str, Any]:
    """Validate EXT-01..EXT-06 observations without loading a signing key."""

    profile, _, reviewer_id, review_ref, _ = _load_external_inputs(profile_path, observations_path)
    return {
        "artifact_kind": EVIDENCE_KIND,
        "profile_id": _required_text(profile.get("profile_id"), "evidence_profile_id_invalid"),
        "profile_fingerprint": sha256_json(profile),
        "check_ids": [check_id for check_id, _ in EXTERNAL_REQUIREMENTS],
        "reviewer_id": reviewer_id,
        "review_evidence_ref": review_ref,
    }


def _load_final_inputs(
    project_root: str | Path,
    profile_path: str | Path,
    readiness_report_path: str | Path,
    observations_path: str | Path,
) -> tuple[Path, dict[str, Any], str, str, str, str, dict[str, Any]]:
    root = Path(project_root).resolve()
    profile = _read_json(profile_path, "evidence_profile_invalid")
    try:
        validate_profile(profile)
    except ValueError as exc:
        raise EvidenceBuildError("evidence_profile_invalid") from exc
    readiness = _read_json(readiness_report_path, "evidence_readiness_report_invalid")
    readiness_errors = validate_readiness_report(readiness)
    if readiness_errors or readiness.get("overall_result") != "DEPLOYMENT_READY":
        raise EvidenceBuildError("evidence_readiness_report_invalid")
    try:
        readiness_root = Path(str(readiness["project_root"])).resolve()
    except (KeyError, OSError, TypeError, ValueError) as exc:
        raise EvidenceBuildError("evidence_readiness_report_invalid") from exc
    if readiness_root != root:
        raise EvidenceBuildError("evidence_readiness_project_root_mismatch")
    profile_fingerprint = sha256_json(profile)
    if readiness.get("profile_id") != profile.get("profile_id") or readiness.get("profile_fingerprint") != profile_fingerprint:
        raise EvidenceBuildError("evidence_readiness_profile_binding_mismatch")
    readiness_fingerprint = readiness.get("report_fingerprint")
    if not is_sha256(readiness_fingerprint):
        raise EvidenceBuildError("evidence_readiness_fingerprint_invalid")
    manifest = _read_json(observations_path, "evidence_observation_manifest_invalid")
    issuer_id, reviewer_id, review_ref, observations = _validate_common_manifest(
        manifest,
        "assertions",
        tuple(check_id for check_id, _, _ in FINAL_ACCEPTANCE_ASSERTIONS),
    )
    for check_id, _, _ in FINAL_ACCEPTANCE_ASSERTIONS:
        _observation_fields(observations[check_id])
    return root, profile, readiness_fingerprint, issuer_id, reviewer_id, review_ref, observations


def validate_final_acceptance_observations(
    project_root: str | Path,
    profile_path: str | Path,
    readiness_report_path: str | Path,
    observations_path: str | Path,
) -> dict[str, Any]:
    """Validate FA-02..FA-06 observations without loading a signing key."""

    _, profile, readiness_fingerprint, _, reviewer_id, review_ref, _ = _load_final_inputs(
        project_root, profile_path, readiness_report_path, observations_path
    )
    return {
        "artifact_kind": FINAL_EVIDENCE_KIND,
        "profile_id": _required_text(profile.get("profile_id"), "evidence_profile_id_invalid"),
        "profile_fingerprint": sha256_json(profile),
        "readiness_report_fingerprint": readiness_fingerprint,
        "assertion_ids": [check_id for check_id, _, _ in FINAL_ACCEPTANCE_ASSERTIONS],
        "reviewer_id": reviewer_id,
        "review_evidence_ref": review_ref,
    }


def _write_new_json(path: str | Path, record: Mapping[str, Any]) -> None:
    destination = Path(path)
    if destination.exists():
        raise EvidenceBuildError("evidence_output_exists")
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(record, stream, ensure_ascii=False, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise EvidenceBuildError("evidence_output_exists") from exc
    except OSError as exc:
        raise EvidenceBuildError("evidence_output_write_failed") from exc


def _sign_record(unsigned: Mapping[str, Any], private_key: Ed25519PrivateKey) -> dict[str, Any]:
    payload_sha256 = sha256_json(unsigned)
    signed_payload = {**unsigned, "payload_sha256": payload_sha256}
    signature = base64.b64encode(private_key.sign(canonical_json(signed_payload))).decode("ascii")
    return {**signed_payload, "signature": signature}


def build_external_evidence(
    project_root: str | Path,
    profile_path: str | Path,
    observations_path: str | Path,
    private_key_path: str | Path,
    output_path: str | Path,
) -> dict[str, Any]:
    """Sign an EXT-01..EXT-06 bundle from a strict observation manifest."""

    root = Path(project_root).resolve()
    profile, issuer_id, reviewer_id, review_ref, observations = _load_external_inputs(profile_path, observations_path)
    private_key = _load_private_key(private_key_path)
    public_key = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    checks = []
    for check_id, assertion in EXTERNAL_REQUIREMENTS:
        refs, observation = _observation_fields(observations[check_id])
        item = {
            "check_id": check_id,
            "assertion": assertion,
            "result": "READY",
            "evidence_refs": refs,
            "observation": observation,
        }
        item["observed_fingerprint"] = sha256_json({key: item[key] for key in ("check_id", "assertion", "result", "observation", "evidence_refs")})
        checks.append(item)
    unsigned = {
        "artifact_kind": EVIDENCE_KIND,
        "version": EVIDENCE_VERSION,
        "status": "VERIFIED",
        "profile_id": _required_text(profile.get("profile_id"), "evidence_profile_id_invalid"),
        "profile_fingerprint": sha256_json(profile),
        "authority_fingerprint": authority_fingerprint(root),
        "checks": checks,
        "issuer": {"key_id": sha256_bytes(public_key), "principal_id": issuer_id, "role": "deployment_authority"},
        "independent_review": {"reviewer_id": reviewer_id, "review_result": "ACCEPTED", "evidence_ref": review_ref},
    }
    record = _sign_record(unsigned, private_key)
    _write_new_json(output_path, record)
    verify_external_evidence(
        output_path,
        trusted_public_key=public_key,
        profile_id=unsigned["profile_id"],
        profile_fingerprint=unsigned["profile_fingerprint"],
        authority_fingerprint=unsigned["authority_fingerprint"],
    )
    return {"artifact_kind": EVIDENCE_KIND, "payload_sha256": record["payload_sha256"], "issuer_key_id": sha256_bytes(public_key), "reviewer_id": reviewer_id}


def build_final_acceptance_evidence(
    project_root: str | Path,
    profile_path: str | Path,
    readiness_report_path: str | Path,
    observations_path: str | Path,
    private_key_path: str | Path,
    output_path: str | Path,
) -> dict[str, Any]:
    """Sign FA-02..FA-06 assertions from a strict acceptance manifest."""

    root, profile, readiness_fingerprint, issuer_id, reviewer_id, review_ref, observations = _load_final_inputs(
        project_root, profile_path, readiness_report_path, observations_path
    )
    profile_fingerprint = sha256_json(profile)
    private_key = _load_private_key(private_key_path)
    public_key = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assertions = []
    for check_id, assertion, observed_values in FINAL_ACCEPTANCE_ASSERTIONS:
        refs, observation = _observation_fields(observations[check_id])
        item = {
            "check_id": check_id,
            "assertion": assertion,
            "result": "READY",
            "observed_values": observed_values,
            "evidence_refs": refs,
            "observation": observation,
        }
        item["observed_fingerprint"] = sha256_json({key: item[key] for key in ("check_id", "assertion", "result", "observed_values", "evidence_refs", "observation")})
        assertions.append(item)
    unsigned = {
        "artifact_kind": FINAL_EVIDENCE_KIND,
        "version": FINAL_EVIDENCE_VERSION,
        "status": "VERIFIED",
        "profile_id": _required_text(profile.get("profile_id"), "evidence_profile_id_invalid"),
        "profile_fingerprint": profile_fingerprint,
        "authority_fingerprint": authority_fingerprint(root),
        "readiness_report_fingerprint": readiness_fingerprint,
        "assertions": assertions,
        "issuer": {"key_id": sha256_bytes(public_key), "principal_id": issuer_id, "role": "deployment_authority"},
        "independent_review": {"reviewer_id": reviewer_id, "review_result": "ACCEPTED", "evidence_ref": review_ref},
    }
    record = _sign_record(unsigned, private_key)
    _write_new_json(output_path, record)
    verify_final_acceptance_evidence(
        output_path,
        trusted_public_key=public_key,
        profile_id=unsigned["profile_id"],
        profile_fingerprint=unsigned["profile_fingerprint"],
        authority_fingerprint=unsigned["authority_fingerprint"],
        readiness_report_fingerprint=readiness_fingerprint,
    )
    return {"artifact_kind": FINAL_EVIDENCE_KIND, "payload_sha256": record["payload_sha256"], "issuer_key_id": sha256_bytes(public_key), "reviewer_id": reviewer_id}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Sign explicit PMIRI deployment observations")
    subparsers = parser.add_subparsers(dest="command", required=True)
    external = subparsers.add_parser("external", help="build signed EXT-01..EXT-06 evidence")
    external.add_argument("--project-root", required=True)
    external.add_argument("--profile", required=True)
    external.add_argument("--observations", required=True)
    external.add_argument("--private-key", required=True)
    external.add_argument("--output", required=True)
    final = subparsers.add_parser("final", help="build signed FA-02..FA-06 acceptance evidence")
    final.add_argument("--project-root", required=True)
    final.add_argument("--profile", required=True)
    final.add_argument("--readiness-report", required=True)
    final.add_argument("--observations", required=True)
    final.add_argument("--private-key", required=True)
    final.add_argument("--output", required=True)
    validate = subparsers.add_parser("validate", help="validate supplied observations without signing or writing evidence")
    validate_subparsers = validate.add_subparsers(dest="validation_command", required=True)
    validate_external = validate_subparsers.add_parser("external", help="validate EXT-01..EXT-06 observations")
    validate_external.add_argument("--profile", required=True)
    validate_external.add_argument("--observations", required=True)
    validate_final = validate_subparsers.add_parser("final", help="validate FA-02..FA-06 observations")
    validate_final.add_argument("--project-root", required=True)
    validate_final.add_argument("--profile", required=True)
    validate_final.add_argument("--readiness-report", required=True)
    validate_final.add_argument("--observations", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "validate":
            if args.validation_command == "external":
                result = validate_external_observations(args.profile, args.observations)
            else:
                result = validate_final_acceptance_observations(args.project_root, args.profile, args.readiness_report, args.observations)
            print(json.dumps({"status": "OBSERVATION_MANIFEST_VALID", **result}, ensure_ascii=False))
            return 0
        if args.command == "external":
            result = build_external_evidence(args.project_root, args.profile, args.observations, args.private_key, args.output)
        else:
            result = build_final_acceptance_evidence(args.project_root, args.profile, args.readiness_report, args.observations, args.private_key, args.output)
    except (EvidenceBuildError, OSError, ValueError) as exc:
        print(json.dumps({"status": "EVIDENCE_BUILD_BLOCKED", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2
    print(json.dumps({"status": "EVIDENCE_BUILT", "output": str(Path(args.output).resolve()), **result}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
