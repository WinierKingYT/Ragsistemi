"""Verification boundary for externally signed deployment evidence.

This module consumes a deployment-supplied Ed25519-signed evidence bundle. It
does not observe a clean room, contact an identity provider, perform network
I/O or turn a profile into authority. The trusted public key and signed
observations must come from the authorized deployment process.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonical_json, is_sha256, sha256_bytes, sha256_json


EVIDENCE_KIND = "PMIRI-DEPLOYMENT-EXTERNAL-EVIDENCE"
EVIDENCE_VERSION = "0.1"
FINAL_EVIDENCE_KIND = "PMIRI-FINAL-ACCEPTANCE-EVIDENCE"
FINAL_EVIDENCE_VERSION = "0.1"
EXTERNAL_REQUIREMENTS = (
    ("EXT-01", "INDEPENDENT_CLEAN_ROOM"),
    ("EXT-02", "DEPLOYED_IDENTITY_PROVIDER"),
    ("EXT-03", "DISTRIBUTED_CONTROL_PLANE"),
    ("EXT-04", "METADATA_ENCRYPTION_AND_KEY_ESCROW"),
    ("EXT-05", "REAL_PROVIDER_CONNECTOR_AUTHORIZATION"),
    ("EXT-06", "INDEPENDENT_GATE_D_RECHECK"),
)
FINAL_ACCEPTANCE_ASSERTIONS = (
    ("FA-02", "D2_CONTROLLED_ACCEPTANCE", {"scenario_count": 34, "all_oracles_match": True, "runtime_execution": "CONTROLLED", "d2_acceptance": "ACCEPTED"}),
    ("FA-03", "R_FC_17_OF_17_PASS", {"required_obligations": 17, "passed_obligations": 17, "r_fc_pass": "PASS", "runtime_execution": "CONTROLLED"}),
    ("FA-04", "MIGRATION_RESTORE_FAILOVER_ACCEPTED", {"migration": "ACCEPTED", "restore": "ACCEPTED", "failover": "ACCEPTED"}),
    ("FA-05", "INDEPENDENT_D2_R_FC_REVIEW", {"d2_review": "ACCEPTED", "r_fc_review": "ACCEPTED"}),
    ("FA-06", "OPERATIONS_APPROVAL", {"status": "APPROVED"}),
)


class DeploymentEvidenceError(ValueError):
    """Raised when signed deployment evidence cannot be trusted."""


@dataclass(frozen=True)
class VerifiedDeploymentEvidence:
    evidence_fingerprint: str
    checks: Mapping[str, Mapping[str, Any]]
    issuer_id: str
    reviewer_id: str


@dataclass(frozen=True)
class VerifiedFinalAcceptanceEvidence:
    evidence_fingerprint: str
    assertions: Mapping[str, Mapping[str, Any]]
    issuer_id: str
    reviewer_id: str


def _decode_public_key(value: bytes) -> bytes:
    if not isinstance(value, bytes) or not value:
        raise DeploymentEvidenceError("deployment_public_key_missing")
    if value.startswith(b"-----BEGIN"):
        try:
            key = serialization.load_pem_public_key(value)
        except (ValueError, TypeError) as exc:
            raise DeploymentEvidenceError("deployment_public_key_invalid") from exc
        if not isinstance(key, Ed25519PublicKey):
            raise DeploymentEvidenceError("deployment_public_key_algorithm_invalid")
        return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if len(value) == 32:
        return value
    try:
        decoded = base64.b64decode(value.strip(), validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise DeploymentEvidenceError("deployment_public_key_encoding_invalid") from exc
    if len(decoded) != 32:
        raise DeploymentEvidenceError("deployment_public_key_length_invalid")
    return decoded


def _read_record(path: str | Path) -> dict[str, Any]:
    try:
        record = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DeploymentEvidenceError("deployment_evidence_invalid_json") from exc
    if not isinstance(record, dict):
        raise DeploymentEvidenceError("deployment_evidence_shape_invalid")
    return record


def verify_external_evidence(
    path: str | Path,
    *,
    trusted_public_key: bytes,
    profile_id: str,
    profile_fingerprint: str,
    authority_fingerprint: str,
) -> VerifiedDeploymentEvidence:
    """Verify an external evidence bundle against local immutable inputs."""
    record = _read_record(path)
    required = {
        "artifact_kind", "version", "status", "profile_id", "profile_fingerprint",
        "authority_fingerprint", "checks", "issuer", "independent_review",
        "payload_sha256", "signature",
    }
    if set(record) != required:
        raise DeploymentEvidenceError("deployment_evidence_fields_invalid")
    if record.get("artifact_kind") != EVIDENCE_KIND or record.get("version") != EVIDENCE_VERSION or record.get("status") != "VERIFIED":
        raise DeploymentEvidenceError("deployment_evidence_identity_invalid")
    if record.get("profile_id") != profile_id or record.get("profile_fingerprint") != profile_fingerprint:
        raise DeploymentEvidenceError("deployment_evidence_profile_binding_mismatch")
    if record.get("authority_fingerprint") != authority_fingerprint:
        raise DeploymentEvidenceError("deployment_evidence_authority_binding_mismatch")
    if not is_sha256(profile_fingerprint) or not is_sha256(authority_fingerprint):
        raise DeploymentEvidenceError("deployment_evidence_fingerprint_invalid")

    issuer = record.get("issuer")
    review = record.get("independent_review")
    if not isinstance(issuer, dict) or set(issuer) != {"key_id", "principal_id", "role"}:
        raise DeploymentEvidenceError("deployment_evidence_issuer_invalid")
    if issuer.get("role") != "deployment_authority" or not isinstance(issuer.get("principal_id"), str) or not issuer["principal_id"]:
        raise DeploymentEvidenceError("deployment_evidence_issuer_invalid")
    if not isinstance(review, dict) or set(review) != {"reviewer_id", "review_result", "evidence_ref"}:
        raise DeploymentEvidenceError("deployment_evidence_review_invalid")
    if review.get("review_result") != "ACCEPTED" or not isinstance(review.get("reviewer_id"), str) or not review["reviewer_id"] or not isinstance(review.get("evidence_ref"), str) or not review["evidence_ref"]:
        raise DeploymentEvidenceError("deployment_evidence_review_invalid")
    if issuer["principal_id"] == review["reviewer_id"]:
        raise DeploymentEvidenceError("deployment_evidence_reviewer_not_independent")

    checks = record.get("checks")
    expected = dict(EXTERNAL_REQUIREMENTS)
    if not isinstance(checks, list) or [item.get("check_id") for item in checks if isinstance(item, dict)] != sorted(expected):
        raise DeploymentEvidenceError("deployment_evidence_checks_invalid")
    normalized: dict[str, Mapping[str, Any]] = {}
    for item in checks:
        if not isinstance(item, dict) or set(item) != {"check_id", "assertion", "result", "evidence_refs", "observation", "observed_fingerprint"}:
            raise DeploymentEvidenceError("deployment_evidence_check_shape_invalid")
        check_id = item.get("check_id")
        if check_id not in expected or item.get("assertion") != expected[check_id] or item.get("result") != "READY":
            raise DeploymentEvidenceError("deployment_evidence_check_identity_invalid")
        refs = item.get("evidence_refs")
        if not isinstance(refs, list) or not refs or any(not isinstance(ref, str) or not ref for ref in refs):
            raise DeploymentEvidenceError("deployment_evidence_check_refs_invalid")
        if not isinstance(item.get("observation"), str) or not item["observation"]:
            raise DeploymentEvidenceError("deployment_evidence_check_observation_invalid")
        expected_fingerprint = sha256_json({key: item[key] for key in ("check_id", "assertion", "result", "observation", "evidence_refs")})
        if item.get("observed_fingerprint") != expected_fingerprint:
            raise DeploymentEvidenceError("deployment_evidence_check_fingerprint_mismatch")
        normalized[check_id] = dict(item)

    public_key = _decode_public_key(trusted_public_key)
    if issuer.get("key_id") != sha256_bytes(public_key):
        raise DeploymentEvidenceError("deployment_evidence_key_id_mismatch")
    unsigned = {key: value for key, value in record.items() if key not in {"payload_sha256", "signature"}}
    payload_fingerprint = sha256_json(unsigned)
    if record.get("payload_sha256") != payload_fingerprint:
        raise DeploymentEvidenceError("deployment_evidence_payload_fingerprint_mismatch")
    signed_payload = {**unsigned, "payload_sha256": payload_fingerprint}
    signature_value = record.get("signature")
    if not isinstance(signature_value, str):
        raise DeploymentEvidenceError("deployment_evidence_signature_invalid")
    try:
        signature = base64.b64decode(signature_value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError, base64.binascii.Error) as exc:
        raise DeploymentEvidenceError("deployment_evidence_signature_invalid") from exc
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, canonical_json(signed_payload))
    except (InvalidSignature, ValueError) as exc:
        raise DeploymentEvidenceError("deployment_evidence_signature_mismatch") from exc
    return VerifiedDeploymentEvidence(
        evidence_fingerprint=payload_fingerprint,
        checks=normalized,
        issuer_id=issuer["principal_id"],
        reviewer_id=review["reviewer_id"],
    )


def verify_final_acceptance_evidence(
    path: str | Path,
    *,
    trusted_public_key: bytes,
    profile_id: str,
    profile_fingerprint: str,
    authority_fingerprint: str,
    readiness_report_fingerprint: str,
) -> VerifiedFinalAcceptanceEvidence:
    """Verify the signed evidence required by the final acceptance gate.

    This is deliberately separate from the six deployment-readiness checks:
    readiness alone must never be interpreted as D2/R-FC acceptance or
    operational approval.
    """
    record = _read_record(path)
    required = {
        "artifact_kind", "version", "status", "profile_id", "profile_fingerprint",
        "authority_fingerprint", "readiness_report_fingerprint", "assertions",
        "issuer", "independent_review", "payload_sha256", "signature",
    }
    if set(record) != required:
        raise DeploymentEvidenceError("final_acceptance_evidence_fields_invalid")
    if record.get("artifact_kind") != FINAL_EVIDENCE_KIND or record.get("version") != FINAL_EVIDENCE_VERSION or record.get("status") != "VERIFIED":
        raise DeploymentEvidenceError("final_acceptance_evidence_identity_invalid")
    if record.get("profile_id") != profile_id or record.get("profile_fingerprint") != profile_fingerprint:
        raise DeploymentEvidenceError("final_acceptance_evidence_profile_binding_mismatch")
    if record.get("authority_fingerprint") != authority_fingerprint or record.get("readiness_report_fingerprint") != readiness_report_fingerprint:
        raise DeploymentEvidenceError("final_acceptance_evidence_readiness_binding_mismatch")
    if not all(is_sha256(value) for value in (profile_fingerprint, authority_fingerprint, readiness_report_fingerprint)):
        raise DeploymentEvidenceError("final_acceptance_evidence_fingerprint_invalid")

    issuer = record.get("issuer")
    review = record.get("independent_review")
    if not isinstance(issuer, dict) or set(issuer) != {"key_id", "principal_id", "role"}:
        raise DeploymentEvidenceError("final_acceptance_evidence_issuer_invalid")
    if issuer.get("role") != "deployment_authority" or not isinstance(issuer.get("principal_id"), str) or not issuer["principal_id"]:
        raise DeploymentEvidenceError("final_acceptance_evidence_issuer_invalid")
    if not isinstance(review, dict) or set(review) != {"reviewer_id", "review_result", "evidence_ref"}:
        raise DeploymentEvidenceError("final_acceptance_evidence_review_invalid")
    if review.get("review_result") != "ACCEPTED" or not isinstance(review.get("reviewer_id"), str) or not review["reviewer_id"] or not isinstance(review.get("evidence_ref"), str) or not review["evidence_ref"]:
        raise DeploymentEvidenceError("final_acceptance_evidence_review_invalid")
    if issuer["principal_id"] == review["reviewer_id"]:
        raise DeploymentEvidenceError("final_acceptance_evidence_reviewer_not_independent")

    assertions = record.get("assertions")
    expected = {check_id: (assertion, observed_values) for check_id, assertion, observed_values in FINAL_ACCEPTANCE_ASSERTIONS}
    if not isinstance(assertions, list) or [item.get("check_id") for item in assertions if isinstance(item, dict)] != sorted(expected):
        raise DeploymentEvidenceError("final_acceptance_evidence_assertions_invalid")
    normalized: dict[str, Mapping[str, Any]] = {}
    for item in assertions:
        if not isinstance(item, dict) or set(item) != {"check_id", "assertion", "result", "observed_values", "evidence_refs", "observation", "observed_fingerprint"}:
            raise DeploymentEvidenceError("final_acceptance_evidence_assertion_shape_invalid")
        check_id = item.get("check_id")
        if check_id not in expected or item.get("assertion") != expected[check_id][0] or item.get("result") != "READY":
            raise DeploymentEvidenceError("final_acceptance_evidence_assertion_identity_invalid")
        if item.get("observed_values") != expected[check_id][1]:
            raise DeploymentEvidenceError("final_acceptance_evidence_assertion_values_invalid")
        refs = item.get("evidence_refs")
        if not isinstance(refs, list) or not refs or any(not isinstance(ref, str) or not ref for ref in refs):
            raise DeploymentEvidenceError("final_acceptance_evidence_assertion_refs_invalid")
        if not isinstance(item.get("observation"), str) or not item["observation"]:
            raise DeploymentEvidenceError("final_acceptance_evidence_assertion_observation_invalid")
        expected_fingerprint = sha256_json({key: item[key] for key in ("check_id", "assertion", "result", "observed_values", "evidence_refs", "observation")})
        if item.get("observed_fingerprint") != expected_fingerprint:
            raise DeploymentEvidenceError("final_acceptance_evidence_assertion_fingerprint_mismatch")
        normalized[check_id] = dict(item)

    public_key = _decode_public_key(trusted_public_key)
    if issuer.get("key_id") != sha256_bytes(public_key):
        raise DeploymentEvidenceError("final_acceptance_evidence_key_id_mismatch")
    unsigned = {key: value for key, value in record.items() if key not in {"payload_sha256", "signature"}}
    payload_fingerprint = sha256_json(unsigned)
    if record.get("payload_sha256") != payload_fingerprint:
        raise DeploymentEvidenceError("final_acceptance_evidence_payload_fingerprint_mismatch")
    signed_payload = {**unsigned, "payload_sha256": payload_fingerprint}
    signature_value = record.get("signature")
    if not isinstance(signature_value, str):
        raise DeploymentEvidenceError("final_acceptance_evidence_signature_invalid")
    try:
        signature = base64.b64decode(signature_value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError, base64.binascii.Error) as exc:
        raise DeploymentEvidenceError("final_acceptance_evidence_signature_invalid") from exc
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, canonical_json(signed_payload))
    except (InvalidSignature, ValueError) as exc:
        raise DeploymentEvidenceError("final_acceptance_evidence_signature_mismatch") from exc
    return VerifiedFinalAcceptanceEvidence(
        evidence_fingerprint=payload_fingerprint,
        assertions=normalized,
        issuer_id=issuer["principal_id"],
        reviewer_id=review["reviewer_id"],
    )


__all__ = [
    "DeploymentEvidenceError",
    "EVIDENCE_KIND",
    "EVIDENCE_VERSION",
    "EXTERNAL_REQUIREMENTS",
    "FINAL_ACCEPTANCE_ASSERTIONS",
    "FINAL_EVIDENCE_KIND",
    "FINAL_EVIDENCE_VERSION",
    "VerifiedDeploymentEvidence",
    "VerifiedFinalAcceptanceEvidence",
    "verify_external_evidence",
    "verify_final_acceptance_evidence",
]
