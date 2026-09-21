"""Gate-D R1 security bindings and non-ordinal egress decisions.

The R1 contracts are intentionally represented as small immutable records.  A
record is useful only when the complete validity tuple is present; a filename,
object id or cached allow is never treated as authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from .canonical import is_sha256, sha256_json, utc_now


CLASSIFICATIONS = frozenset({"PUBLIC", "CLOUD_OK", "RESTRICTED", "LOCAL_ONLY"})
AUTHORIZATION_RESULTS = frozenset({"ALLOW", "DENY", "INDETERMINATE", "REVALIDATE_REQUIRED"})
DISCLOSURE_RESULTS = frozenset({"DISCLOSE_AS_IS", "DISCLOSE_REDACTED", "DISCLOSE_COARSENED", "OPAQUE_NOT_AVAILABLE", "DENY", "INDETERMINATE"})
EGRESS_RESULTS = frozenset({"ALLOW_AS_IS", "ALLOW_WITH_CONSTRAINTS", "RECOMPILE_REQUIRED_WITH_CONSTRAINTS", "DENY", "INDETERMINATE"})


class SecurityContractViolation(ValueError):
    pass


def _parse_time(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if isinstance(value, str) and value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timestamp_must_be_timezone_aware")
    return parsed.astimezone(timezone.utc)


def _valid_interval(valid_from: str, valid_until: str | None, now: str) -> bool:
    try:
        start = _parse_time(valid_from)
        end = _parse_time(valid_until) if valid_until else None
        current = _parse_time(now)
        return start <= current and (end is None or current <= end)
    except (TypeError, ValueError):
        return False


def _normalized_scope(scope: Mapping[str, Iterable[str]]) -> dict[str, tuple[str, ...]]:
    result: dict[str, tuple[str, ...]] = {}
    for key, values in scope.items():
        if isinstance(values, str):
            raise SecurityContractViolation("authority_scope_must_be_array")
        result[str(key)] = tuple(sorted({str(value) for value in values}))
    return result


def intersect_authority(scopes: Iterable[Mapping[str, Iterable[str]]]) -> dict[str, tuple[str, ...]]:
    """Intersect every delegation/restriction; never union privileges."""
    normalized = [_normalized_scope(scope) for scope in scopes]
    if not normalized:
        return {}
    keys = set(normalized[0])
    for scope in normalized[1:]:
        keys &= set(scope)
    return {key: tuple(sorted(set.intersection(*(set(scope[key]) for scope in normalized)))) for key in sorted(keys)}


@dataclass(frozen=True)
class AuthorizationSubjectChain:
    service_principal_ref: str
    originating_trust_zone_attestation_ref: str
    operation_ref: str
    purpose_binding_ref: str
    effective_authority: Mapping[str, tuple[str, ...]]
    human_principal_ref: str | None = None
    workload_principal_ref: str | None = None
    delegation_grant_refs: tuple[str, ...] = ()

    @classmethod
    def derive(
        cls,
        *,
        service_principal_ref: str,
        originating_trust_zone_attestation_ref: str,
        operation_ref: str,
        purpose_binding_ref: str,
        scopes: Iterable[Mapping[str, Iterable[str]]],
        human_principal_ref: str | None = None,
        workload_principal_ref: str | None = None,
        delegation_grant_refs: Iterable[str] = (),
    ) -> "AuthorizationSubjectChain":
        required = (service_principal_ref, originating_trust_zone_attestation_ref, operation_ref, purpose_binding_ref)
        if not all(isinstance(value, str) and value for value in required):
            raise SecurityContractViolation("subject_chain_required_component_missing")
        effective = intersect_authority(scopes)
        if not effective or not any(effective.values()):
            raise SecurityContractViolation("effective_authority_empty")
        return cls(
            service_principal_ref=service_principal_ref,
            originating_trust_zone_attestation_ref=originating_trust_zone_attestation_ref,
            operation_ref=operation_ref,
            purpose_binding_ref=purpose_binding_ref,
            effective_authority=effective,
            human_principal_ref=human_principal_ref,
            workload_principal_ref=workload_principal_ref,
            delegation_grant_refs=tuple(sorted(set(delegation_grant_refs))),
        )

    @property
    def fingerprint(self) -> str:
        return sha256_json(
            {
                "human_principal_ref": self.human_principal_ref,
                "service_principal_ref": self.service_principal_ref,
                "workload_principal_ref": self.workload_principal_ref,
                "delegation_grant_refs": list(self.delegation_grant_refs),
                "originating_trust_zone_attestation_ref": self.originating_trust_zone_attestation_ref,
                "operation_ref": self.operation_ref,
                "purpose_binding_ref": self.purpose_binding_ref,
                "effective_authority": dict(sorted(self.effective_authority.items())),
            }
        )


@dataclass(frozen=True)
class PurposeBinding:
    purpose_binding_id: str
    operation_ref: str
    recognized_purpose: str
    derivation_ref: str
    fingerprint: str

    @classmethod
    def create(cls, *, operation_ref: str, recognized_purpose: str, derivation_ref: str) -> "PurposeBinding":
        if not all(isinstance(value, str) and value for value in (operation_ref, recognized_purpose, derivation_ref)):
            raise SecurityContractViolation("purpose_binding_missing")
        payload = {"operation_ref": operation_ref, "recognized_purpose": recognized_purpose, "derivation_ref": derivation_ref}
        return cls(_ref("purpose", payload), operation_ref, recognized_purpose, derivation_ref, sha256_json(payload))

    def verify_requested_purpose(self, requested_purpose: str | None) -> None:
        if requested_purpose is not None and requested_purpose != self.recognized_purpose:
            raise SecurityContractViolation("purpose_relabeling_forbidden")


@dataclass(frozen=True)
class SecurityClassificationBinding:
    binding_id: str
    target_kind: str
    target_id: str
    classification: str
    assigning_authority_ref: str
    policy_basis_ref: str
    provenance_ref: str
    valid_from: str
    valid_until: str | None = None

    def is_valid(self, *, now: str) -> bool:
        return self.classification in CLASSIFICATIONS and _valid_interval(self.valid_from, self.valid_until, now)


def evaluate_classification_change(
    *,
    prior: SecurityClassificationBinding | None,
    requested: SecurityClassificationBinding,
    authorized_actor_ref: str,
    policy_basis_version: str,
    now: str,
) -> dict[str, Any]:
    """Allow classification changes only at an explicit trusted boundary."""
    reasons: list[str] = []
    if requested.classification not in CLASSIFICATIONS:
        reasons.append("CLASSIFICATION_UNKNOWN")
    if not authorized_actor_ref or not policy_basis_version:
        reasons.append("AUTHORITY_MISSING")
    if not requested.is_valid(now=now):
        reasons.append("VALIDITY_INVALID")
    if prior and (prior.target_kind != requested.target_kind or prior.target_id != requested.target_id):
        reasons.append("TARGET_MISMATCH")
    result = "ACCEPT" if not reasons else ("DENY" if "AUTHORITY_MISSING" in reasons else "INDETERMINATE")
    return {
        "target_ref": f"{requested.target_kind}://{requested.target_id}",
        "prior_binding_ref": prior.binding_id if prior else None,
        "requested_binding_ref": requested.binding_id,
        "authorized_actor_ref": authorized_actor_ref,
        "policy_basis_version": policy_basis_version,
        "result": result,
        "reason_codes": reasons or ["NONE"],
        "recorded_at": now,
        "fingerprint": sha256_json({"requested": requested.binding_id, "prior": prior.binding_id if prior else None, "result": result, "reasons": reasons}),
    }


@dataclass(frozen=True)
class DerivedSensitivityAssessment:
    assessment_id: str
    derived_artifact_ref: str
    input_security_lineage_refs: tuple[str, ...]
    aggregation_semantics_ref: str | None
    policy_epoch: int
    result: str
    required_security_bindings: tuple[str, ...]
    fingerprint: str

    @classmethod
    def assess(
        cls,
        *,
        derived_artifact_ref: str,
        input_security_lineage_refs: Iterable[str],
        aggregation_semantics_ref: str | None,
        policy_epoch: int,
        additional_restriction_required: bool = False,
        required_security_bindings: Iterable[str] = (),
    ) -> "DerivedSensitivityAssessment":
        lineage = tuple(sorted(set(input_security_lineage_refs)))
        bindings = tuple(sorted(set(required_security_bindings)))
        if not lineage or not aggregation_semantics_ref:
            result = "INDETERMINATE"
        elif additional_restriction_required:
            result = "ADDITIONAL_RESTRICTION_REQUIRED"
        else:
            result = "NO_NEW_RESTRICTION_IDENTIFIED"
        payload = {
            "derived_artifact_ref": derived_artifact_ref,
            "input_security_lineage_refs": list(lineage),
            "aggregation_semantics_ref": aggregation_semantics_ref,
            "policy_epoch": policy_epoch,
            "result": result,
            "required_security_bindings": list(bindings),
        }
        return cls(_ref("assessment", payload), derived_artifact_ref, lineage, aggregation_semantics_ref, policy_epoch, result, bindings, sha256_json(payload))


@dataclass(frozen=True)
class SecurityDecisionValidity:
    subject_chain_fingerprint: str
    trust_zone_fingerprint: str
    purpose: str
    material_manifest_fingerprint: str
    operation: str
    policy_version: str
    policy_epoch: int
    destination_binding_fingerprint: str | None
    valid_until: str

    def is_valid(self, *, current: "SecurityDecisionValidity", now: str) -> bool:
        return self == current and _valid_interval("1970-01-01T00:00:00Z", self.valid_until, now)


@dataclass(frozen=True)
class EgressMaterialManifest:
    manifest_id: str
    source_refs: tuple[str, ...]
    security_lineage_refs: tuple[str, ...]
    derived_sensitivity_refs: tuple[str, ...]
    semantic_obligation_refs: tuple[str, ...]
    material_members_digest: str
    policy_epoch: int
    fingerprint: str

    @classmethod
    def create(cls, *, source_refs: Iterable[str], security_lineage_refs: Iterable[str], derived_sensitivity_refs: Iterable[str], semantic_obligation_refs: Iterable[str], material_members: Iterable[str], policy_epoch: int) -> "EgressMaterialManifest":
        sources = tuple(sorted(set(source_refs)))
        lineage = tuple(sorted(set(security_lineage_refs)))
        assessments = tuple(sorted(set(derived_sensitivity_refs)))
        obligations = tuple(sorted(set(semantic_obligation_refs)))
        members_digest = sha256_json(list(material_members))
        payload = {"source_refs": list(sources), "security_lineage_refs": list(lineage), "derived_sensitivity_refs": list(assessments), "semantic_obligation_refs": list(obligations), "material_members_digest": members_digest, "policy_epoch": policy_epoch}
        return cls(_ref("manifest", payload), sources, lineage, assessments, obligations, members_digest, policy_epoch, sha256_json(payload))


@dataclass(frozen=True)
class EgressDecision:
    result: str
    reason: str
    validity: SecurityDecisionValidity
    material_manifest_fingerprint: str
    destination_binding_fingerprint: str | None
    fingerprint: str

    @classmethod
    def evaluate(
        cls,
        *,
        validity: SecurityDecisionValidity,
        current_validity: SecurityDecisionValidity,
        manifest: EgressMaterialManifest,
        destination_binding_fingerprint: str | None,
        destination_kind: str,
        classifications: Iterable[SecurityClassificationBinding | None],
        sensitivity: DerivedSensitivityAssessment,
        now: str,
        constrained: bool = False,
    ) -> "EgressDecision":
        reason = "NONE"
        result = "ALLOW_WITH_CONSTRAINTS" if constrained else "ALLOW_AS_IS"
        if not validity.is_valid(current=current_validity, now=now):
            result, reason = "RECOMPILE_REQUIRED_WITH_CONSTRAINTS", "POLICY_EPOCH_CHANGED"
        elif validity.material_manifest_fingerprint != manifest.fingerprint:
            result, reason = "DENY", "MATERIAL_FINGERPRINT_MISMATCH"
        elif destination_binding_fingerprint != validity.destination_binding_fingerprint:
            result, reason = "DENY", "EXACT_BINDING_MISSING"
        elif destination_kind == "EXTERNAL_PROVIDER" and any(binding is None or not binding.is_valid(now=now) or binding.classification == "LOCAL_ONLY" for binding in classifications):
            result, reason = "DENY", "CLASSIFICATION_MISMATCH"
        elif sensitivity.result == "INDETERMINATE":
            result, reason = "INDETERMINATE", "CLASSIFICATION_UNKNOWN"
        elif sensitivity.result == "ADDITIONAL_RESTRICTION_REQUIRED":
            result, reason = "RECOMPILE_REQUIRED_WITH_CONSTRAINTS", "ADDITIONAL_RESTRICTION_REQUIRED"
        payload = {"result": result, "reason": reason, "validity": validity.__dict__, "material_manifest_fingerprint": manifest.fingerprint, "destination": destination_binding_fingerprint}
        return cls(result, reason, validity, manifest.fingerprint, destination_binding_fingerprint, sha256_json(payload))


class ProviderSendFence:
    """Final R1 enforcement point for an injected provider transport."""

    def authorize(self, decision: EgressDecision, *, current_context_fingerprint: str, expected_context_fingerprint: str) -> None:
        if decision.result not in {"ALLOW_AS_IS", "ALLOW_WITH_CONSTRAINTS"}:
            raise PermissionError(decision.reason)
        if current_context_fingerprint != expected_context_fingerprint:
            raise PermissionError("context_revalidation_required")


def _ref(kind: str, value: Any) -> str:
    return f"{kind}://{sha256_json(value)[:32]}"


__all__ = [
    "AUTHORIZATION_RESULTS",
    "CLASSIFICATIONS",
    "DISCLOSURE_RESULTS",
    "EgressDecision",
    "EgressMaterialManifest",
    "AuthorizationSubjectChain",
    "DerivedSensitivityAssessment",
    "PurposeBinding",
    "ProviderSendFence",
    "SecurityClassificationBinding",
    "SecurityContractViolation",
    "SecurityDecisionValidity",
    "EGRESS_RESULTS",
    "evaluate_classification_change",
    "intersect_authority",
]
