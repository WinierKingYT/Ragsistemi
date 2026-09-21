"""Executable, fail-closed pieces of the Gate-D R2 decision model."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
from typing import Any, Iterable, Mapping

from .canonical import is_sha256, sha256_json
from .decisions import ContractViolation
from .network import NetworkDecision, classify_address, normalize_url


POLICY_VALUE_TYPES = {
    "destination_identity": "destination_identity",
    "retention_deletion": "retention_deletion",
    "training_use": "training_use",
    "subprocessors": "subprocessors",
    "processing_region": "processing_region",
    "feature_capability": "feature_capability",
    "structured_output_attachment": "structured_output_attachment",
    "logging_diagnostics": "logging_diagnostics",
    "credential_operation_scope": "credential_operation_scope",
    "redirect_fetch_behavior": "redirect_fetch_behavior",
}
POLICY_VALUE_FIELDS = {
    "destination_identity": frozenset({"value_type", "identity_ref", "normalized_authority", "scheme"}),
    "retention_deletion": frozenset({"value_type", "retention_mode", "deletion_mode"}),
    "training_use": frozenset({"value_type", "training_use"}),
    "subprocessors": frozenset({"value_type", "subprocessors_fingerprint", "subprocessor_count"}),
    "processing_region": frozenset({"value_type", "region", "region_scope"}),
    "feature_capability": frozenset({"value_type", "capability_key", "supported", "capability_profile_ref"}),
    "structured_output_attachment": frozenset({"value_type", "structured_output_supported", "attachment_types", "max_attachment_bytes"}),
    "logging_diagnostics": frozenset({"value_type", "logging_scope"}),
    "credential_operation_scope": frozenset({"value_type", "allowed_operations", "audience"}),
    "redirect_fetch_behavior": frozenset({"value_type", "redirects_allowed", "max_redirect_hops", "revalidate_each_hop"}),
}


@dataclass(frozen=True)
class ResolutionEntry:
    ip: str
    family: str
    policy_status: str


@dataclass(frozen=True)
class ResolutionDecision:
    normalized_target: str
    entries: tuple[ResolutionEntry, ...]
    resolution_set_status: str
    selected_target: ResolutionEntry | None
    action_result: str
    reason_class: str


class NetworkPolicy:
    """Evaluate supplied DNS answers; never performs DNS or socket I/O."""

    def evaluate_resolution(self, url: str, addresses: Iterable[str]) -> ResolutionDecision:
        target = normalize_url(url)
        entries_list = []
        for address in addresses:
            try:
                parsed = ipaddress.ip_address(address)
            except ValueError:
                entries_list.append(ResolutionEntry(ip=address, family="IPv4", policy_status="DENIED_UNALLOWLISTED"))
            else:
                normalized = str(parsed)
                entries_list.append(ResolutionEntry(ip=normalized, family="IPv6" if parsed.version == 6 else "IPv4", policy_status=classify_address(normalized)))
        entries = tuple(entries_list)
        if not entries:
            return ResolutionDecision(target.safe_url(), (), "DENIED_MIXED", None, "DENY", "DNS_UNVALIDATED")
        all_public = all(entry.policy_status == "ALLOWLISTED_PUBLIC" for entry in entries)
        if not all_public:
            return ResolutionDecision(target.safe_url(), entries, "DENIED_MIXED", None, "DENY", "PRIVATE_OR_UNAPPROVED_ADDRESS")
        return ResolutionDecision(target.safe_url(), entries, "ALL_ALLOWLISTED_PUBLIC", entries[0], "DENY", "OUTBOUND_NETWORK_DISABLED")


def create_provider_policy_observation(
    *,
    observation_id: str,
    subject_binding_ref: str,
    policy_dimension: str,
    observed_value: Mapping[str, Any],
    purpose: str,
    material_classes: Iterable[str],
    source_authority_class: str,
    source_ref: str,
    issuer: str,
    observed_at: str,
    valid_until: str,
    policy_version: str,
    freshness_profile: FreshnessProfile,
    invalidation_epoch: int,
    status: str = "ACTIVE",
) -> dict[str, Any]:
    """Create a typed provider-policy observation with a bound value tag."""
    record = {
        "record_type": "PMIRI_D2_PROVIDER_POLICY_OBSERVATION",
        "schema_version": "0.3",
        "observation_id": observation_id,
        "subject_binding_ref": subject_binding_ref,
        "policy_dimension": policy_dimension,
        "observed_value": dict(observed_value),
        "purpose": purpose,
        "material_classes": list(material_classes),
        "source_authority_class": source_authority_class,
        "source_ref": source_ref,
        "issuer": issuer,
        "observed_at": observed_at,
        "valid_until": valid_until,
        "policy_version": policy_version,
        "freshness_profile_id": freshness_profile.profile_id,
        "freshness_profile_fingerprint": freshness_profile.fingerprint,
        "invalidation_epoch": invalidation_epoch,
        "status": status,
    }
    validate_provider_policy_observation({**record, "observation_fingerprint": sha256_json(record)})
    record["observation_fingerprint"] = sha256_json(record)
    return record


def validate_provider_policy_observation(record: Mapping[str, Any]) -> None:
    required = (
        "record_type", "schema_version", "observation_id", "subject_binding_ref", "policy_dimension",
        "observed_value", "purpose", "material_classes", "source_authority_class", "source_ref",
        "issuer", "observed_at", "valid_until", "policy_version", "freshness_profile_id",
        "freshness_profile_fingerprint", "invalidation_epoch", "status", "observation_fingerprint",
    )
    if any(field not in record for field in required):
        raise ContractViolation("provider_policy_observation_missing")
    if set(record) != set(required) or record["record_type"] != "PMIRI_D2_PROVIDER_POLICY_OBSERVATION" or record["schema_version"] != "0.3":
        raise ContractViolation("provider_policy_observation_schema_invalid")
    if not all(isinstance(record[field], str) and record[field] for field in ("observation_id", "subject_binding_ref", "source_ref", "issuer", "policy_version", "freshness_profile_id")):
        raise ContractViolation("provider_policy_observation_identity_invalid")
    dimension = record["policy_dimension"]
    value = record["observed_value"]
    expected_type = POLICY_VALUE_TYPES.get(dimension)
    if expected_type is None or not isinstance(value, Mapping):
        raise ContractViolation("provider_policy_observation_dimension_invalid")
    if set(value) != set(POLICY_VALUE_FIELDS[dimension]) or value.get("value_type") != expected_type:
        raise ContractViolation("provider_policy_observation_value_binding_invalid")
    _validate_policy_value(dimension, value)
    if record["status"] not in {"ACTIVE", "EXPIRED", "REVOKED", "SUPERSEDED", "CONTRADICTED", "INVALID"}:
        raise ContractViolation("provider_policy_observation_status_invalid")
    if not isinstance(record["material_classes"], list) or not record["material_classes"]:
        raise ContractViolation("provider_policy_observation_material_scope_invalid")
    if not all(isinstance(value, str) and value for value in record["material_classes"]):
        raise ContractViolation("provider_policy_observation_material_scope_invalid")
    if len(set(record["material_classes"])) != len(record["material_classes"]):
        raise ContractViolation("provider_policy_observation_material_scope_invalid")
    if not isinstance(record["invalidation_epoch"], int) or isinstance(record["invalidation_epoch"], bool) or record["invalidation_epoch"] < 0:
        raise ContractViolation("provider_policy_observation_epoch_invalid")
    try:
        observed_at = _parse_policy_timestamp(record["observed_at"])
        valid_until = _parse_policy_timestamp(record["valid_until"])
    except (TypeError, ValueError):
        raise ContractViolation("provider_policy_observation_timestamp_invalid")
    if observed_at > valid_until:
        raise ContractViolation("provider_policy_observation_timestamp_order_invalid")
    if not is_sha256(record["freshness_profile_fingerprint"]):
        raise ContractViolation("provider_policy_observation_freshness_fingerprint_invalid")
    fingerprint = record["observation_fingerprint"]
    if not is_sha256(fingerprint) or fingerprint != sha256_json({key: value for key, value in record.items() if key != "observation_fingerprint"}):
        raise ContractViolation("provider_policy_observation_fingerprint_invalid")


def _parse_policy_timestamp(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp_invalid")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timestamp_must_be_timezone_aware")
    return parsed.astimezone(timezone.utc)


def _validate_policy_value(dimension: str, value: Mapping[str, Any]) -> None:
    def nonempty(field: str) -> bool:
        return isinstance(value.get(field), str) and bool(value[field])

    def boolean(field: str) -> bool:
        return type(value.get(field)) is bool

    def nonnegative_integer(field: str) -> bool:
        return isinstance(value.get(field), int) and not isinstance(value[field], bool) and value[field] >= 0

    valid = False
    if dimension == "destination_identity":
        valid = nonempty("identity_ref") and nonempty("normalized_authority") and value.get("scheme") == "HTTPS"
    elif dimension == "retention_deletion":
        valid = value.get("retention_mode") in {"NONE", "LIMITED", "INDEFINITE", "UNKNOWN"} and value.get("deletion_mode") in {"SUPPORTED", "NOT_SUPPORTED", "CONDITIONAL", "UNKNOWN"}
    elif dimension == "training_use":
        valid = value.get("training_use") in {"PROHIBITED", "ALLOWED", "CONDITIONAL", "UNKNOWN"}
    elif dimension == "subprocessors":
        valid = is_sha256(value.get("subprocessors_fingerprint")) and nonnegative_integer("subprocessor_count")
    elif dimension == "processing_region":
        valid = nonempty("region") and value.get("region_scope") in {"SINGLE_REGION", "MULTI_REGION", "UNKNOWN"}
    elif dimension == "feature_capability":
        valid = nonempty("capability_key") and boolean("supported") and nonempty("capability_profile_ref")
    elif dimension == "structured_output_attachment":
        attachment_types = value.get("attachment_types")
        valid = boolean("structured_output_supported") and isinstance(attachment_types, list) and all(isinstance(item, str) and item for item in attachment_types) and len(set(attachment_types)) == len(attachment_types) and nonnegative_integer("max_attachment_bytes")
    elif dimension == "logging_diagnostics":
        valid = value.get("logging_scope") in {"NONE", "METADATA_ONLY", "CONTENT_POSSIBLE", "UNKNOWN"}
    elif dimension == "credential_operation_scope":
        operations = value.get("allowed_operations")
        valid = isinstance(operations, list) and bool(operations) and all(isinstance(item, str) and item in {"provider_call", "connector_fetch", "attachment_fetch", "external_fetch"} for item in operations) and len(set(operations)) == len(operations) and nonempty("audience")
    elif dimension == "redirect_fetch_behavior":
        valid = boolean("redirects_allowed") and nonnegative_integer("max_redirect_hops") and value.get("revalidate_each_hop") is True
    if not valid:
        raise ContractViolation("provider_policy_observation_value_type_invalid")


def provider_policy_observation_is_fresh(record: Mapping[str, Any], *, now: str, profile: FreshnessProfile, current_epoch: int) -> bool:
    try:
        validate_provider_policy_observation(record)
        if record["status"] != "ACTIVE":
            return False
        if record["freshness_profile_id"] != profile.profile_id or record["freshness_profile_fingerprint"] != profile.fingerprint:
            return False
        if record["invalidation_epoch"] != current_epoch:
            return False
        return _parse_policy_timestamp(record["observed_at"]) <= _parse_policy_timestamp(now) <= _parse_policy_timestamp(record["valid_until"])
    except (ContractViolation, TypeError, ValueError):
        return False


@dataclass(frozen=True)
class FreshnessProfile:
    profile_id: str
    algorithm_version: str
    valid_for_seconds: int

    @property
    def fingerprint(self) -> str:
        return sha256_json({"profile_id": self.profile_id, "algorithm_version": self.algorithm_version, "valid_for_seconds": self.valid_for_seconds})


@dataclass(frozen=True)
class PolicyObservation:
    dimension: str
    value: str
    observed_at: str
    valid_until: str
    invalidation_epoch: int
    freshness_profile: FreshnessProfile
    fingerprint: str

    @staticmethod
    def create(dimension: str, value: str, observed_at: str, valid_until: str, invalidation_epoch: int, profile: FreshnessProfile) -> "PolicyObservation":
        payload = {"dimension": dimension, "value": value, "observed_at": observed_at, "valid_until": valid_until, "invalidation_epoch": invalidation_epoch, "freshness_profile_id": profile.profile_id, "freshness_profile_fingerprint": profile.fingerprint}
        return PolicyObservation(dimension, value, observed_at, valid_until, invalidation_epoch, profile, sha256_json(payload))

    def is_fresh(self, *, now: str, current_epoch: int, profile: FreshnessProfile) -> bool:
        if profile.profile_id != self.freshness_profile.profile_id or profile.fingerprint != self.freshness_profile.fingerprint:
            return False
        if current_epoch != self.invalidation_epoch:
            return False
        return now <= self.valid_until


@dataclass(frozen=True)
class RedactionResult:
    text: str
    action_result: str
    obligations: tuple[str, ...]
    constraint_refs: tuple[str, ...]
    citation_map_fingerprint: str


def constrained_redact(text: str, *, remove_terms: Iterable[str], required_obligations: Iterable[str], citations: Mapping[str, str]) -> RedactionResult:
    """Apply an explicit redaction and make removed obligations visible."""
    output = text
    removed = []
    for term in remove_terms:
        if term and term in output:
            output = output.replace(term, "[REDACTED]")
            removed.append(term)
    obligations = tuple(sorted(set(required_obligations)))
    constraints = tuple("constraint_" + sha256_json({"obligation": obligation, "removed": removed})[:24] for obligation in obligations if removed)
    citation_fingerprint = sha256_json({"citations": dict(sorted(citations.items())), "text": output})
    action = "ALLOW_WITH_CONSTRAINTS" if constraints else "ALLOW"
    return RedactionResult(output, action, obligations, constraints, citation_fingerprint)


def validate_transition_history(history: list[Mapping[str, object]], *, terminal: str) -> None:
    previous = "NOT_APPLICABLE"
    for index, event in enumerate(history):
        if event.get("sequence") != index or event.get("from_state") != previous:
            raise ContractViolation("lifecycle_history_disconnected")
        previous = str(event.get("to_state"))
    if not history or previous != terminal:
        raise ContractViolation("lifecycle_terminal_state_invalid")
