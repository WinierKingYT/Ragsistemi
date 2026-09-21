"""Executable Gate-D decision and emission enforcement.

This module is deliberately transport-neutral.  It evaluates exact, caller-
supplied observations and only permits an injected in-memory transport after
the final decision fence has revalidated every bound.  It never performs DNS,
TLS, socket, credential or provider I/O itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Protocol

from .canonical import is_sha256, sha256_json, utc_now
from .decisions import (
    ContractViolation,
    REASON_CLASSES,
    decision_fingerprint,
    validate_capability_decision,
    validate_external_emission,
    validate_integrated_envelope,
    validate_lifecycle,
    validate_outbound_decision,
    validate_trust_decision,
)
from .network import (
    CANONICALIZATION_PROFILE_FINGERPRINT,
    CANONICALIZATION_PROFILE_ID,
    NetworkBoundaryError,
    build_connection_binding,
    normalize_url,
)
from .policy import FreshnessProfile, NetworkPolicy
from .models import QueryRequest
from .request_auth import RequestAuthorizationBinding


def _parse_time(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp_invalid")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timestamp_must_be_timezone_aware")
    return parsed.astimezone(timezone.utc)


def _fresh_window(record: Mapping[str, Any], now: str) -> bool:
    try:
        return _parse_time(str(record["observed_at"])) <= _parse_time(now) <= _parse_time(str(record["valid_until"]))
    except (KeyError, TypeError, ValueError):
        return False


def _ref(kind: str, value: Any) -> str:
    return f"{kind}://{sha256_json(value)[:32]}"


def _reason_class(value: str, *, fallback: str = "INTERNAL_CONTRACT_INVALID") -> str:
    return value if value in REASON_CLASSES else fallback


def _fingerprint_set(values: Iterable[Any]) -> str:
    return sha256_json(list(values))


def _request_from_mapping(request: Mapping[str, Any]) -> QueryRequest | None:
    required = {"request_id", "project_constraint", "query"}
    if not required.issubset(request):
        return None
    try:
        return QueryRequest(
            request_id=str(request["request_id"]),
            project_constraint=str(request["project_constraint"]),
            query=str(request["query"]),
            purpose=str(request.get("purpose", "local_read")),
            max_results=int(request.get("max_results", 20)),
        )
    except (TypeError, ValueError):
        return None


def _authorization_request(value: QueryRequest | Mapping[str, Any] | None) -> QueryRequest | None:
    if isinstance(value, QueryRequest):
        return value
    if isinstance(value, Mapping):
        return _request_from_mapping(value)
    return None


def _finalize(record: dict[str, Any]) -> dict[str, Any]:
    record["decision_fingerprint"] = decision_fingerprint(record)
    return record


_RUNTIME_INTEGRATED_REQUIRED_FIELDS = frozenset({
    "record_type", "schema_version", "decision_id", "request_authorization_fingerprint", "authorization_lineage_ref",
    "authorization_lineage_fingerprint", "source_evidence_set_ref", "source_evidence_set_fingerprint", "context_intent_ref",
    "context_intent_fingerprint", "inherited_epistemic_ceiling_ref", "inherited_epistemic_ceiling_fingerprint",
    "semantic_obligations_ref", "semantic_obligations_fingerprint", "subject_chain_fingerprint", "purpose_fingerprint",
    "operation", "purpose", "material_manifest_fingerprint", "destination_binding_ref", "destination_binding_fingerprint",
    "trust_assertion_set_fingerprint", "capability_observation_set_fingerprint", "policy_version", "freshness_profile_id",
    "freshness_profile_fingerprint", "invalidation_epoch", "emission_mode", "authority_manifest_fingerprint", "validity_ref",
    "trust_state", "capability_state", "action_result", "content_lifecycle", "outbound_network_decision_ref",
    "outbound_network_decision_fingerprint", "fetched_content_lifecycle_ref", "fetched_content_lifecycle_fingerprint",
    "fetched_content_origin_binding_ref", "fetched_content_destination_binding_ref", "fetched_content_admission_state",
    "fetched_content_retrieval_visibility", "fetched_content_history_terminal_state", "fetched_content_terminal_response_fingerprint",
    "reason_class", "decision_fingerprint", "constrained_artifact_fingerprint", "network_binding_fingerprint", "constraint_refs",
})
_RUNTIME_OUTBOUND_REQUIRED_FIELDS = frozenset({
    "record_type", "schema_version", "decision_id", "operation", "purpose", "destination_binding_ref", "destination_identity_ref",
    "canonicalization_profile_id", "canonicalization_profile_fingerprint", "normalized_target", "connection_binding_ref",
    "connection_binding_fingerprint", "selected_target_resolution_ref", "selected_target_ip", "selected_target_family",
    "resolution_set_status", "connection_binding_status", "final_revalidation_event_sequence", "final_revalidation_result",
    "tls_identity_status", "tls_identity_fingerprint", "connection_epoch", "invalidation_epoch", "freshness_profile_id",
    "freshness_profile_fingerprint", "purpose_binding_ref", "trust_decision_ref", "capability_decision_ref", "limits_profile_ref",
    "authority_manifest_fingerprint", "action_result", "content_lifecycle", "fetched_content_lifecycle_ref",
    "fetched_content_lifecycle_fingerprint", "fetched_content_origin_binding_ref", "fetched_content_destination_binding_ref",
    "fetched_content_admission_state", "fetched_content_retrieval_visibility", "fetched_content_history_terminal_state",
    "fetched_content_terminal_response_fingerprint", "reason_class", "validity_ref", "decision_fingerprint",
})


def _require_runtime_record_shape(record: Mapping[str, Any], expected: frozenset[str], label: str) -> None:
    if not isinstance(record, Mapping) or set(record) != set(expected):
        raise ContractViolation(label + "_schema_shape_invalid")


_CAPABILITY_VALUE_FIELDS: dict[str, frozenset[str]] = {
    "attachment_input": frozenset({"value_type", "supported", "accepted_content_types", "max_attachment_bytes"}),
    "structured_output": frozenset({"value_type", "supported", "schema_profile_ref"}),
    "provider_model_feature": frozenset({"value_type", "feature_name", "supported", "feature_profile_ref"}),
    "retention_deletion": frozenset({"value_type", "retention_mode", "deletion_mode"}),
    "training_use": frozenset({"value_type", "training_use"}),
    "subprocessors": frozenset({"value_type", "subprocessors_fingerprint", "subprocessor_count"}),
    "processing_region": frozenset({"value_type", "region", "region_scope"}),
    "credential_operation_scope": frozenset({"value_type", "allowed_operations", "audience"}),
    "redirect_fetch_behavior": frozenset({"value_type", "redirects_allowed", "max_redirect_hops", "revalidate_each_hop"}),
    "destination_identity": frozenset({"value_type", "identity_ref", "normalized_authority", "scheme"}),
    "resource_limits": frozenset({"value_type", "limits_profile_ref"}),
}


def _validate_capability_observation(record: Mapping[str, Any]) -> None:
    required = (
        "record_type",
        "schema_version",
        "capability_contract_version",
        "capability_observation_id",
        "subject_binding",
        "capability_key",
        "observed_value",
        "scope",
        "source_authority",
        "evidence_refs",
        "observed_at",
        "valid_from",
        "valid_until",
        "invalidation_epoch",
        "status",
        "observation_fingerprint",
    )
    if any(field not in record for field in required):
        raise ContractViolation("capability_observation_missing")
    if set(record) != set(required) or record["record_type"] != "PMIRI_D2_CAPABILITY_OBSERVATION" or record["schema_version"] != "0.3" or record["capability_contract_version"] != "0.1":
        raise ContractViolation("capability_observation_schema_invalid")
    if not all(isinstance(record[field], str) and record[field] for field in ("capability_observation_id", "subject_binding", "source_authority", "observed_at", "valid_from", "valid_until")):
        raise ContractViolation("capability_observation_identity_invalid")
    key = record["capability_key"]
    value = record["observed_value"]
    if key not in _CAPABILITY_VALUE_FIELDS or not isinstance(value, Mapping):
        raise ContractViolation("capability_observation_value_invalid")
    if set(value) != set(_CAPABILITY_VALUE_FIELDS[key]) or value.get("value_type") != key:
        raise ContractViolation("capability_observation_value_binding_invalid")
    scope = record["scope"]
    if not isinstance(scope, Mapping) or set(scope) != {"purpose", "material_classes", "region", "feature_profile"}:
        raise ContractViolation("capability_observation_scope_invalid")
    if not isinstance(scope["purpose"], str) or not scope["purpose"] or not isinstance(scope["material_classes"], list) or not scope["material_classes"] or not all(isinstance(item, str) and item for item in scope["material_classes"]):
        raise ContractViolation("capability_observation_scope_invalid")
    if not isinstance(scope["region"], str) or not scope["region"] or not isinstance(scope["feature_profile"], str) or not scope["feature_profile"]:
        raise ContractViolation("capability_observation_scope_invalid")
    if not isinstance(record["evidence_refs"], list) or not record["evidence_refs"]:
        raise ContractViolation("capability_observation_evidence_invalid")
    if not all(isinstance(value, str) and value for value in record["evidence_refs"]):
        raise ContractViolation("capability_observation_evidence_invalid")
    if record["status"] not in {"ACTIVE", "EXPIRED", "REVOKED", "SUPERSEDED", "CONTRADICTED", "INVALID"}:
        raise ContractViolation("capability_observation_status_invalid")
    if not isinstance(record["invalidation_epoch"], int) or isinstance(record["invalidation_epoch"], bool) or record["invalidation_epoch"] < 0:
        raise ContractViolation("capability_observation_epoch_invalid")
    try:
        observed_at = _parse_time(record["observed_at"])
        valid_from = _parse_time(record["valid_from"])
        valid_until = _parse_time(record["valid_until"])
    except (TypeError, ValueError):
        raise ContractViolation("capability_observation_timestamp_invalid")
    if not valid_from <= observed_at <= valid_until:
        raise ContractViolation("capability_observation_timestamp_order_invalid")
    _validate_capability_value(key, value)
    fingerprint = record["observation_fingerprint"]
    if not is_sha256(fingerprint) or fingerprint != sha256_json({key: value for key, value in record.items() if key != "observation_fingerprint"}):
        raise ContractViolation("capability_observation_fingerprint_invalid")


def _validate_capability_value(key: str, value: Mapping[str, Any]) -> None:
    def nonempty(field: str) -> bool:
        return isinstance(value.get(field), str) and bool(value[field])

    def boolean(field: str) -> bool:
        return type(value.get(field)) is bool

    def nonnegative_integer(field: str) -> bool:
        return isinstance(value.get(field), int) and not isinstance(value[field], bool) and value[field] >= 0

    valid = False
    if key == "attachment_input":
        accepted = value.get("accepted_content_types")
        valid = boolean("supported") and isinstance(accepted, list) and bool(accepted) and all(isinstance(item, str) and bool(item) for item in accepted) and nonnegative_integer("max_attachment_bytes")
    elif key == "structured_output":
        valid = boolean("supported") and nonempty("schema_profile_ref")
    elif key == "provider_model_feature":
        valid = nonempty("feature_name") and boolean("supported") and nonempty("feature_profile_ref")
    elif key == "retention_deletion":
        valid = value.get("retention_mode") in {"NONE", "LIMITED", "INDEFINITE", "UNKNOWN"} and value.get("deletion_mode") in {"SUPPORTED", "NOT_SUPPORTED", "CONDITIONAL", "UNKNOWN"}
    elif key == "training_use":
        valid = value.get("training_use") in {"PROHIBITED", "ALLOWED", "CONDITIONAL", "UNKNOWN"}
    elif key == "subprocessors":
        valid = is_sha256(value.get("subprocessors_fingerprint")) and nonnegative_integer("subprocessor_count")
    elif key == "processing_region":
        valid = nonempty("region") and value.get("region_scope") in {"SINGLE_REGION", "MULTI_REGION", "UNKNOWN"}
    elif key == "credential_operation_scope":
        operations = value.get("allowed_operations")
        valid = isinstance(operations, list) and bool(operations) and all(isinstance(item, str) and item in {"provider_call", "connector_fetch", "attachment_fetch", "external_fetch"} for item in operations) and len(set(operations)) == len(operations) and nonempty("audience")
    elif key == "redirect_fetch_behavior":
        valid = boolean("redirects_allowed") and nonnegative_integer("max_redirect_hops") and value.get("revalidate_each_hop") is True
    elif key == "destination_identity":
        valid = nonempty("identity_ref") and nonempty("normalized_authority") and value.get("scheme") == "HTTPS"
    elif key == "resource_limits":
        valid = nonempty("limits_profile_ref")
    if not valid:
        raise ContractViolation("capability_observation_value_type_invalid")


@dataclass(frozen=True)
class EpochSnapshot:
    """The invalidation epoch used by the final emission fence."""

    invalidation_epoch: int = 0


@dataclass(frozen=True)
class ExecutionReceipt:
    status: str
    action_result: str
    reason_class: str
    transport_called: bool
    output: Mapping[str, Any] | None = None

    def structured(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "action_result": self.action_result,
            "reason_class": self.reason_class,
            "transport_called": self.transport_called,
            "output": dict(self.output) if self.output is not None else None,
        }


class ProviderTransport(Protocol):
    def send(self, payload: Mapping[str, Any]) -> Mapping[str, Any]: ...


class ConnectorTransport(Protocol):
    def fetch(self, target: str) -> bytes: ...


class InMemoryProviderTransport:
    """Deterministic provider test double; it cannot leave the process."""

    def __init__(self, response: Mapping[str, Any] | None = None):
        self.response = dict(response or {"provider": "in-memory", "text": "synthetic response"})
        self.calls: list[dict[str, Any]] = []

    def send(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        self.calls.append(dict(payload))
        return dict(self.response)


class InMemoryConnectorTransport:
    """Deterministic connector test double; it cannot perform network I/O."""

    def __init__(self, response: bytes = b"synthetic connector response\n"):
        self.response = bytes(response)
        self.calls: list[str] = []

    def fetch(self, target: str) -> bytes:
        self.calls.append(target)
        return self.response


class GateDDecisionEngine:
    """Evaluate exact Gate-D observations and build bound decision records."""

    def __init__(
        self,
        authority_manifest_fingerprint: str,
        *,
        freshness_profile: FreshnessProfile | None = None,
        policy_version: str = "local-policy-0.1",
        now: str | None = None,
        network_execution_enabled: bool = False,
        policy_epoch_store: Any | None = None,
    ):
        if not is_sha256(authority_manifest_fingerprint):
            raise ValueError("authority_manifest_fingerprint_invalid")
        self.authority_manifest_fingerprint = authority_manifest_fingerprint
        self.freshness_profile = freshness_profile or FreshnessProfile("pmiri-local-0.1", "0.1", 300)
        self.policy_version = policy_version
        self.now = now or utc_now()
        self.network_execution_enabled = network_execution_enabled
        self.policy_epoch_store = policy_epoch_store
        initial_epoch = int(policy_epoch_store.get()) if policy_epoch_store is not None else 0
        if initial_epoch < 0:
            raise ValueError("policy_epoch_invalid")
        self.epochs = EpochSnapshot(initial_epoch)

    @property
    def invalidation_epoch(self) -> int:
        if self.policy_epoch_store is not None:
            return int(self.policy_epoch_store.get())
        return self.epochs.invalidation_epoch

    def invalidate(self) -> int:
        """Invalidate all previously compiled decisions before emission."""
        if self.policy_epoch_store is not None:
            bump = getattr(self.policy_epoch_store, "bump", None)
            if callable(bump):
                return int(bump())
            next_epoch = self.invalidation_epoch + 1
            self.policy_epoch_store.advance(next_epoch)
            return next_epoch
        self.epochs = EpochSnapshot(self.invalidation_epoch + 1)
        return self.invalidation_epoch

    def evaluate_trust(
        self,
        *,
        subject: Mapping[str, Any],
        purpose: str,
        material_class: str,
        feature: str | None,
        zone: str,
        assertions: Iterable[Mapping[str, Any]],
        destination_binding_ref: str = "binding://destination",
        material_manifest_ref: str = "material://request",
        capability_decision_ref: str = "decision://capability/pending",
    ) -> dict[str, Any]:
        assertion_list = [dict(item) for item in assertions]
        assertion_refs = [str(item.get("trust_assertion_id") or _ref("assertion", item)) for item in assertion_list]
        exact_subject = [item for item in assertion_list if item.get("subject") == dict(subject)]
        scoped = [
            item
            for item in exact_subject
            if item.get("purpose") == purpose
            and material_class in item.get("allowed_material_classes", [])
            and zone in item.get("allowed_zones", [])
            and (feature is None or not item.get("allowed_features") or feature in item.get("allowed_features", []))
        ]
        revoked = [item for item in exact_subject if item.get("status") in {"REVOKED", "CONTRADICTED", "INVALID"}]
        if revoked:
            trust_state, action, reason = "REVOKED", "DENY", "AUTHORITY_CONFLICT"
        elif not exact_subject:
            trust_state, action, reason = "UNKNOWN", "DENY", "AUTHORITY_MISSING"
        elif not scoped:
            trust_state, action, reason = "UNTRUSTED", "DENY", "SCOPE_MISMATCH"
        elif not any(item.get("status") == "ACTIVE" and _fresh_window(item, self.now) for item in scoped):
            trust_state, action, reason = "EXPIRED", "DENY", "POLICY_STALE"
        elif any(item.get("authority_manifest_fingerprint") not in {None, self.authority_manifest_fingerprint} for item in scoped):
            trust_state, action, reason = "INVALID", "DENY", "MATERIAL_FINGERPRINT_MISMATCH"
        else:
            trust_state, action, reason = "TRUSTED_FOR_BOUND_PURPOSE", "ALLOW", "NONE"
        record = {
            "record_type": "PMIRI_D2_TRUST_DECISION",
            "schema_version": "0.3",
            "decision_id": _ref("decision", {"kind": "trust", "subject": subject, "purpose": purpose}),
            "destination_binding_ref": destination_binding_ref,
            "purpose_binding_ref": _ref("purpose", {"purpose": purpose}),
            "material_manifest_ref": material_manifest_ref,
            "trust_assertion_refs": assertion_refs or [_ref("assertion", {"subject": subject, "purpose": purpose})],
            "capability_decision_ref": capability_decision_ref,
            "authority_manifest_fingerprint": self.authority_manifest_fingerprint,
            "freshness_profile_id": self.freshness_profile.profile_id,
            "freshness_profile_fingerprint": self.freshness_profile.fingerprint,
            "validity_ref": _ref("validity", {"now": self.now, "epoch": self.invalidation_epoch}),
            "trust_state": trust_state,
            "action_result": action,
            "content_lifecycle": "NOT_APPLICABLE",
            "reason_class": reason,
        }
        if action == "ALLOW":
            record["allowed_feature_refs"] = [feature] if feature else []
        result = _finalize(record)
        validate_trust_decision(result)
        return result

    def evaluate_capability(
        self,
        *,
        subject_binding: str,
        purpose: str,
        required_capabilities: Iterable[str],
        observations: Iterable[Mapping[str, Any]],
        material_manifest_ref: str = "material://request",
    ) -> dict[str, Any]:
        required = tuple(dict.fromkeys(required_capabilities))
        observation_list = [dict(item) for item in observations]
        for observation in observation_list:
            _validate_capability_observation(observation)
        refs = [str(item.get("capability_observation_id") or _ref("observation", item)) for item in observation_list]
        candidates = [
            item
            for item in observation_list
            if item.get("subject_binding") == subject_binding
            and item.get("capability_key") in required
            and item.get("status") == "ACTIVE"
        ]
        missing = [key for key in required if not any(item.get("capability_key") == key for item in candidates)]
        stale = [
            item
            for item in candidates
            if item.get("invalidation_epoch") != self.invalidation_epoch or not _fresh_window(item, self.now)
        ]
        unsupported = [
            item
            for item in candidates
            if isinstance(item.get("observed_value"), Mapping) and item["observed_value"].get("supported") is False
        ]
        if missing:
            state, action, reason = "MISSING", "DENY", "CAPABILITY_MISSING"
        elif stale:
            state, action, reason = "STALE", "REQUIRE_REVALIDATION", "STALE_EVIDENCE"
        elif unsupported:
            state, action, reason = "OUT_OF_SCOPE", "DENY", "CAPABILITY_OUT_OF_SCOPE"
        else:
            state, action, reason = "FRESH", "ALLOW", "NONE"
        record = {
            "record_type": "PMIRI_D2_CAPABILITY_DECISION",
            "schema_version": "0.2",
            "decision_id": _ref("decision", {"kind": "capability", "subject": subject_binding, "purpose": purpose}),
            "subject_binding": subject_binding,
            "purpose": purpose,
            "material_manifest_ref": material_manifest_ref,
            "material_manifest_fingerprint": sha256_json({"ref": material_manifest_ref}),
            "capability_profile_fingerprint": _fingerprint_set(required),
            "observation_refs": refs,
            "policy_version": self.policy_version,
            "invalidation_epoch": self.invalidation_epoch,
            "authority_manifest_fingerprint": self.authority_manifest_fingerprint,
            "freshness_profile_id": self.freshness_profile.profile_id,
            "freshness_profile_fingerprint": self.freshness_profile.fingerprint,
            "capability_state": state,
            "action_result": action,
            "reason_class": reason,
            "validity_ref": _ref("validity", {"now": self.now, "epoch": self.invalidation_epoch}),
        }
        result = _finalize(record)
        validate_capability_decision(result)
        return result

    def evaluate_network(
        self,
        *,
        operation: str,
        purpose: str,
        url: str,
        addresses: Iterable[str],
        tls_identity_status: str = "MATCHED",
        final_revalidation_result: str = "MATCHED",
        content_lifecycle: str = "NOT_APPLICABLE",
        lifecycle: Mapping[str, Any] | None = None,
        lifecycle_ref: str | None = None,
    ) -> dict[str, Any]:
        """Evaluate static resolution/TLS observations without making I/O."""
        address_list = list(addresses)
        if operation != "provider_call" and lifecycle is not None:
            validate_lifecycle(lifecycle)
            if lifecycle.get("operation") != operation or lifecycle.get("purpose") != purpose:
                raise ContractViolation("network_lifecycle_operation_or_purpose_mismatch")
            if not isinstance(lifecycle_ref, str) or not lifecycle_ref:
                raise ContractViolation("network_lifecycle_ref_missing")
            if content_lifecycle != "NOT_APPLICABLE" and content_lifecycle != lifecycle.get("admission_state"):
                raise ContractViolation("network_lifecycle_state_mismatch")
            content_lifecycle = str(lifecycle["admission_state"])
        elif operation == "provider_call" and (lifecycle is not None or lifecycle_ref is not None):
            raise ContractViolation("provider_call_lifecycle_binding_forbidden")
        target = None
        try:
            target = normalize_url(url)
        except NetworkBoundaryError as exc:
            reason = "UNSUPPORTED_SCHEME" if str(exc) == "SCHEME_NOT_ALLOWED" else ("INTERNAL_CONTRACT_INVALID" if str(exc) == "IDNA_VALIDATOR_UNAVAILABLE" else "URL_INVALID")
            normalized = {"scheme": "HTTPS", "authority": "invalid", "path_class": "invalid"}
            resolution_status = "DENIED_MIXED"
            selected_ip = selected_family = None
            binding_status = "DENIED"
            action = "DENY"
        else:
            resolution = NetworkPolicy().evaluate_resolution(url, address_list)
            normalized = {"scheme": "HTTPS", "authority": target.authority, "path_class": target.request_target()}
            resolution_status = resolution.resolution_set_status
            selected_ip = resolution.selected_target.ip if resolution.selected_target else None
            selected_family = resolution.selected_target.family if resolution.selected_target else None
            if resolution_status != "ALL_ALLOWLISTED_PUBLIC":
                reason = "PRIVATE_ADDRESS" if any(entry.policy_status != "ALLOWLISTED_PUBLIC" for entry in resolution.entries) else resolution.reason_class
                action = "DENY"
                binding_status = "DENIED"
            elif tls_identity_status != "MATCHED":
                reason, action, binding_status = "TLS_IDENTITY_MISMATCH", "DENY", "DENIED"
            elif final_revalidation_result != "MATCHED":
                reason, action, binding_status = "DNS_REBINDING", "DENY", "STALE"
            elif not self.network_execution_enabled:
                reason, action, binding_status = "EXACT_BINDING_MISSING", "DENY", "DENIED"
            else:
                reason, action, binding_status = "NONE", "ALLOW", "VALIDATED"
        connection_binding = None
        if target is not None and address_list:
            connection_binding = build_connection_binding(
                endpoint=url,
                addresses=address_list,
                observed_at=self.now,
                connection_epoch=self.invalidation_epoch,
                invalidation_epoch=self.invalidation_epoch,
                tls_identity_status=tls_identity_status,
                final_revalidation_result=final_revalidation_result,
                destination_identity_ref=_ref("destination", normalized),
                execution_enabled=self.network_execution_enabled,
            )
        connection_fingerprint = connection_binding["binding_fingerprint"] if connection_binding is not None else sha256_json(
            {
                "normalized": normalized,
                "resolution_set_status": resolution_status,
                "selected_ip": selected_ip,
                "selected_family": selected_family,
                "epoch": self.invalidation_epoch,
            }
        )
        connection_ref = connection_binding["connection_binding_id"] if connection_binding is not None else _ref("connection", connection_fingerprint)
        selected_resolution_ref = None
        tls_identity_fingerprint = sha256_json({"url": url, "tls": tls_identity_status})
        final_event_sequence = 0
        final_event_result = final_revalidation_result if resolution_status == "ALL_ALLOWLISTED_PUBLIC" else "DENIED"
        if connection_binding is not None:
            binding_status = connection_binding["binding_status"]
            final_event = connection_binding["revalidation_events"][-1]
            final_event_sequence = final_event["sequence"]
            final_event_result = final_event["result"]
            selected_resolution_ref = (
                connection_binding["selected_target"]["resolution_entry_ref"]
                if connection_binding["selected_target"] is not None else None
            )
            tls_identity_fingerprint = connection_binding["tls"]["identity_binding_fingerprint"]
        resolved_lifecycle_ref = None if operation == "provider_call" else (lifecycle_ref or _ref("lifecycle", {"url": normalized, "epoch": self.invalidation_epoch}))
        lifecycle_fingerprint = None if resolved_lifecycle_ref is None else (
            str(lifecycle["lifecycle_fingerprint"]) if lifecycle is not None else sha256_json({"ref": resolved_lifecycle_ref})
        )
        if operation != "provider_call" and content_lifecycle == "NOT_APPLICABLE":
            # A decision without a caller-supplied lifecycle can remain a
            # schema-valid candidate, but emission still requires the exact
            # resolved lifecycle record at the final fence.
            content_lifecycle = "ABORTED" if action == "DENY" else "QUARANTINED"
        record = {
            "record_type": "PMIRI_D2_OUTBOUND_NETWORK_DECISION",
            "schema_version": "0.3",
            "decision_id": _ref("decision", {"kind": "network", "url": url, "epoch": self.invalidation_epoch}),
            "operation": operation,
            "purpose": purpose,
            "destination_binding_ref": _ref("binding", normalized),
            "destination_identity_ref": _ref("destination", normalized),
            "canonicalization_profile_id": CANONICALIZATION_PROFILE_ID,
            "canonicalization_profile_fingerprint": CANONICALIZATION_PROFILE_FINGERPRINT,
            "normalized_target": normalized,
            "connection_binding_ref": connection_ref,
            "connection_binding_fingerprint": connection_fingerprint,
            "selected_target_resolution_ref": selected_resolution_ref,
            "selected_target_ip": selected_ip,
            "selected_target_family": selected_family,
            "resolution_set_status": resolution_status,
            "connection_binding_status": binding_status,
            "final_revalidation_event_sequence": final_event_sequence,
            "final_revalidation_result": final_event_result,
            "tls_identity_status": tls_identity_status if resolution_status == "ALL_ALLOWLISTED_PUBLIC" else "MISMATCHED",
            "tls_identity_fingerprint": tls_identity_fingerprint,
            "connection_epoch": self.invalidation_epoch,
            "invalidation_epoch": self.invalidation_epoch,
            "freshness_profile_id": self.freshness_profile.profile_id,
            "freshness_profile_fingerprint": self.freshness_profile.fingerprint,
            "purpose_binding_ref": _ref("purpose", purpose),
            "trust_decision_ref": "decision://trust/pending",
            "capability_decision_ref": "decision://capability/pending",
            "limits_profile_ref": "limits://default",
            "authority_manifest_fingerprint": self.authority_manifest_fingerprint,
            "action_result": action,
            "content_lifecycle": content_lifecycle,
            "fetched_content_lifecycle_ref": resolved_lifecycle_ref,
            "fetched_content_lifecycle_fingerprint": lifecycle_fingerprint,
            "fetched_content_origin_binding_ref": lifecycle.get("origin_binding_ref") if lifecycle is not None else (_ref("origin", normalized) if resolved_lifecycle_ref else None),
            "fetched_content_destination_binding_ref": lifecycle.get("destination_binding_ref") if lifecycle is not None else (_ref("binding", normalized) if resolved_lifecycle_ref else None),
            "fetched_content_admission_state": lifecycle.get("admission_state") if lifecycle is not None else (content_lifecycle if resolved_lifecycle_ref else None),
            "fetched_content_retrieval_visibility": {
                "QUARANTINED": "QUARANTINE_ONLY",
                "ADMITTED_TYPED_DATA": "TYPED_DATA_ONLY",
                "REJECTED": "NONE",
                "DISCARDED": "NONE",
                "ABORTED": "NONE",
            }.get(content_lifecycle, "NONE") if resolved_lifecycle_ref and lifecycle is None else (lifecycle.get("retrieval_visibility") if resolved_lifecycle_ref and lifecycle is not None else None),
            "fetched_content_history_terminal_state": lifecycle.get("history_terminal_state") if lifecycle is not None else (content_lifecycle if resolved_lifecycle_ref else None),
            "fetched_content_terminal_response_fingerprint": lifecycle.get("terminal_response_fingerprint") if lifecycle is not None else (sha256_json({"response": "not-fetched"}) if resolved_lifecycle_ref else None),
            "reason_class": reason,
            "validity_ref": _ref("validity", {"now": self.now, "epoch": self.invalidation_epoch}),
        }
        result = _finalize(record)
        validate_outbound_decision(result)
        return result

    def build_integrated_envelope(
        self,
        *,
        request: Mapping[str, Any],
        trust_decision: Mapping[str, Any],
        capability_decision: Mapping[str, Any],
        network_decision: Mapping[str, Any] | None = None,
        emission_mode: str = "EXTERNAL",
        content_lifecycle: str = "NOT_APPLICABLE",
        constraint_refs: Iterable[str] = (),
        authorization_binding: RequestAuthorizationBinding | None = None,
    ) -> dict[str, Any]:
        validate_trust_decision(trust_decision)
        validate_capability_decision(capability_decision)
        operation = str(request.get("operation", "provider_call"))
        purpose = str(request.get("purpose", "provider_call"))
        network_action = network_decision.get("action_result") if network_decision else None
        if trust_decision["action_result"] not in {"ALLOW", "ALLOW_WITH_CONSTRAINTS"}:
            action, reason = "DENY", _reason_class(str(trust_decision.get("reason_class", "AUTHORITY_MISSING")), fallback="AUTHORITY_MISSING")
        elif capability_decision["action_result"] not in {"ALLOW", "ALLOW_WITH_CONSTRAINTS"}:
            action, reason = capability_decision["action_result"], _reason_class(str(capability_decision.get("reason_class", "CAPABILITY_MISSING")), fallback="CAPABILITY_MISSING")
        elif emission_mode == "EXTERNAL" and network_action not in {"ALLOW", "ALLOW_WITH_CONSTRAINTS"}:
            action, reason = "DENY", _reason_class(str((network_decision or {}).get("reason_class", "EXACT_BINDING_MISSING")), fallback="EXACT_BINDING_MISSING")
        elif emission_mode == "LOCAL_ONLY":
            action, reason = "LOCAL_ONLY", "NONE"
        elif network_action == "ALLOW_WITH_CONSTRAINTS" or trust_decision["action_result"] == "ALLOW_WITH_CONSTRAINTS":
            action, reason = "ALLOW_WITH_CONSTRAINTS", "NONE"
        else:
            action, reason = "ALLOW", "NONE"
        if emission_mode == "EXTERNAL" and action in {"ALLOW", "ALLOW_WITH_CONSTRAINTS"}:
            if authorization_binding is None:
                action, reason = "DENY", "AUTHORITY_MISSING"
            elif not authorization_binding.is_valid(now=self.now, current_policy_epoch=self.invalidation_epoch):
                action, reason = "DENY", "POLICY_EPOCH_CHANGED"
            elif authorization_binding.operation != operation or authorization_binding.purpose != purpose:
                action, reason = "DENY", "EXACT_BINDING_MISSING"
            elif authorization_binding.policy_version != self.policy_version:
                action, reason = "DENY", "POLICY_STALE"
            elif not (query := _request_from_mapping(request)) or not authorization_binding.integrity_valid(query):
                action, reason = "DENY", "EXACT_BINDING_MISSING"
        if operation != "provider_call" and network_decision:
            content_lifecycle = network_decision.get("content_lifecycle", content_lifecycle)
        record = {
            "record_type": "PMIRI_D2_INTEGRATED_DECISION_ENVELOPE",
            "schema_version": "0.3",
            "decision_id": _ref("decision", {"kind": "integrated", "request": dict(request), "epoch": self.invalidation_epoch}),
            "request_authorization_fingerprint": authorization_binding.fingerprint if authorization_binding else request.get("request_authorization_fingerprint", sha256_json(dict(request))),
            "authorization_lineage_ref": authorization_binding.binding_id if authorization_binding else str(request.get("authorization_lineage_ref", _ref("lineage", request))),
            "authorization_lineage_fingerprint": authorization_binding.fingerprint if authorization_binding else request.get("authorization_lineage_fingerprint", sha256_json({"lineage": request.get("authorization_lineage_ref", "local")})),
            "source_evidence_set_ref": str(request.get("source_evidence_set_ref", "evidence://local")),
            "source_evidence_set_fingerprint": request.get("source_evidence_set_fingerprint", sha256_json({"source": "local"})),
            "context_intent_ref": str(request.get("context_intent_ref", "intent://local")),
            "context_intent_fingerprint": request.get("context_intent_fingerprint", sha256_json({"intent": purpose})),
            "inherited_epistemic_ceiling_ref": str(request.get("inherited_epistemic_ceiling_ref", "ceiling://local")),
            "inherited_epistemic_ceiling_fingerprint": request.get("inherited_epistemic_ceiling_fingerprint", sha256_json({"ceiling": "bounded"})),
            "semantic_obligations_ref": str(request.get("semantic_obligations_ref", "obligations://local")),
            "semantic_obligations_fingerprint": request.get("semantic_obligations_fingerprint", sha256_json({"obligations": []})),
            "subject_chain_fingerprint": authorization_binding.subject_chain_fingerprint if authorization_binding else request.get("subject_chain_fingerprint", sha256_json(request.get("subject", {}))),
            "purpose_fingerprint": authorization_binding.purpose_binding_fingerprint if authorization_binding else request.get("purpose_fingerprint", sha256_json({"purpose": purpose})),
            "operation": authorization_binding.operation if authorization_binding else operation,
            "purpose": authorization_binding.purpose if authorization_binding else purpose,
            "material_manifest_fingerprint": request.get("material_manifest_fingerprint", capability_decision.get("material_manifest_fingerprint")),
            "destination_binding_ref": str(request.get("destination_binding_ref", network_decision.get("destination_binding_ref") if network_decision else trust_decision.get("destination_binding_ref", "binding://destination"))),
            "destination_binding_fingerprint": request.get("destination_binding_fingerprint", sha256_json({"destination": request.get("destination", "local")})),
            "trust_assertion_set_fingerprint": request.get("trust_assertion_set_fingerprint", _fingerprint_set(trust_decision.get("trust_assertion_refs", []))),
            "capability_observation_set_fingerprint": request.get("capability_observation_set_fingerprint", _fingerprint_set(capability_decision.get("observation_refs", []))),
            "constrained_artifact_fingerprint": request.get("constrained_artifact_fingerprint", sha256_json({"artifact": "provider-neutral-context"})) if emission_mode == "EXTERNAL" else None,
            "network_binding_fingerprint": network_decision.get("connection_binding_fingerprint") if network_decision else None,
            "outbound_network_decision_ref": network_decision.get("decision_id") if network_decision else None,
            "outbound_network_decision_fingerprint": network_decision.get("decision_fingerprint") if network_decision else None,
            "fetched_content_lifecycle_ref": network_decision.get("fetched_content_lifecycle_ref") if network_decision else None,
            "fetched_content_lifecycle_fingerprint": network_decision.get("fetched_content_lifecycle_fingerprint") if network_decision else None,
            "fetched_content_origin_binding_ref": network_decision.get("fetched_content_origin_binding_ref") if network_decision else None,
            "fetched_content_destination_binding_ref": network_decision.get("fetched_content_destination_binding_ref") if network_decision else None,
            "fetched_content_admission_state": network_decision.get("fetched_content_admission_state") if network_decision else None,
            "fetched_content_retrieval_visibility": network_decision.get("fetched_content_retrieval_visibility") if network_decision else None,
            "fetched_content_history_terminal_state": network_decision.get("fetched_content_history_terminal_state") if network_decision else None,
            "fetched_content_terminal_response_fingerprint": network_decision.get("fetched_content_terminal_response_fingerprint") if network_decision else None,
            "policy_version": authorization_binding.policy_version if authorization_binding else self.policy_version,
            "freshness_profile_id": self.freshness_profile.profile_id,
            "freshness_profile_fingerprint": self.freshness_profile.fingerprint,
            "invalidation_epoch": authorization_binding.policy_epoch if authorization_binding else self.invalidation_epoch,
            "emission_mode": emission_mode,
            "authority_manifest_fingerprint": self.authority_manifest_fingerprint,
            "validity_ref": _ref("validity", {"now": self.now, "epoch": self.invalidation_epoch}),
            "trust_state": trust_decision.get("trust_state", "UNKNOWN"),
            "capability_state": capability_decision.get("capability_state", "MISSING"),
            "action_result": action,
            "content_lifecycle": content_lifecycle,
            "reason_class": reason,
            "constraint_refs": list(dict.fromkeys(constraint_refs)),
        }
        result = _finalize(record)
        validate_integrated_envelope(result)
        return result

    def authorize_emission(
        self,
        envelope: Mapping[str, Any],
        *,
        trust_decision: Mapping[str, Any],
        capability_decision: Mapping[str, Any],
        network_decision: Mapping[str, Any] | None,
        lifecycle: Mapping[str, Any] | None = None,
        authorization_binding: RequestAuthorizationBinding | None = None,
        authorization_request: QueryRequest | Mapping[str, Any] | None = None,
        authorization_revalidator: Any | None = None,
    ) -> None:
        """Final fence: no transport may run after a stale or denied decision."""
        validate_integrated_envelope(envelope)
        validate_trust_decision(trust_decision)
        validate_capability_decision(capability_decision)
        if envelope.get("decision_fingerprint") != decision_fingerprint(envelope):
            raise ContractViolation("integrated_decision_fingerprint_mismatch")
        if envelope.get("invalidation_epoch") != self.invalidation_epoch:
            raise ContractViolation("POLICY_EPOCH_CHANGED")
        if envelope.get("trust_state") != trust_decision.get("trust_state"):
            raise ContractViolation("trust_state_binding_mismatch")
        if envelope.get("capability_state") != capability_decision.get("capability_state"):
            raise ContractViolation("capability_state_binding_mismatch")
        if envelope.get("emission_mode") != "EXTERNAL":
            raise ContractViolation("LOCAL_ONLY_EMISSION")
        if envelope.get("action_result") not in {"ALLOW", "ALLOW_WITH_CONSTRAINTS"}:
            raise ContractViolation(str(envelope.get("reason_class", "DENIED")))
        if authorization_binding is None:
            raise ContractViolation("AUTHORITY_MISSING")
        if not authorization_binding.is_valid(now=self.now, current_policy_epoch=self.invalidation_epoch):
            raise ContractViolation("AUTHORITY_STALE_OR_INVALID")
        if authorization_binding.policy_version != self.policy_version:
            raise ContractViolation("POLICY_VERSION_MISMATCH")
        query = _authorization_request(authorization_request)
        if query is None or not authorization_binding.integrity_valid(query):
            raise ContractViolation("REQUEST_BINDING_MISMATCH")
        expected_binding_fields = {
            "request_authorization_fingerprint": authorization_binding.fingerprint,
            "authorization_lineage_ref": authorization_binding.binding_id,
            "authorization_lineage_fingerprint": authorization_binding.fingerprint,
            "subject_chain_fingerprint": authorization_binding.subject_chain_fingerprint,
            "purpose_fingerprint": authorization_binding.purpose_binding_fingerprint,
            "operation": authorization_binding.operation,
            "purpose": authorization_binding.purpose,
            "policy_version": authorization_binding.policy_version,
            "invalidation_epoch": authorization_binding.policy_epoch,
        }
        if any(envelope.get(key) != value for key, value in expected_binding_fields.items()):
            raise ContractViolation("AUTHORIZATION_BINDING_MISMATCH")
        revalidate = getattr(authorization_revalidator, "revalidate", None)
        if not callable(revalidate) or not revalidate(query, authorization_binding, now=self.now):
            raise ContractViolation("AUTHORITY_REVALIDATION_FAILED")
        if network_decision is None:
            raise ContractViolation("network_decision_missing")
        _require_runtime_record_shape(envelope, _RUNTIME_INTEGRATED_REQUIRED_FIELDS, "integrated_envelope")
        _require_runtime_record_shape(network_decision, _RUNTIME_OUTBOUND_REQUIRED_FIELDS, "outbound_network_decision")
        if envelope["network_binding_fingerprint"] != network_decision["connection_binding_fingerprint"]:
            raise ContractViolation("network_binding_fingerprint_mismatch")
        if envelope["outbound_network_decision_ref"] != network_decision["decision_id"] or envelope["outbound_network_decision_fingerprint"] != network_decision["decision_fingerprint"]:
            raise ContractViolation("outbound_network_decision_binding_mismatch")
        if envelope["destination_binding_ref"] != network_decision["destination_binding_ref"]:
            raise ContractViolation("destination_binding_mismatch")
        validate_external_emission(envelope, network_decision, lifecycle)


class EnforcedTransportRuntime:
    """Run injected transports only after :class:`GateDDecisionEngine` allows."""

    def __init__(
        self,
        engine: GateDDecisionEngine,
        *,
        provider: ProviderTransport | None = None,
        connector: ConnectorTransport | None = None,
        external_execution_authorized: bool = False,
    ):
        self.engine = engine
        self.provider = provider
        self.connector = connector
        self.external_execution_authorized = external_execution_authorized

    @staticmethod
    def _transport_binding_matches(transport: Any, network_decision: Mapping[str, Any]) -> bool:
        bound = getattr(transport, "network_decision", None)
        if not isinstance(bound, Mapping):
            return True
        fields = (
            "operation",
            "normalized_target",
            "connection_binding_ref",
            "connection_binding_fingerprint",
            "connection_epoch",
            "invalidation_epoch",
        )
        return all(bound.get(field) == network_decision.get(field) for field in fields)

    def execute_provider(self, payload: Mapping[str, Any], *, envelope: Mapping[str, Any], trust_decision: Mapping[str, Any], capability_decision: Mapping[str, Any], network_decision: Mapping[str, Any], authorization_binding: RequestAuthorizationBinding | None = None, authorization_request: QueryRequest | Mapping[str, Any] | None = None, authorization_revalidator: Any | None = None) -> ExecutionReceipt:
        try:
            self.engine.authorize_emission(envelope, trust_decision=trust_decision, capability_decision=capability_decision, network_decision=network_decision, authorization_binding=authorization_binding, authorization_request=authorization_request, authorization_revalidator=authorization_revalidator)
        except ContractViolation as exc:
            return ExecutionReceipt("DENIED", str(envelope.get("action_result", "DENY")), str(exc), False)
        if self.provider is None:
            return ExecutionReceipt("BLOCKED", "DENY", "PROVIDER_TRANSPORT_NOT_CONFIGURED", False)
        if type(self.provider) is not InMemoryProviderTransport and not self.external_execution_authorized:
            return ExecutionReceipt("BLOCKED", "DENY", "EXTERNAL_PROVIDER_NOT_AUTHORIZED", False)
        if not self._transport_binding_matches(self.provider, network_decision):
            return ExecutionReceipt("DENIED", "DENY", "TRANSPORT_DECISION_BINDING_MISMATCH", False)
        return ExecutionReceipt("EXECUTED", "ALLOW", "NONE", True, self.provider.send(payload))

    def execute_connector(self, target: str, *, envelope: Mapping[str, Any], trust_decision: Mapping[str, Any], capability_decision: Mapping[str, Any], network_decision: Mapping[str, Any], lifecycle: Mapping[str, Any], authorization_binding: RequestAuthorizationBinding | None = None, authorization_request: QueryRequest | Mapping[str, Any] | None = None, authorization_revalidator: Any | None = None) -> ExecutionReceipt:
        try:
            self.engine.authorize_emission(envelope, trust_decision=trust_decision, capability_decision=capability_decision, network_decision=network_decision, lifecycle=lifecycle, authorization_binding=authorization_binding, authorization_request=authorization_request, authorization_revalidator=authorization_revalidator)
        except ContractViolation as exc:
            return ExecutionReceipt("DENIED", str(envelope.get("action_result", "DENY")), str(exc), False)
        if self.connector is None:
            return ExecutionReceipt("BLOCKED", "DENY", "CONNECTOR_TRANSPORT_NOT_CONFIGURED", False)
        if type(self.connector) is not InMemoryConnectorTransport and not self.external_execution_authorized:
            return ExecutionReceipt("BLOCKED", "DENY", "EXTERNAL_CONNECTOR_NOT_AUTHORIZED", False)
        if not self._transport_binding_matches(self.connector, network_decision):
            return ExecutionReceipt("DENIED", "DENY", "TRANSPORT_DECISION_BINDING_MISMATCH", False)
        response = self.connector.fetch(target)
        return ExecutionReceipt("EXECUTED", "ALLOW", "NONE", True, {"response_fingerprint": sha256_json({"bytes": response.hex()})})


__all__ = [
    "ConnectorTransport",
    "EpochSnapshot",
    "EnforcedTransportRuntime",
    "ExecutionReceipt",
    "GateDDecisionEngine",
    "InMemoryConnectorTransport",
    "InMemoryProviderTransport",
    "ProviderTransport",
]
