"""Fail-closed Gate-D vocabulary and cross-record validation helpers."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping

from .canonical import is_sha256, sha256_json


OPERATIONS = frozenset({"provider_call", "connector_fetch", "attachment_fetch", "external_fetch"})
PURPOSES = frozenset({"retrieval", "context_delivery", "external_fetch", "attachment_import", "provider_call"})
ACTIONS = frozenset({"ALLOW", "ALLOW_WITH_CONSTRAINTS", "DENY", "REQUIRE_REVIEW", "REQUIRE_REVALIDATION", "LOCAL_ONLY"})
LIFECYCLES = frozenset({"NOT_APPLICABLE", "QUARANTINED", "ADMITTED_TYPED_DATA", "REJECTED", "DISCARDED", "ABORTED"})
LEGAL_TRANSITIONS = {
    ("NOT_APPLICABLE", "QUARANTINED"): "FETCH_COMPLETED",
    ("QUARANTINED", "ADMITTED_TYPED_DATA"): "ADMISSION_APPROVED",
    ("QUARANTINED", "REJECTED"): "REJECTED",
    ("QUARANTINED", "DISCARDED"): "DISCARDED",
    ("QUARANTINED", "ABORTED"): "ABORTED",
    ("ADMITTED_TYPED_DATA", "DISCARDED"): "DISCARDED",
    ("ADMITTED_TYPED_DATA", "ABORTED"): "ABORTED",
}
TRUST_STATES = frozenset(
    {
        "TRUSTED_FOR_BOUND_PURPOSE",
        "CONDITIONALLY_TRUSTED",
        "UNTRUSTED",
        "UNKNOWN",
        "EXPIRED",
        "REVOKED",
        "CONTRADICTED",
        "INVALID",
    }
)
CAPABILITY_STATES = frozenset(
    {"FRESH", "STALE", "MISSING", "REVOKED", "CONTRADICTED", "INVALID", "OUT_OF_SCOPE"}
)
REASON_CLASSES = frozenset(
    {
        "NONE", "AUTHORITY_MISSING", "AUTHORITY_CONFLICT", "EXACT_BINDING_MISSING", "SCOPE_MISMATCH",
        "POLICY_UNKNOWN", "POLICY_STALE", "POLICY_CONTRADICTION", "STALE_EVIDENCE", "REVOKED_EVIDENCE",
        "CLASSIFICATION_MISMATCH", "MATERIAL_FINGERPRINT_MISMATCH", "CAPABILITY_MISSING", "CAPABILITY_OUT_OF_SCOPE",
        "DESTINATION_NOT_ALLOWLISTED", "CREDENTIAL_SCOPE_INVALID", "CREDENTIAL_VISIBILITY_RISK", "URL_INVALID",
        "UNSUPPORTED_SCHEME", "PRIVATE_ADDRESS", "DNS_REBINDING", "REDIRECT_UNAUTHORIZED", "TLS_IDENTITY_MISMATCH",
        "RESOURCE_LIMIT_EXCEEDED", "CONTENT_TYPE_DISALLOWED", "SEMANTIC_OBLIGATION_UNSATISFIABLE", "CITATION_INVALID",
        "HIDDEN_RETRIEVAL_ATTEMPT", "POLICY_EPOCH_CHANGED", "TEARDOWN_UNPROVEN", "UNTRUSTED_EXTERNAL_CONTROL_TEXT",
        "INTERNAL_CONTRACT_INVALID", "REVIEW_REQUIRED",
    }
)


class ContractViolation(ValueError):
    pass


def _required(record: Mapping[str, Any], fields: tuple[str, ...], label: str) -> None:
    missing = [field for field in fields if field not in record]
    if missing:
        raise ContractViolation(f"{label}_missing:" + ",".join(missing))


def validate_trust_decision(record: Mapping[str, Any]) -> None:
    required = (
        "record_type", "schema_version", "decision_id", "destination_binding_ref", "purpose_binding_ref",
        "material_manifest_ref", "trust_assertion_refs", "capability_decision_ref", "authority_manifest_fingerprint",
        "freshness_profile_id", "freshness_profile_fingerprint", "validity_ref", "trust_state", "action_result",
        "content_lifecycle", "reason_class", "decision_fingerprint",
    )
    optional = {"constraint_artifact_ref", "allowed_feature_refs", "redaction_profile_ref"}
    _required(record, required, "trust_decision")
    if set(record) - (set(required) | optional) or record.get("record_type") != "PMIRI_D2_TRUST_DECISION" or record.get("schema_version") != "0.3":
        raise ContractViolation("trust_decision_schema_invalid")
    if not isinstance(record["trust_assertion_refs"], list) or not record["trust_assertion_refs"]:
        raise ContractViolation("trust_assertion_refs_invalid")
    if not all(isinstance(value, str) and value for value in record["trust_assertion_refs"]):
        raise ContractViolation("trust_assertion_refs_invalid")
    if not is_sha256(record["authority_manifest_fingerprint"]) or not is_sha256(record["freshness_profile_fingerprint"]):
        raise ContractViolation("trust_fingerprint_invalid")
    if not is_sha256(record["decision_fingerprint"]):
        raise ContractViolation("trust_decision_fingerprint_invalid")
    if record["decision_fingerprint"] != sha256_json({key: value for key, value in record.items() if key != "decision_fingerprint"}):
        raise ContractViolation("trust_decision_fingerprint_mismatch")
    if record["trust_state"] not in TRUST_STATES:
        raise ContractViolation("trust_state_unknown")
    if record["reason_class"] not in REASON_CLASSES:
        raise ContractViolation("trust_reason_class_invalid")
    if record["action_result"] not in ACTIONS:
        raise ContractViolation("action_unknown")
    if record["content_lifecycle"] != "NOT_APPLICABLE":
        raise ContractViolation("trust_content_lifecycle_must_be_not_applicable")
    if record["trust_state"] in {"UNTRUSTED", "UNKNOWN", "EXPIRED", "REVOKED", "CONTRADICTED", "INVALID"} and record["action_result"] in {"ALLOW", "ALLOW_WITH_CONSTRAINTS"}:
        raise ContractViolation("non_trusted_trust_cannot_allow")
    if record["trust_state"] == "CONDITIONALLY_TRUSTED" and record["action_result"] != "ALLOW_WITH_CONSTRAINTS":
        raise ContractViolation("conditional_trust_requires_constraints")
    if record["action_result"] == "ALLOW_WITH_CONSTRAINTS" and not all(isinstance(record.get(field), str) and record[field] for field in ("constraint_artifact_ref", "redaction_profile_ref")):
        raise ContractViolation("trust_constraints_missing")
    if "allowed_feature_refs" in record and (not isinstance(record["allowed_feature_refs"], list) or not all(isinstance(value, str) and value for value in record["allowed_feature_refs"])):
        raise ContractViolation("trust_allowed_features_invalid")


def validate_capability_decision(record: Mapping[str, Any]) -> None:
    required = (
        "record_type", "schema_version", "decision_id", "subject_binding", "purpose", "material_manifest_ref",
        "material_manifest_fingerprint", "capability_profile_fingerprint", "observation_refs", "policy_version",
        "invalidation_epoch", "authority_manifest_fingerprint", "freshness_profile_id", "freshness_profile_fingerprint",
        "capability_state", "action_result", "reason_class", "validity_ref", "decision_fingerprint",
    )
    _required(record, required, "capability_decision")
    if set(record) != set(required) or record.get("record_type") != "PMIRI_D2_CAPABILITY_DECISION" or record.get("schema_version") != "0.2":
        raise ContractViolation("capability_decision_schema_invalid")
    if not isinstance(record["observation_refs"], list) or not all(isinstance(value, str) and value for value in record["observation_refs"]):
        raise ContractViolation("capability_observation_refs_invalid")
    if record["capability_state"] != "MISSING" and not record["observation_refs"]:
        raise ContractViolation("capability_observation_refs_missing")
    if not all(is_sha256(record[field]) for field in ("material_manifest_fingerprint", "capability_profile_fingerprint", "authority_manifest_fingerprint", "freshness_profile_fingerprint", "decision_fingerprint")):
        raise ContractViolation("capability_decision_fingerprint_invalid")
    if record["decision_fingerprint"] != sha256_json({key: value for key, value in record.items() if key != "decision_fingerprint"}):
        raise ContractViolation("capability_decision_fingerprint_mismatch")
    if not isinstance(record["invalidation_epoch"], int) or isinstance(record["invalidation_epoch"], bool) or record["invalidation_epoch"] < 0:
        raise ContractViolation("capability_decision_epoch_invalid")
    if record["capability_state"] not in CAPABILITY_STATES or record["action_result"] not in ACTIONS:
        raise ContractViolation("capability_vocabulary_invalid")
    if record["reason_class"] not in REASON_CLASSES:
        raise ContractViolation("capability_reason_class_invalid")
    if record["capability_state"] != "FRESH" and record["action_result"] in {"ALLOW", "ALLOW_WITH_CONSTRAINTS"}:
        raise ContractViolation("non_fresh_capability_cannot_allow")
    if record["capability_state"] == "MISSING" and record["reason_class"] != "CAPABILITY_MISSING":
        raise ContractViolation("capability_missing_reason_mismatch")


def validate_lifecycle(record: Mapping[str, Any]) -> None:
    required = (
        "record_type", "schema_version", "content_id", "operation", "purpose", "origin_binding_ref",
        "destination_binding_ref", "response_fingerprint", "terminal_response_fingerprint", "observed_content_type",
        "response_size_bytes", "initial_classification", "trust_state", "history_start_state", "history_terminal_state",
        "admission_state", "retrieval_visibility", "canonical_or_control_influence_prohibited", "transitions",
        "authority_manifest_fingerprint", "lifecycle_fingerprint",
    )
    optional = {"admission_predicate", "typed_data_schema_ref", "typed_data_fingerprint"}
    _required(record, required, "lifecycle")
    if set(record) - (set(required) | optional) or record.get("record_type") != "PMIRI_D2_FETCHED_CONTENT_LIFECYCLE" or record.get("schema_version") != "0.3":
        raise ContractViolation("lifecycle_schema_invalid")
    if not all(isinstance(record[field], str) and record[field] for field in ("content_id", "origin_binding_ref", "destination_binding_ref", "observed_content_type", "initial_classification")):
        raise ContractViolation("lifecycle_identity_field_invalid")
    if record["operation"] not in OPERATIONS or record["purpose"] not in PURPOSES:
        raise ContractViolation("lifecycle_operation_or_purpose_invalid")
    if record["history_start_state"] != "NOT_APPLICABLE" or record["history_terminal_state"] not in LIFECYCLES:
        raise ContractViolation("lifecycle_state_invalid")
    if record["admission_state"] != record["history_terminal_state"]:
        raise ContractViolation("lifecycle_terminal_state_mismatch")
    if not is_sha256(record["response_fingerprint"]) or not is_sha256(record["terminal_response_fingerprint"]) or not is_sha256(record["authority_manifest_fingerprint"]):
        raise ContractViolation("lifecycle_response_fingerprint_invalid")
    if record["terminal_response_fingerprint"] != record["response_fingerprint"]:
        raise ContractViolation("lifecycle_terminal_response_mismatch")
    if not isinstance(record["response_size_bytes"], int) or isinstance(record["response_size_bytes"], bool) or record["response_size_bytes"] < 0:
        raise ContractViolation("lifecycle_response_size_invalid")
    if record["canonical_or_control_influence_prohibited"] is not True:
        raise ContractViolation("lifecycle_control_influence_not_prohibited")
    lifecycle_fingerprint = record["lifecycle_fingerprint"]
    expected_lifecycle_fingerprint = sha256_json({key: value for key, value in record.items() if key != "lifecycle_fingerprint"})
    if not is_sha256(lifecycle_fingerprint) or lifecycle_fingerprint != expected_lifecycle_fingerprint:
        raise ContractViolation("lifecycle_fingerprint_invalid")
    if record["history_terminal_state"] == "NOT_APPLICABLE":
        if record["retrieval_visibility"] != "NONE" or "admission_predicate" in record or "typed_data_schema_ref" in record or "typed_data_fingerprint" in record:
            raise ContractViolation("lifecycle_not_applicable_projection_invalid")
    else:
        predicate = record.get("admission_predicate")
        if not isinstance(predicate, Mapping):
            raise ContractViolation("lifecycle_admission_predicate_missing")
        predicate_fields = {
            "explicit_operation", "explicit_operation_ref", "origin_bound", "parser_result_ref", "classification_ref",
            "validation_result_ref", "content_policy_result_ref", "instruction_influence_prohibited", "control_influence_prohibited",
        }
        if set(predicate) != predicate_fields:
            raise ContractViolation("lifecycle_admission_predicate_schema_invalid")
        _required(
            predicate,
            (
                "explicit_operation",
                "explicit_operation_ref",
                "origin_bound",
                "parser_result_ref",
                "classification_ref",
                "validation_result_ref",
                "content_policy_result_ref",
                "instruction_influence_prohibited",
                "control_influence_prohibited",
            ),
            "lifecycle_admission_predicate",
        )
        if predicate["explicit_operation"] != record["operation"] or predicate["origin_bound"] is not True:
            raise ContractViolation("lifecycle_admission_binding_invalid")
        if predicate["instruction_influence_prohibited"] is not True or predicate["control_influence_prohibited"] is not True:
            raise ContractViolation("lifecycle_control_influence_not_prohibited")
        visibility = {
            "QUARANTINED": "QUARANTINE_ONLY",
            "ADMITTED_TYPED_DATA": "TYPED_DATA_ONLY",
            "REJECTED": "NONE",
            "DISCARDED": "NONE",
            "ABORTED": "NONE",
        }.get(record["history_terminal_state"])
        if record["retrieval_visibility"] != visibility:
            raise ContractViolation("lifecycle_visibility_mismatch")
        if record["history_terminal_state"] == "ADMITTED_TYPED_DATA" and not all(
            isinstance(record.get(field), str) and record[field] for field in ("typed_data_schema_ref", "typed_data_fingerprint")
        ):
            raise ContractViolation("lifecycle_typed_data_proof_missing")
        if record["history_terminal_state"] != "ADMITTED_TYPED_DATA" and ("typed_data_schema_ref" in record or "typed_data_fingerprint" in record):
            raise ContractViolation("lifecycle_typed_data_projection_invalid")
    transitions = record["transitions"]
    if not isinstance(transitions, list):
        raise ContractViolation("lifecycle_transitions_invalid")
    previous = "NOT_APPLICABLE"
    previous_time: datetime | None = None
    for sequence, transition in enumerate(transitions):
        if not isinstance(transition, Mapping):
            raise ContractViolation("lifecycle_transition_invalid")
        transition_fields = {"sequence", "from_state", "to_state", "event", "observed_at", "actor_ref", "reason_class"}
        if set(transition) != transition_fields:
            raise ContractViolation("lifecycle_transition_schema_invalid")
        if transition.get("sequence") != sequence or transition.get("from_state") != previous:
            raise ContractViolation("lifecycle_history_disconnected")
        if transition.get("reason_class") not in REASON_CLASSES:
            raise ContractViolation("lifecycle_transition_reason_invalid")
        try:
            observed_at = str(transition["observed_at"])
            timestamp = datetime.fromisoformat(observed_at[:-1] + "+00:00" if observed_at.endswith("Z") else observed_at)
            if timestamp.tzinfo is None or (previous_time is not None and timestamp < previous_time):
                raise ValueError
        except (KeyError, TypeError, ValueError):
            raise ContractViolation("lifecycle_transition_time_invalid")
        pair = (str(transition.get("from_state")), str(transition.get("to_state")))
        if pair not in LEGAL_TRANSITIONS or transition.get("event") != LEGAL_TRANSITIONS[pair]:
            raise ContractViolation("lifecycle_transition_forbidden")
        previous = transition.get("to_state")
        previous_time = timestamp
    if record["history_terminal_state"] != "NOT_APPLICABLE" and not transitions:
        raise ContractViolation("lifecycle_history_missing")
    if transitions and previous != record["history_terminal_state"]:
        raise ContractViolation("lifecycle_terminal_transition_mismatch")


def validate_outbound_decision(record: Mapping[str, Any]) -> None:
    _required(record, ("operation", "purpose", "action_result", "content_lifecycle", "reason_class"), "outbound_decision")
    if record["operation"] not in OPERATIONS or record["purpose"] not in PURPOSES:
        raise ContractViolation("outbound_operation_or_purpose_invalid")
    if record["reason_class"] not in REASON_CLASSES:
        raise ContractViolation("outbound_reason_class_invalid")
    if record["action_result"] not in ACTIONS or record["content_lifecycle"] not in LIFECYCLES:
        raise ContractViolation("outbound_vocabulary_invalid")
    if record["operation"] == "provider_call" and record["content_lifecycle"] != "NOT_APPLICABLE":
        raise ContractViolation("provider_call_lifecycle_must_be_not_applicable")
    lifecycle_fields = (
        "fetched_content_lifecycle_ref",
        "fetched_content_lifecycle_fingerprint",
        "fetched_content_origin_binding_ref",
        "fetched_content_destination_binding_ref",
        "fetched_content_admission_state",
        "fetched_content_retrieval_visibility",
        "fetched_content_history_terminal_state",
        "fetched_content_terminal_response_fingerprint",
    )
    if record["operation"] == "provider_call":
        if any(record.get(field) is not None for field in lifecycle_fields):
            raise ContractViolation("provider_call_lifecycle_binding_forbidden")
    else:
        _required(record, lifecycle_fields, "content_operation")
        if any(record.get(field) is None for field in lifecycle_fields):
            raise ContractViolation("content_operation_requires_lifecycle_binding")
        if not is_sha256(record["fetched_content_lifecycle_fingerprint"]) or not is_sha256(record["fetched_content_terminal_response_fingerprint"]):
            raise ContractViolation("content_operation_lifecycle_fingerprint_invalid")
        if record["content_lifecycle"] == "NOT_APPLICABLE":
            raise ContractViolation("content_operation_lifecycle_not_applicable")
    if record["action_result"] in {"ALLOW", "ALLOW_WITH_CONSTRAINTS"}:
        required = {
            "tls_identity_status": "MATCHED",
            "resolution_set_status": "ALL_ALLOWLISTED_PUBLIC",
            "connection_binding_status": "VALIDATED",
            "final_revalidation_result": "MATCHED",
        }
        for key, value in required.items():
            if record.get(key) != value:
                raise ContractViolation(f"allow_requires_{key}")
    if record.get("decision_fingerprint"):
        if not is_sha256(record["decision_fingerprint"]):
            raise ContractViolation("decision_fingerprint_invalid")
        if record["decision_fingerprint"] != decision_fingerprint(record):
            raise ContractViolation("decision_fingerprint_mismatch")


def validate_integrated_envelope(record: Mapping[str, Any]) -> None:
    _required(record, ("operation", "purpose", "action_result", "authority_manifest_fingerprint"), "integrated_envelope")
    if record["operation"] not in OPERATIONS or record["purpose"] not in PURPOSES or record["action_result"] not in ACTIONS:
        raise ContractViolation("integrated_vocabulary_invalid")
    if record.get("reason_class") is not None and record["reason_class"] not in REASON_CLASSES:
        raise ContractViolation("integrated_reason_class_invalid")
    if not is_sha256(record["authority_manifest_fingerprint"]):
        raise ContractViolation("authority_fingerprint_invalid")
    if record["operation"] == "provider_call" and record.get("fetched_content_lifecycle_ref"):
        raise ContractViolation("provider_call_cannot_bind_fetched_content")


def validate_external_emission(envelope: Mapping[str, Any], network: Mapping[str, Any], lifecycle: Mapping[str, Any] | None = None) -> None:
    """Validate exact cross-record bindings before an external emission."""
    validate_integrated_envelope(envelope)
    validate_outbound_decision(network)
    if envelope.get("action_result") in {"ALLOW", "ALLOW_WITH_CONSTRAINTS"} and network.get("action_result") not in {"ALLOW", "ALLOW_WITH_CONSTRAINTS"}:
        raise ContractViolation("integrated_allow_without_network_allow")
    for field in ("operation", "purpose", "action_result"):
        if envelope.get(field) != network.get(field):
            raise ContractViolation(f"cross_record_{field}_mismatch")
    if envelope.get("network_binding_fingerprint") is not None and envelope.get("network_binding_fingerprint") != network.get("connection_binding_fingerprint"):
        raise ContractViolation("network_binding_fingerprint_mismatch")
    if envelope.get("outbound_network_decision_ref") is not None and envelope.get("outbound_network_decision_ref") != network.get("decision_id"):
        raise ContractViolation("outbound_network_decision_binding_mismatch")
    if envelope.get("outbound_network_decision_fingerprint") is not None and envelope.get("outbound_network_decision_fingerprint") != network.get("decision_fingerprint"):
        raise ContractViolation("outbound_network_decision_binding_mismatch")
    if envelope.get("destination_binding_ref") is not None and network.get("destination_binding_ref") is not None and envelope.get("destination_binding_ref") != network.get("destination_binding_ref"):
        raise ContractViolation("destination_binding_mismatch")
    if envelope["operation"] != "provider_call":
        if lifecycle is None:
            raise ContractViolation("lifecycle_required_for_content_operation")
        validate_lifecycle(lifecycle)
        lifecycle_fingerprint = lifecycle.get("lifecycle_fingerprint", lifecycle.get("fingerprint"))
        if not isinstance(lifecycle_fingerprint, str):
            raise ContractViolation("lifecycle_fingerprint_missing")
        for field in ("operation", "purpose"):
            if lifecycle.get(field) != envelope.get(field) or lifecycle.get(field) != network.get(field):
                raise ContractViolation(f"lifecycle_{field}_mismatch")
        if network.get("destination_binding_ref") != envelope.get("destination_binding_ref"):
            raise ContractViolation("destination_binding_mismatch")
        if network.get("fetched_content_lifecycle_ref") != envelope.get("fetched_content_lifecycle_ref"):
            raise ContractViolation("lifecycle_ref_mismatch")
        if network.get("fetched_content_lifecycle_fingerprint") != lifecycle_fingerprint or envelope.get("fetched_content_lifecycle_fingerprint") != lifecycle_fingerprint:
            raise ContractViolation("lifecycle_fingerprint_mismatch")
        exact_fields = {
            "fetched_content_origin_binding_ref": "origin_binding_ref",
            "fetched_content_destination_binding_ref": "destination_binding_ref",
            "fetched_content_admission_state": "admission_state",
            "fetched_content_retrieval_visibility": "retrieval_visibility",
            "fetched_content_history_terminal_state": "history_terminal_state",
            "fetched_content_terminal_response_fingerprint": "terminal_response_fingerprint",
        }
        for projection_field, lifecycle_field in exact_fields.items():
            expected = lifecycle[lifecycle_field]
            if network.get(projection_field) != expected or envelope.get(projection_field) != expected:
                raise ContractViolation(f"lifecycle_{lifecycle_field}_mismatch")
        if lifecycle["terminal_response_fingerprint"] != lifecycle["response_fingerprint"]:
            raise ContractViolation("lifecycle_terminal_response_mismatch")


def decision_fingerprint(record: Mapping[str, Any]) -> str:
    payload = {key: value for key, value in record.items() if key not in {"decision_fingerprint", "captured_at"}}
    return sha256_json(payload)
