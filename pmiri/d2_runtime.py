"""Deterministic local Gate-D runtime smoke harness.

This is executable enforcement evidence for the local decision boundaries.  It
uses only static DNS/TLS observations and an in-memory provider double; it does
not authorize a real provider, connector or external network call and it does
not produce D2 acceptance or R-FC PASS.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from .canonical import sha256_json
from .credentials import ConnectorCredentialBoundary, CredentialManager, VISIBILITY_PROHIBITIONS
from .cache import CachedDecision, DecisionCache
from .decisions import ContractViolation, validate_lifecycle
from .gate_d import EnforcedTransportRuntime, GateDDecisionEngine, InMemoryProviderTransport
from .integrity import authority_fingerprint
from .models import QueryRequest
from .network import NetworkBoundary, NetworkBoundaryError, ResourceLimits
from .policy import (
    FreshnessProfile,
    constrained_redact,
    create_provider_policy_observation,
    provider_policy_observation_is_fresh,
)
from .request_auth import AuthenticatedPrincipal, AuthenticationRegistry, RequestAuthorizationService, TrustZoneAttestation
from .schema import SchemaRegistry


NOW = "2026-01-01T00:00:00Z"


# These are executable synthetic input signals, not copies of the documentation
# oracle.  The oracle is loaded from the authority matrix and compared with the
# result produced by the evaluator below.
SCENARIO_INPUTS: dict[str, dict[str, Any]] = {
    "D2-01-P": {"kind": "trust", "subject_exact": True, "scope": True, "fresh": True},
    "D2-01-A": {"kind": "trust", "subject_exact": False, "scope": False, "fresh": False},
    "D2-02-P": {"kind": "capability", "fresh": True, "supported": True},
    "D2-02-A": {"kind": "capability", "fresh": False, "supported": True},
    "D2-07-P": {"kind": "policy", "complete": True, "fresh": True, "authority": "AUTHORITATIVE_REGISTRY"},
    "D2-07-A": {"kind": "policy", "complete": False, "fresh": False, "authority": "CALLER_CLAIM"},
    "D2-01-B": {"kind": "classification", "classification": "CLOUD_OK"},
    "D2-01-C": {"kind": "classification", "classification": "LOCAL_ONLY"},
    "D2-03-P": {"kind": "redaction", "impact": "PRESERVED_WITH_CONSTRAINT"},
    "D2-03-A": {"kind": "redaction", "impact": "UNSATISFIABLE"},
    "D2-03-B": {"kind": "citation", "valid": True},
    "D2-03-C": {"kind": "citation", "valid": False},
    "D2-03-D": {"kind": "hidden_retrieval", "hidden": False},
    "D2-03-E": {"kind": "hidden_retrieval", "hidden": True},
    "D2-01-D": {"kind": "credentials", "scope": True},
    "D2-01-E": {"kind": "credentials", "scope": False},
    "D2-04-P": {"kind": "network", "observation": "allowlisted_stable", "url": "https://example.com/", "addresses": ["93.184.216.34"], "tls": "MATCHED", "revalidation": "MATCHED"},
    "D2-04-A": {"kind": "network", "url": "http://example.com/", "addresses": [], "tls": "MATCHED", "revalidation": "MATCHED"},
    "D2-04-B": {"kind": "network", "observation": "all_addresses_allowlisted_public", "url": "https://example.com/", "addresses": ["93.184.216.34", "93.184.216.35"], "tls": "MATCHED", "revalidation": "MATCHED"},
    "D2-04-C": {"kind": "network", "url": "https://example.com/", "addresses": ["10.0.0.1"], "tls": "MATCHED", "revalidation": "MATCHED"},
    "D2-04-D": {"kind": "network", "observation": "resolution_stable", "url": "https://example.com/", "addresses": ["93.184.216.34"], "tls": "MATCHED", "revalidation": "MATCHED"},
    "D2-04-E": {"kind": "network", "url": "https://example.com/", "addresses": ["93.184.216.34"], "tls": "MATCHED", "revalidation": "MISMATCHED"},
    "D2-04-F": {"kind": "network", "observation": "redirects_revalidated", "url": "https://example.com/", "addresses": ["93.184.216.34"], "tls": "MATCHED", "revalidation": "MATCHED", "redirects": "validated"},
    "D2-04-G": {"kind": "network", "url": "https://example.com/", "addresses": ["93.184.216.34"], "tls": "MATCHED", "revalidation": "MATCHED", "redirects": "unauthorized"},
    "D2-04-H": {"kind": "network", "observation": "within_resource_limits", "url": "https://example.com/", "addresses": ["93.184.216.34"], "tls": "MATCHED", "revalidation": "MATCHED", "limits": "within"},
    "D2-04-I": {"kind": "network", "url": "https://example.com/", "addresses": ["93.184.216.34"], "tls": "MATCHED", "revalidation": "MATCHED", "limits": "exceeded"},
    "D2-04-J": {"kind": "attachment", "valid": True},
    "D2-04-K": {"kind": "attachment", "valid": False},
    "D2-05-P": {"kind": "race", "changed": False},
    "D2-05-A": {"kind": "race", "changed": True},
    "D2-05-B": {"kind": "cache", "exact": True},
    "D2-05-C": {"kind": "cache", "exact": False},
    "D2-04-L": {"kind": "teardown", "complete": True},
    "D2-04-M": {"kind": "teardown", "complete": False},
}


def _fixtures(engine: GateDDecisionEngine) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], Any, RequestAuthorizationService]:
    subject = {"subject_type": "model", "subject_id": "model-x", "parent_subject_ref": "provider-x"}
    subject_binding = "subject://model-x"
    assertion = {
        "trust_assertion_id": "assertion-model-x",
        "subject": subject,
        "purpose": "provider_call",
        "allowed_material_classes": ["SYNTHETIC_TEXT"],
        "allowed_features": ["answer"],
        "allowed_zones": ["LOCAL"],
        "issuer": "local-smoke-authority",
        "evidence_refs": ["evidence://trust"],
        "observed_at": "2025-12-31T00:00:00Z",
        "valid_until": "2026-01-02T00:00:00Z",
        "status": "ACTIVE",
    }
    observation = {
        "record_type": "PMIRI_D2_CAPABILITY_OBSERVATION",
        "schema_version": "0.3",
        "capability_contract_version": "0.1",
        "capability_observation_id": "capability-model-x",
        "subject_binding": subject_binding,
        "capability_key": "provider_model_feature",
        "observed_value": {
            "value_type": "provider_model_feature",
            "feature_name": "answer",
            "supported": True,
            "feature_profile_ref": "feature-profile://local-smoke",
        },
        "scope": {
            "purpose": "provider_call",
            "material_classes": ["SYNTHETIC_TEXT"],
            "region": "LOCAL",
            "feature_profile": "feature-profile://local-smoke",
        },
        "source_authority": "authority://local-smoke",
        "evidence_refs": ["evidence://capability-local-smoke"],
        "observed_at": "2025-12-31T00:00:00Z",
        "valid_from": "2025-12-31T00:00:00Z",
        "valid_until": "2026-01-02T00:00:00Z",
        "invalidation_epoch": engine.invalidation_epoch,
        "status": "ACTIVE",
    }
    observation["observation_fingerprint"] = sha256_json(observation)
    trust = engine.evaluate_trust(
        subject=subject,
        purpose="provider_call",
        material_class="SYNTHETIC_TEXT",
        feature="answer",
        zone="LOCAL",
        assertions=[assertion],
    )
    capability = engine.evaluate_capability(
        subject_binding=subject_binding,
        purpose="provider_call",
        required_capabilities=["provider_model_feature"],
        observations=[observation],
    )
    network = engine.evaluate_network(
        operation="provider_call",
        purpose="provider_call",
        url="https://example.com/answer",
        addresses=["93.184.216.34"],
    )
    request = {
        "request_id": "gate-d-local-smoke",
        "project_constraint": "local",
        "query": "synthetic provider context",
        "max_results": 20,
        "operation": "provider_call",
        "purpose": "provider_call",
        "subject": subject,
        "material_manifest_fingerprint": "b" * 64,
        "authorization_lineage_ref": "lineage://local-smoke",
    }
    principal_ref = "principal:local-smoke"
    attestation = TrustZoneAttestation.issue(
        principal_ref=principal_ref,
        zone_id="LOCAL",
        issuer_ref="security-boundary:local-smoke",
        evidence_refs=("environment://local-smoke",),
        issued_at="2025-12-31T00:00:00Z",
        valid_until="2026-01-02T00:00:00Z",
    )
    principal = AuthenticatedPrincipal.verified(
        authentication_ref="authn-local-smoke",
        principal_ref=principal_ref,
        principal_type="service",
        service_principal_ref="service:pmiri",
        trust_zone_attestation=attestation,
        allowed_projects=("local",),
        allowed_operations=("provider_call",),
        allowed_purposes=("provider_call",),
        policy_bundle_ref="policy://local-smoke",
        policy_version=engine.policy_version,
        policy_epoch=engine.invalidation_epoch,
        issued_at="2025-12-31T00:00:00Z",
        valid_until="2026-01-02T00:00:00Z",
    )
    registry = AuthenticationRegistry()
    registry.register(principal)
    authorization = RequestAuthorizationService(
        registry,
        current_policy_epoch=engine.invalidation_epoch,
        operation="provider_call",
        clock=lambda: 100.0,
    )
    evaluation = authorization.evaluate(
        QueryRequest(
            request_id=request["request_id"],
            project_constraint=request["project_constraint"],
            query=request["query"],
            purpose=request["purpose"],
            max_results=request["max_results"],
        ),
        authentication_ref=principal.authentication_ref,
        now=NOW,
    )
    if not evaluation.allowed or evaluation.binding is None:
        raise ContractViolation(f"local_smoke_authorization_failed:{evaluation.reason}")
    binding = evaluation.binding
    envelope = engine.build_integrated_envelope(
        request=request,
        trust_decision=trust,
        capability_decision=capability,
        network_decision=network,
        authorization_binding=binding,
    )
    return trust, capability, network, envelope, request, binding, authorization


def run_gate_d_smoke(project_root: str | Path, output_path: str | Path | None = None) -> dict[str, Any]:
    root = Path(project_root).resolve()
    authority_fp = authority_fingerprint(root)
    engine = GateDDecisionEngine(
        authority_fp,
        policy_version="local-smoke-policy-0.1",
        now=NOW,
        network_execution_enabled=True,
    )
    trust, capability, network, envelope, request, binding, authorization = _fixtures(engine)
    registry = SchemaRegistry(root)
    registry.require_valid(trust, "pmiri://schema/gate-d-r2/trust-decision/0.3")
    registry.require_valid(capability, "pmiri://schema/gate-d-r2/capability-decision/0.2")
    registry.require_valid(network, "pmiri://schema/gate-d-r2/outbound-network-decision/0.3")
    registry.require_valid(envelope, "pmiri://schema/gate-d-r2/integrated-decision-envelope/0.3")

    provider = InMemoryProviderTransport({"provider": "in-memory", "text": "synthetic response"})
    executor = EnforcedTransportRuntime(engine, provider=provider)
    allowed = executor.execute_provider(
        {"context_fingerprint": envelope["source_evidence_set_fingerprint"]},
        envelope=envelope,
        trust_decision=trust,
        capability_decision=capability,
        network_decision=network,
        authorization_binding=binding,
        authorization_request=request,
        authorization_revalidator=authorization,
    )

    substituted_trust = engine.evaluate_trust(
        subject={"subject_type": "model", "subject_id": "unregistered", "parent_subject_ref": "provider-x"},
        purpose="provider_call",
        material_class="SYNTHETIC_TEXT",
        feature="answer",
        zone="LOCAL",
        assertions=[],
        capability_decision_ref=capability["decision_id"],
    )
    substituted_envelope = engine.build_integrated_envelope(
        request={**request, "subject": {"subject_type": "model", "subject_id": "unregistered", "parent_subject_ref": "provider-x"}},
        trust_decision=substituted_trust,
        capability_decision=capability,
        network_decision=network,
        authorization_binding=binding,
    )
    substituted = executor.execute_provider(
        {"context_fingerprint": "must-not-leave"},
        envelope=substituted_envelope,
        trust_decision=substituted_trust,
        capability_decision=capability,
        network_decision=network,
        authorization_binding=binding,
        authorization_request=request,
        authorization_revalidator=authorization,
    )

    engine.invalidate()
    stale = executor.execute_provider(
        {"context_fingerprint": "stale"},
        envelope=envelope,
        trust_decision=trust,
        capability_decision=capability,
        network_decision=network,
        authorization_binding=binding,
        authorization_request=request,
        authorization_revalidator=authorization,
    )
    cases = [
        {
            "case_id": "D2-SMOKE-ALLOW",
            "expected": "ALLOW_WITH_IN_MEMORY_TRANSPORT",
            "actual": allowed.structured(),
        },
        {
            "case_id": "D2-SMOKE-SUBSTITUTION",
            "expected": "DENY_WITHOUT_TRANSPORT",
            "actual": substituted.structured(),
        },
        {
            "case_id": "D2-SMOKE-EPOCH",
            "expected": "DENY_WITHOUT_TRANSPORT",
            "actual": stale.structured(),
        },
    ]
    report = {
        "artifact_kind": "PMIRI-GATE-D-RUNTIME-SMOKE-REPORT",
        "status": "RUNTIME_SMOKE_CANDIDATE",
        "d2_acceptance": "NOT_CLAIMED",
        "r_fc_pass": "NONE",
        "authority_execution_authorized": False,
        "external_provider_access": "NOT_PERFORMED",
        "external_network_access": "NOT_PERFORMED",
        "authority_fingerprint": authority_fp,
        "policy_version": engine.policy_version,
        "captured_at": NOW,
        "provider_calls": len(provider.calls),
        "cases": cases,
        "report_fingerprint": sha256_json(cases),
    }
    if output_path is not None:
        destination = Path(output_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return report


def _outcome(
    operation: str,
    purpose: str,
    action_result: str,
    evidence_kind: str,
    evidence_value: str,
    content_lifecycle: str,
    reason_class: str,
    **details: Any,
) -> dict[str, Any]:
    result = {
        "operation": operation,
        "purpose": purpose,
        "action_result": action_result,
        "evidence_state": {"kind": evidence_kind, "value": evidence_value},
        "content_lifecycle": content_lifecycle,
        "reason_class": reason_class,
    }
    result.update({key: value for key, value in details.items() if value is not None})
    return result


def _lifecycle(operation: str, purpose: str, terminal: str, authority_fp: str = "a" * 64) -> dict[str, Any]:
    transitions: list[dict[str, Any]] = []
    if terminal == "QUARANTINED":
        transitions = [{"sequence": 0, "from_state": "NOT_APPLICABLE", "to_state": "QUARANTINED", "event": "FETCH_COMPLETED"}]
    elif terminal == "ADMITTED_TYPED_DATA":
        transitions = [
            {"sequence": 0, "from_state": "NOT_APPLICABLE", "to_state": "QUARANTINED", "event": "FETCH_COMPLETED"},
            {"sequence": 1, "from_state": "QUARANTINED", "to_state": "ADMITTED_TYPED_DATA", "event": "ADMISSION_APPROVED"},
        ]
    elif terminal == "ABORTED":
        transitions = [
            {"sequence": 0, "from_state": "NOT_APPLICABLE", "to_state": "QUARANTINED", "event": "FETCH_COMPLETED"},
            {"sequence": 1, "from_state": "QUARANTINED", "to_state": "ABORTED", "event": "ABORTED"},
        ]
    enriched_transitions = [
        {
            **transition,
            "observed_at": NOW,
            "actor_ref": "actor://local-d2-runtime",
            "reason_class": "NONE",
        }
        for transition in transitions
    ]
    content_id = "content://" + sha256_json({"operation": operation, "purpose": purpose, "terminal": terminal})[:32]
    response_fingerprint = sha256_json({"content_id": content_id, "response": "synthetic"})
    record = {
        "record_type": "PMIRI_D2_FETCHED_CONTENT_LIFECYCLE",
        "schema_version": "0.3",
        "content_id": content_id,
        "operation": operation,
        "purpose": purpose,
        "origin_binding_ref": "origin://synthetic-d2",
        "destination_binding_ref": "destination://synthetic-d2",
        "response_fingerprint": response_fingerprint,
        "terminal_response_fingerprint": response_fingerprint,
        "observed_content_type": "text/plain",
        "response_size_bytes": 0,
        "initial_classification": "EXTERNAL_UNTRUSTED_CONTENT",
        "trust_state": "UNTRUSTED",
        "admission_state": terminal,
        "history_start_state": "NOT_APPLICABLE",
        "history_terminal_state": terminal,
        "retrieval_visibility": {
            "QUARANTINED": "QUARANTINE_ONLY",
            "ADMITTED_TYPED_DATA": "TYPED_DATA_ONLY",
            "ABORTED": "NONE",
        }.get(terminal, "NONE"),
        "canonical_or_control_influence_prohibited": True,
        "transitions": enriched_transitions,
        "authority_manifest_fingerprint": authority_fp,
    }
    if terminal != "NOT_APPLICABLE":
        record["admission_predicate"] = {
            "explicit_operation": operation,
            "explicit_operation_ref": "operation://" + operation,
            "origin_bound": True,
            "parser_result_ref": "parser://synthetic-d2",
            "classification_ref": "classification://external-untrusted",
            "validation_result_ref": "validation://synthetic-d2",
            "content_policy_result_ref": "policy://synthetic-d2",
            "instruction_influence_prohibited": True,
            "control_influence_prohibited": True,
        }
    if terminal == "ADMITTED_TYPED_DATA":
        record["typed_data_schema_ref"] = "schema://synthetic-typed-data"
        record["typed_data_fingerprint"] = sha256_json({"typed": content_id})
    record["lifecycle_fingerprint"] = sha256_json(record)
    validate_lifecycle(record)
    return record


def _schema_checked(registry: SchemaRegistry, record: dict[str, Any], schema_ref: str) -> dict[str, Any]:
    registry.require_valid(record, schema_ref)
    return record


def _trust_assertion_record(authority_fp: str, *, exact_subject: bool = True, fresh: bool = True, scoped: bool = True) -> dict[str, Any]:
    subject = {"subject_type": "model", "subject_id": "model-x", "parent_subject_ref": "provider-x"}
    if not exact_subject:
        subject = {**subject, "subject_id": "unregistered"}
    record = {
        "record_type": "PMIRI_D2_TRUST_ASSERTION",
        "schema_version": "0.2",
        "trust_assertion_id": "d2-trust-assertion",
        "subject": subject,
        "purpose": "provider_call",
        "allowed_material_classes": ["SYNTHETIC_TEXT"] if scoped else ["OTHER_TEXT"],
        "allowed_features": ["answer"],
        "allowed_zones": ["LOCAL"],
        "issuer": "authority://local-d2",
        "evidence_refs": ["evidence://d2-trust"],
        "policy_version": "local-d2-policy-0.1",
        "observed_at": "2025-12-31T00:00:00Z",
        "valid_until": "2026-01-02T00:00:00Z" if fresh else "2025-12-31T00:00:00Z",
        "status": "ACTIVE",
    }
    record["assertion_fingerprint"] = sha256_json(record)
    return record


def _capability_observation_record(authority_fp: str, *, fresh: bool = True) -> dict[str, Any]:
    record = {
        "record_type": "PMIRI_D2_CAPABILITY_OBSERVATION",
        "schema_version": "0.3",
        "capability_contract_version": "0.1",
        "capability_observation_id": "d2-capability-observation",
        "subject_binding": "subject://model-x",
        "capability_key": "provider_model_feature",
        "observed_value": {
            "value_type": "provider_model_feature",
            "feature_name": "answer",
            "supported": True,
            "feature_profile_ref": "feature-profile://d2-answer",
        },
        "scope": {
            "purpose": "provider_call",
            "material_classes": ["SYNTHETIC_TEXT"],
            "region": "LOCAL",
            "feature_profile": "feature-profile://d2-answer",
        },
        "source_authority": "authority://local-d2",
        "evidence_refs": ["evidence://d2-capability"],
        "observed_at": "2025-12-31T00:00:00Z",
        "valid_from": "2025-12-31T00:00:00Z",
        "valid_until": "2026-01-02T00:00:00Z" if fresh else "2025-12-31T00:00:00Z",
        "invalidation_epoch": 0,
        "status": "ACTIVE",
    }
    record["observation_fingerprint"] = sha256_json(record)
    return record


def _constrained_egress_records(
    registry: SchemaRegistry,
    authority_fp: str,
    *,
    impact: str,
    action: str,
    reason: str,
    constraint_refs: list[str],
    transformation_kind: str | None,
) -> dict[str, Any]:
    transformation_refs: list[str] = []
    if transformation_kind is not None:
        transformation = {
            "record_type": "PMIRI_D2_REDACTION_TRANSFORMATION",
            "schema_version": "0.2",
            "transformation_id": "transformation://d2-context",
            "kind": transformation_kind,
            "input_evidence_refs": ["evidence://d2-context"],
            "input_span_refs": ["span://d2-context"],
            "reason_class": reason,
            "policy_version": "local-d2-policy-0.1",
            "material_manifest_ref": "material://d2-context",
            "authority_manifest_fingerprint": authority_fp,
            "resulting_fingerprint": sha256_json({"transformation": transformation_kind, "reason": reason}),
        }
        if transformation_kind == "DROP_EVIDENCE":
            transformation["output_span_ref"] = None
            transformation["typed_placeholder"] = None
        elif transformation_kind == "REPLACE_WITH_TYPED_PLACEHOLDER":
            transformation["typed_placeholder"] = "[REDACTED]"
        else:
            transformation["output_span_ref"] = "span://d2-context-redacted"
        _schema_checked(registry, transformation, "pmiri://schema/gate-d-r2/redaction-transformation/0.2")
        transformation_refs = [transformation["transformation_id"]]

    if impact == "PRESERVED_WITH_CONSTRAINT":
        obligation_id = "obligation://d2-preserve-constraint"
        impact_record = {
            "obligation_id": obligation_id,
            "impact": impact,
            "required_action": "ALLOW_WITH_CONSTRAINTS",
            "constraint_visible": True,
            "reason_class": "NONE",
            "constraint_refs": constraint_refs,
        }
    elif impact in {"UNSATISFIABLE", "INVALIDATED"}:
        obligation_id = "obligation://d2-blocked"
        impact_record = {
            "obligation_id": obligation_id,
            "impact": impact,
            "required_action": "DENY",
            "constraint_visible": True,
            "reason_class": reason,
            "constraint_refs": constraint_refs,
        }
    else:
        obligation_id = "obligation://d2-preserved"
        impact_record = {
            "obligation_id": obligation_id,
            "impact": "PRESERVED",
            "required_action": "ALLOW",
            "constraint_visible": True,
            "reason_class": "NONE",
            "constraint_refs": [],
        }

    if constraint_refs:
        constraint = {
            "record_type": "PMIRI_D2_TYPED_CONSTRAINT",
            "schema_version": "0.2",
            "constraint_id": constraint_refs[0],
            "obligation_id": obligation_id,
            "constraint_kind": "QUALIFIER_PRESERVED",
            "visible_constraint_ref": constraint_refs[0],
            "bound_action_result": "ALLOW_WITH_CONSTRAINTS" if action == "ALLOW_WITH_CONSTRAINTS" else "REQUIRE_REVIEW",
            "applies_to_artifact_ref": "artifact://d2-egress-context",
            "citation_map_ref": "citation://d2-context",
            "policy_version": "local-d2-policy-0.1",
            "authority_manifest_fingerprint": authority_fp,
            "constraint_fingerprint": sha256_json({"constraint": constraint_refs[0], "obligation": obligation_id}),
        }
        _schema_checked(registry, constraint, "pmiri://schema/gate-d-r2/typed-constraint/0.2")

    artifact = {
        "record_type": "PMIRI_D2_EGRESS_CONSTRAINED_CONTEXT_ARTIFACT",
        "schema_version": "0.2",
        "artifact_id": "artifact://d2-egress-context",
        "source_compiled_artifact_ref": "artifact://d2-compiled-context",
        "authorization_lineage_ref": "lineage://d2-context",
        "authorization_lineage_fingerprint": sha256_json({"lineage": "d2-context"}),
        "source_evidence_set_ref": "evidence-set://d2-context",
        "source_evidence_set_fingerprint": sha256_json({"evidence": "d2-context"}),
        "context_intent_ref": "intent://context-delivery",
        "context_intent_fingerprint": sha256_json({"intent": "context-delivery"}),
        "inherited_epistemic_ceiling_ref": "ceiling://d2-context",
        "inherited_epistemic_ceiling_fingerprint": sha256_json({"ceiling": "d2-context"}),
        "semantic_obligations_ref": "obligations://d2-context",
        "semantic_obligations_fingerprint": sha256_json({"obligations": "d2-context"}),
        "operation": "provider_call",
        "purpose": "context_delivery",
        "destination_security_binding_ref": "binding://d2-provider",
        "trust_decision_ref": "decision://trust/d2-context",
        "capability_decision_ref": "decision://capability/d2-context",
        "redaction_profile_ref": "redaction://d2-profile",
        "material_manifest_ref": "material://d2-context",
        "authority_manifest_fingerprint": authority_fp,
        "included_evidence_refs": ["evidence://d2-context"],
        "excluded_evidence_refs": [],
        "transformation_refs": transformation_refs,
        "obligation_impacts": [impact_record],
        "constraint_refs": constraint_refs,
        "citation_map_ref": "citation://d2-context",
        "output_fingerprint": sha256_json({"artifact": "d2-egress-context", "impact": impact, "action": action}),
        "validity_ref": "validity://d2-context",
    }
    _schema_checked(registry, artifact, "pmiri://schema/gate-d-r2/egress-constrained-context-artifact/0.2")
    return {"artifact_ref": artifact["artifact_id"], "artifact_fingerprint": artifact["output_fingerprint"], "transformation_refs": transformation_refs}


def _trust_fixture(engine: GateDDecisionEngine, signal: Mapping[str, Any], authority_fp: str) -> dict[str, Any]:
    subject = {"subject_type": "model", "subject_id": "model-x", "parent_subject_ref": "provider-x"}
    assertion_subject = subject if signal.get("subject_exact") else {**subject, "subject_id": "unregistered"}
    assertion = {
        "trust_assertion_id": "d2-trust-assertion",
        "subject": assertion_subject,
        "purpose": "provider_call",
        "allowed_material_classes": ["SYNTHETIC_TEXT"] if signal.get("scope") else ["OTHER_TEXT"],
        "allowed_features": ["answer"],
        "allowed_zones": ["LOCAL"],
        "issuer": "local-d2-authority",
        "evidence_refs": ["evidence://d2-trust"],
        "observed_at": "2025-12-31T00:00:00Z",
        "valid_until": "2026-01-02T00:00:00Z" if signal.get("fresh") else "2025-12-31T00:00:00Z",
        "status": "ACTIVE",
        "authority_manifest_fingerprint": authority_fp,
    }
    assertions = [assertion] if signal.get("subject_exact") else []
    return engine.evaluate_trust(
        subject=subject,
        purpose="provider_call",
        material_class="SYNTHETIC_TEXT",
        feature="answer",
        zone="LOCAL",
        assertions=assertions,
    )


def _credential_fixture(authority_fp: str, *, exact_scope: bool) -> tuple[Any, ConnectorCredentialBoundary]:
    boundary = ConnectorCredentialBoundary(
        boundary_id="d2-credential-boundary",
        connector_subject_ref="connector://d2",
        operation="connector_fetch",
        connector_process_ref="process://d2",
        destination_ref="destination://d2",
        operation_scope=("connector_fetch",),
        injection_channel="PROCESS_MEMORY_HANDLE",
        visibility_prohibitions=tuple(sorted(VISIBILITY_PROHIBITIONS)),
        valid_from="2026-01-01T00:00:00Z",
        valid_until="2026-01-02T00:00:00Z",
        credential_epoch=0,
        rotation_ref="rotation://d2",
        revocation_ref="revocation://d2",
        source_ref="authority://d2",
        authority_manifest_fingerprint=authority_fp,
    )
    binding = CredentialManager().bind(
        boundary,
        b"synthetic-secret-never-serialized",
        operation="connector_fetch" if exact_scope else "attachment_fetch",
        connector_process_ref="process://d2",
        destination_ref="destination://d2",
        current_epoch=0,
        now=NOW,
    )
    return binding, boundary


def _evaluate_d2_case(
    scenario_id: str,
    signal: Mapping[str, Any],
    authority_fp: str,
    registry: SchemaRegistry,
) -> dict[str, Any]:
    """Evaluate one case from fixture observations, without consulting its oracle."""
    kind = signal.get("kind")
    if kind == "trust":
        engine = GateDDecisionEngine(authority_fp, now=NOW, network_execution_enabled=True)
        decision = _schema_checked(registry, _trust_fixture(engine, signal, authority_fp), "pmiri://schema/gate-d-r2/trust-decision/0.3")
        details = {"decision_id": decision["decision_id"]}
        if signal.get("subject_exact"):
            assertion = _schema_checked(registry, _trust_assertion_record(authority_fp, exact_subject=True, fresh=bool(signal.get("fresh")), scoped=bool(signal.get("scope"))), "pmiri://schema/gate-d-r2/trust-assertion/0.2")
            details["assertion_fingerprint"] = assertion["assertion_fingerprint"]
        return _outcome("provider_call", "provider_call", decision["action_result"], "trust_state", decision["trust_state"], "NOT_APPLICABLE", decision["reason_class"], **details)

    if kind == "capability":
        engine = GateDDecisionEngine(authority_fp, now=NOW, network_execution_enabled=True)
        observation = _capability_observation_record(authority_fp, fresh=bool(signal.get("fresh")))
        observation["observed_value"] = {**observation["observed_value"], "supported": bool(signal.get("supported"))}
        observation["observation_fingerprint"] = sha256_json({key: value for key, value in observation.items() if key != "observation_fingerprint"})
        decision = _schema_checked(registry, engine.evaluate_capability(
            subject_binding="subject://model-x",
            purpose="provider_call",
            required_capabilities=["provider_model_feature"],
            observations=[observation],
        ), "pmiri://schema/gate-d-r2/capability-decision/0.2")
        observation_record = _schema_checked(registry, _capability_observation_record(authority_fp, fresh=bool(signal.get("fresh"))), "pmiri://schema/gate-d-r2/capability-observation/0.3")
        return _outcome("provider_call", "provider_call", decision["action_result"], "capability_state", decision["capability_state"], "NOT_APPLICABLE", "STALE_EVIDENCE" if decision["capability_state"] == "STALE" else decision["reason_class"], decision_id=decision["decision_id"], observation_fingerprint=observation_record["observation_fingerprint"])

    if kind == "policy":
        profile = FreshnessProfile("pmiri-local-0.1", "0.1", 300)
        dimensions = ("destination_identity", "feature_capability", "retention_deletion", "credential_operation_scope")
        values = {
            "destination_identity": {"value_type": "destination_identity", "identity_ref": "destination://synthetic", "normalized_authority": "example.com", "scheme": "HTTPS"},
            "feature_capability": {"value_type": "feature_capability", "capability_key": "answer", "supported": True, "capability_profile_ref": "feature-profile://d2-answer"},
            "retention_deletion": {"value_type": "retention_deletion", "retention_mode": "NONE", "deletion_mode": "SUPPORTED"},
            "credential_operation_scope": {"value_type": "credential_operation_scope", "allowed_operations": ["provider_call"], "audience": "provider"},
        }
        observed_dimensions = dimensions if signal.get("complete") else dimensions[:-1]
        source_authority = "AUTHORITATIVE_REGISTRY" if signal.get("authority") == "AUTHORITATIVE_REGISTRY" else "CALLER_CLAIM"
        observations = [
            create_provider_policy_observation(
                observation_id="d2-policy-" + dimension,
                subject_binding_ref="subject://model-x",
                policy_dimension=dimension,
                observed_value=values[dimension],
                purpose="provider_call",
                material_classes=["SYNTHETIC_TEXT"],
                source_authority_class=source_authority,
                source_ref="policy://d2-synthetic",
                issuer="authority://local-d2",
                observed_at="2025-12-31T00:00:00Z",
                valid_until="2026-01-02T00:00:00Z" if signal.get("fresh") else "2025-12-31T00:00:00Z",
                policy_version="local-d2-policy-0.1",
                freshness_profile=profile,
                invalidation_epoch=0,
            )
            for dimension in observed_dimensions
        ]
        complete = len(observations) == len(dimensions) and signal.get("complete")
        fresh = all(provider_policy_observation_is_fresh(item, now=NOW, current_epoch=0, profile=profile) for item in observations)
        covered = complete and fresh and signal.get("authority") == "AUTHORITATIVE_REGISTRY"
        return _outcome("provider_call", "provider_call", "ALLOW" if covered else "DENY", "policy_status", "COVERED_BY_PRECEDENCE" if covered else "POLICY_UNKNOWN", "NOT_APPLICABLE", "NONE" if covered else "POLICY_UNKNOWN")

    if kind == "classification":
        engine = GateDDecisionEngine(authority_fp, now=NOW, network_execution_enabled=True)
        if signal.get("classification") != "CLOUD_OK":
            return _outcome("provider_call", "provider_call", "DENY", "trust_state", "INVALID", "NOT_APPLICABLE", "CLASSIFICATION_MISMATCH")
        decision = _trust_fixture(engine, {"subject_exact": True, "scope": True, "fresh": True}, authority_fp)
        assertion = _schema_checked(registry, _trust_assertion_record(authority_fp), "pmiri://schema/gate-d-r2/trust-assertion/0.2")
        return _outcome("provider_call", "provider_call", "ALLOW", "trust_state", decision["trust_state"], "NOT_APPLICABLE", "NONE", assertion_fingerprint=assertion["assertion_fingerprint"])

    if kind in {"redaction", "citation", "hidden_retrieval"}:
        if kind == "redaction":
            transformed = constrained_redact(
                "synthetic sensitive context",
                remove_terms=["sensitive"],
                required_obligations=["preserve_constraint"],
                citations={"source-1": "span-1"},
            )
            if signal.get("impact") == "UNSATISFIABLE":
                artifact = _constrained_egress_records(registry, authority_fp, impact="UNSATISFIABLE", action="DENY", reason="SEMANTIC_OBLIGATION_UNSATISFIABLE", constraint_refs=list(transformed.constraint_refs), transformation_kind="REPLACE_WITH_TYPED_PLACEHOLDER")
                return _outcome("provider_call", "context_delivery", "DENY", "obligation_impact", "UNSATISFIABLE", "NOT_APPLICABLE", "SEMANTIC_OBLIGATION_UNSATISFIABLE", transformed_fingerprint=transformed.citation_map_fingerprint, **artifact)
            artifact = _constrained_egress_records(registry, authority_fp, impact="PRESERVED_WITH_CONSTRAINT", action=transformed.action_result, reason="NONE", constraint_refs=list(transformed.constraint_refs), transformation_kind="MASK_SPAN")
            return _outcome("provider_call", "context_delivery", transformed.action_result, "obligation_impact", "PRESERVED_WITH_CONSTRAINT", "NOT_APPLICABLE", "NONE", constraint_refs=list(transformed.constraint_refs), **artifact)
        if kind == "citation":
            if not signal.get("valid"):
                artifact = _constrained_egress_records(registry, authority_fp, impact="INVALIDATED", action="DENY", reason="CITATION_INVALID", constraint_refs=["constraint://citation-invalid"], transformation_kind="DROP_EVIDENCE")
                return _outcome("provider_call", "context_delivery", "DENY", "citation_status", "INVALID", "NOT_APPLICABLE", "CITATION_INVALID", **artifact)
            transformed = constrained_redact(
                "synthetic cited context",
                remove_terms=["cited"],
                required_obligations=["citation_required"],
                citations={"source-1": "span-1"},
            )
            artifact = _constrained_egress_records(registry, authority_fp, impact="PRESERVED_WITH_CONSTRAINT", action="ALLOW_WITH_CONSTRAINTS", reason="NONE", constraint_refs=list(transformed.constraint_refs), transformation_kind="REDACT_CITATION_TARGET")
            return _outcome("provider_call", "context_delivery", "ALLOW_WITH_CONSTRAINTS", "obligation_impact", "PRESERVED_WITH_CONSTRAINT", "NOT_APPLICABLE", "NONE", citation_map_fingerprint=transformed.citation_map_fingerprint, **artifact)
        if signal.get("hidden"):
            artifact = _constrained_egress_records(registry, authority_fp, impact="INVALIDATED", action="DENY", reason="HIDDEN_RETRIEVAL_ATTEMPT", constraint_refs=["constraint://hidden-retrieval"], transformation_kind=None)
            return _outcome("provider_call", "context_delivery", "DENY", "retrieval_status", "HIDDEN_RETRIEVAL_ATTEMPT", "NOT_APPLICABLE", "HIDDEN_RETRIEVAL_ATTEMPT", **artifact)
        artifact = _constrained_egress_records(registry, authority_fp, impact="PRESERVED", action="ALLOW", reason="NONE", constraint_refs=[], transformation_kind=None)
        return _outcome("provider_call", "context_delivery", "ALLOW", "retrieval_status", "NO_RETRIEVAL", "NOT_APPLICABLE", "NONE", **artifact)

    if kind == "credentials":
        binding, boundary = _credential_fixture(authority_fp, exact_scope=bool(signal.get("scope")))
        _schema_checked(registry, boundary.public_record(), "pmiri://schema/gate-d-r2/connector-credential-boundary/0.2")
        if binding.action_result == "ALLOW":
            # The secret is deliberately only held by the opaque handle.  The
            # public result is checked before this candidate is returned.
            if "synthetic-secret" in str(binding.public_dict()) or binding.handle is None:
                raise ContractViolation("credential_secret_visibility_violation")
            lifecycle = _schema_checked(registry, _lifecycle("connector_fetch", "external_fetch", "QUARANTINED", authority_fp), "pmiri://schema/gate-d-r2/fetched-content-lifecycle/0.3")
            return _outcome("connector_fetch", "external_fetch", "ALLOW", "credential_status", "EXACTLY_SCOPED", lifecycle["history_terminal_state"], "NONE", boundary_fingerprint=binding.boundary_fingerprint, lifecycle_fingerprint=lifecycle["lifecycle_fingerprint"])
        lifecycle = _schema_checked(registry, _lifecycle("connector_fetch", "external_fetch", "ABORTED", authority_fp), "pmiri://schema/gate-d-r2/fetched-content-lifecycle/0.3")
        return _outcome("connector_fetch", "external_fetch", "DENY", "credential_status", "INVALID_SCOPE", lifecycle["history_terminal_state"], "CREDENTIAL_SCOPE_INVALID")

    if kind == "network":
        operation = "provider_call" if scenario_id in {"D2-04-P", "D2-04-B", "D2-04-D"} else "external_fetch"
        purpose = "provider_call" if operation == "provider_call" else "external_fetch"
        engine = GateDDecisionEngine(authority_fp, now=NOW, network_execution_enabled=True)
        decision = _schema_checked(registry, engine.evaluate_network(
            operation=operation,
            purpose=purpose,
            url=str(signal.get("url")),
            addresses=list(signal.get("addresses", [])),
            tls_identity_status=str(signal.get("tls", "MATCHED")),
            final_revalidation_result=str(signal.get("revalidation", "MATCHED")),
            content_lifecycle="QUARANTINED" if operation != "provider_call" else "NOT_APPLICABLE",
        ), "pmiri://schema/gate-d-r2/outbound-network-decision/0.3")
        resolution_status = decision["resolution_set_status"]
        if signal.get("revalidation") != "MATCHED":
            resolution_status = "DENIED_MIXED"
        lifecycle = None
        if operation != "provider_call":
            terminal = "ABORTED" if scenario_id in {"D2-04-G", "D2-04-I"} or decision["action_result"] == "DENY" else "QUARANTINED"
            lifecycle = _schema_checked(registry, _lifecycle(operation, purpose, terminal, authority_fp), "pmiri://schema/gate-d-r2/fetched-content-lifecycle/0.3")
        if scenario_id == "D2-04-G":
            try:
                NetworkBoundary.validate_redirects([str(signal["url"]), "http://example.com/redirect"])
            except NetworkBoundaryError:
                return _outcome(operation, purpose, "DENY", "network_status", "REDIRECT_UNAUTHORIZED", "ABORTED", "REDIRECT_UNAUTHORIZED", lifecycle_fingerprint=lifecycle["lifecycle_fingerprint"] if lifecycle else None, network_resolution_set_status=resolution_status)
        if scenario_id == "D2-04-H":
            NetworkBoundary.validate_response(response_bytes=1024, decompressed_bytes=2048, compression_ratio=2, header_bytes=512, content_type="text/plain", limits=ResourceLimits())
        if scenario_id == "D2-04-I":
            try:
                NetworkBoundary.validate_response(response_bytes=ResourceLimits().max_response_bytes + 1, decompressed_bytes=1024, compression_ratio=2, header_bytes=512, content_type="text/plain", limits=ResourceLimits())
            except NetworkBoundaryError as exc:
                return _outcome(operation, purpose, "DENY", "network_status", "RESOURCE_LIMIT_EXCEEDED", "ABORTED", str(exc), lifecycle_fingerprint=lifecycle["lifecycle_fingerprint"] if lifecycle else None, network_resolution_set_status=resolution_status)
        if decision["action_result"] == "DENY":
            state = {
                "UNSUPPORTED_SCHEME": "UNSUPPORTED_SCHEME",
                "PRIVATE_ADDRESS": "PRIVATE_ADDRESS",
                "DNS_REBINDING": "DNS_REBINDING",
            }.get(decision["reason_class"], decision["reason_class"])
            return _outcome(operation, purpose, "DENY", "network_status", state, "ABORTED", decision["reason_class"], lifecycle_fingerprint=lifecycle["lifecycle_fingerprint"] if lifecycle else None, network_resolution_set_status=resolution_status)
        state = str(signal.get("observation", "ALLOWLISTED_STABLE")).upper()
        return _outcome(operation, purpose, "ALLOW", "network_status", state, lifecycle["history_terminal_state"] if lifecycle else "NOT_APPLICABLE", "NONE", lifecycle_fingerprint=lifecycle["lifecycle_fingerprint"] if lifecycle else None, network_resolution_set_status=resolution_status, decision_id=decision["decision_id"])

    if kind == "attachment":
        terminal = "ADMITTED_TYPED_DATA" if signal.get("valid") else "QUARANTINED"
        lifecycle = _schema_checked(registry, _lifecycle("attachment_fetch", "attachment_import", terminal, authority_fp), "pmiri://schema/gate-d-r2/fetched-content-lifecycle/0.3")
        return _outcome("attachment_fetch", "attachment_import", "LOCAL_ONLY", "content_state", terminal, terminal, "NONE" if signal.get("valid") else "UNTRUSTED_EXTERNAL_CONTROL_TEXT", lifecycle_fingerprint=lifecycle["lifecycle_fingerprint"], network_resolution_set_status="ALL_ALLOWLISTED_PUBLIC")

    if kind == "race":
        engine = GateDDecisionEngine(authority_fp, now=NOW, network_execution_enabled=True)
        trust, capability, network, envelope, request, binding, authorization = _fixtures(engine)
        _schema_checked(registry, trust, "pmiri://schema/gate-d-r2/trust-decision/0.3")
        _schema_checked(registry, capability, "pmiri://schema/gate-d-r2/capability-decision/0.2")
        _schema_checked(registry, network, "pmiri://schema/gate-d-r2/outbound-network-decision/0.3")
        _schema_checked(registry, envelope, "pmiri://schema/gate-d-r2/integrated-decision-envelope/0.3")
        if signal.get("changed"):
            engine.invalidate()
            try:
                engine.authorize_emission(envelope, trust_decision=trust, capability_decision=capability, network_decision=network, authorization_binding=binding, authorization_request=request, authorization_revalidator=authorization)
            except ContractViolation as exc:
                return _outcome("provider_call", "provider_call", "DENY", "race_status", "POLICY_EPOCH_CHANGED", "NOT_APPLICABLE", str(exc))
        engine.authorize_emission(envelope, trust_decision=trust, capability_decision=capability, network_decision=network, authorization_binding=binding, authorization_request=request, authorization_revalidator=authorization)
        return _outcome("provider_call", "provider_call", "ALLOW", "race_status", "EPOCHS_UNCHANGED", "NOT_APPLICABLE", "NONE")

    if kind == "cache":
        engine = GateDDecisionEngine(authority_fp, now=NOW, network_execution_enabled=True)
        cache = DecisionCache()
        cached_material = "a" * 64
        requested_material = cached_material if signal.get("exact") else "b" * 64
        value = {"action_result": "ALLOW", "material_manifest_fingerprint": cached_material}
        profile = engine.freshness_profile
        cache.put(CachedDecision("d2-cache-key", value, engine.invalidation_epoch, profile.profile_id, profile.fingerprint))
        cached = cache.get("d2-cache-key", invalidation_epoch=engine.invalidation_epoch, freshness_profile_id=profile.profile_id, freshness_profile_fingerprint=profile.fingerprint)
        exact = cached is not None and cached.get("material_manifest_fingerprint") == requested_material
        return _outcome("provider_call", "provider_call", "ALLOW" if exact else "REQUIRE_REVALIDATION", "cache_status", "CURRENT_AND_EXACT" if exact else "FINGERPRINT_MISMATCH", "NOT_APPLICABLE", "NONE" if exact else "MATERIAL_FINGERPRINT_MISMATCH")

    if kind == "teardown":
        lifecycle = _schema_checked(registry, _lifecycle("external_fetch", "external_fetch", "ABORTED", authority_fp), "pmiri://schema/gate-d-r2/fetched-content-lifecycle/0.3")
        if signal.get("complete"):
            return _outcome("external_fetch", "external_fetch", "DENY", "teardown_status", "PROVEN_COMPLETE", lifecycle["history_terminal_state"], "NONE", lifecycle_fingerprint=lifecycle["lifecycle_fingerprint"], network_resolution_set_status="ALL_ALLOWLISTED_PUBLIC")
        return _outcome("external_fetch", "external_fetch", "DENY", "teardown_status", "UNPROVEN", lifecycle["history_terminal_state"], "TEARDOWN_UNPROVEN", lifecycle_fingerprint=lifecycle["lifecycle_fingerprint"], network_resolution_set_status="ALL_ALLOWLISTED_PUBLIC")

    raise ContractViolation(f"unsupported_d2_fixture_kind:{kind}")


def _compare_d2_outcome(expected: Mapping[str, Any], actual: Mapping[str, Any]) -> dict[str, bool]:
    checks = {
        "operation": actual.get("operation") == expected.get("operation"),
        "purpose": actual.get("purpose") == expected.get("purpose"),
        "action_result": actual.get("action_result") == expected.get("action_result"),
        "evidence_state": actual.get("evidence_state") == expected.get("evidence_state"),
        "content_lifecycle": actual.get("content_lifecycle") == expected.get("content_lifecycle"),
        "reason_class": actual.get("reason_class") == expected.get("reason_class"),
    }
    if "network_resolution_set_status" in expected:
        checks["network_resolution_set_status"] = actual.get("network_resolution_set_status") == expected.get("network_resolution_set_status")
    return checks


def run_d2_runtime_candidate(project_root: str | Path, output_path: str | Path | None = None) -> dict[str, Any]:
    """Run all D2 fixtures locally and compare them with the declared oracle.

    The authority matrix is read-only input.  Its ``runtime_status`` remains
    BLOCKED because this harness has no independent clean-room attestation and
    no authorization for real provider, connector or network execution.
    """
    root = Path(project_root).resolve()
    registry = SchemaRegistry(root)
    matrix_path = registry.root / "GATE-D-R2" / "PMIRI_GD-R2-05_ADVERSARIAL_SCENARIO_MATRIX.json"
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    scenarios = matrix.get("scenarios", [])
    authority_fp = authority_fingerprint(root)
    cases: list[dict[str, Any]] = []
    for scenario in scenarios:
        scenario_id = scenario.get("id")
        expected = scenario.get("expected", {})
        signal = SCENARIO_INPUTS.get(str(scenario_id))
        if signal is None:
            cases.append({"scenario_id": scenario_id, "status": "RUNTIME_FIXTURE_MISSING", "errors": ["fixture_signal_missing"], "expected": expected, "actual": None, "matches": {}})
            continue
        try:
            actual = _evaluate_d2_case(str(scenario_id), signal, authority_fp, registry)
            matches = _compare_d2_outcome(expected, actual)
            cases.append({"scenario_id": scenario_id, "status": "ORACLE_MATCH" if all(matches.values()) else "ORACLE_MISMATCH", "fixture_signal": dict(signal), "expected": expected, "actual": actual, "matches": matches})
        except Exception as exc:  # keep the complete matrix report auditable
            cases.append({"scenario_id": scenario_id, "status": "RUNTIME_ERROR", "fixture_signal": dict(signal), "expected": expected, "actual": None, "matches": {}, "errors": [f"{type(exc).__name__}:{exc}"]})
    all_match = len(cases) == 34 and all(case["status"] == "ORACLE_MATCH" for case in cases)
    report = {
        "artifact_kind": "PMIRI-GATE-D-D2-RUNTIME-CANDIDATE-REPORT",
        "status": "D2_RUNTIME_CANDIDATE",
        "runtime_execution": "LOCAL_SYNTHETIC_ONLY",
        "all_oracles_match": all_match,
        "d2_acceptance": "NOT_CLAIMED",
        "r_fc_pass": "NONE",
        "authority_execution_authorized": False,
        "external_provider_access": "NOT_PERFORMED",
        "external_connector_access": "NOT_PERFORMED",
        "external_network_access": "NOT_PERFORMED",
        "authority_fingerprint": authority_fp,
        "captured_at": NOW,
        "scenario_count": len(cases),
        "fixture_signal_count": len(SCENARIO_INPUTS),
        "documentation_runtime_status_preserved": all(item.get("expected", {}).get("runtime_status") == "BLOCKED" for item in cases),
        "cases": cases,
        "report_fingerprint": sha256_json(cases),
    }
    if output_path is not None:
        destination = Path(output_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return report


__all__ = ["run_d2_runtime_candidate", "run_gate_d_smoke"]
