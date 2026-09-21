from __future__ import annotations

import os
import json
import shutil
import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

from pmiri.clean_room import DOMAINS, IsolationObservation, verify_attestation
from pmiri.cache import CachedDecision, DecisionCache
from pmiri.attestation import create_attestation, load_attestation, write_attestation
from pmiri.canonical import sha256_json
from pmiri.decisions import ContractViolation, decision_fingerprint, validate_external_emission, validate_lifecycle, validate_outbound_decision, validate_trust_decision
from pmiri.d2 import validate_d2_matrix
from pmiri.d2_runtime import run_d2_runtime_candidate
from pmiri.evidence import create_evidence_record, validate_evidence_record
from pmiri.gate_d import EnforcedTransportRuntime, GateDDecisionEngine, InMemoryConnectorTransport, InMemoryProviderTransport
from pmiri.credentials import ConnectorCredentialBoundary, CredentialManager, VISIBILITY_PROHIBITIONS
from pmiri.controlled_replay import run_controlled_case
from pmiri.integrity import validate_documentation_bundle
from pmiri.models import QueryRequest
from pmiri.network import NetworkBoundary, NetworkBoundaryError, ResourceLimits, build_connection_binding, normalize_url, validate_connection_binding
from pmiri.preflight import _verify_runner_package, run_preflight, validate_preflight_record_shape
from pmiri.policy import (
    FreshnessProfile,
    NetworkPolicy,
    PolicyObservation,
    constrained_redact,
    create_provider_policy_observation,
    validate_provider_policy_observation,
)
from pmiri.request_auth import AuthenticatedPrincipal, AuthenticationRegistry, RequestAuthorizationService, TrustZoneAttestation
from pmiri.replay import run_case
from pmiri.r_fc import run_r_fc_blocked_candidate
from pmiri.security import (
    AuthorizationSubjectChain,
    DerivedSensitivityAssessment,
    EgressDecision,
    EgressMaterialManifest,
    PurposeBinding,
    SecurityClassificationBinding,
    SecurityContractViolation,
    SecurityDecisionValidity,
    intersect_authority,
)
from pmiri.schema import SchemaRegistry
from pmiri.sealing import seal_directory, verify_seal


class BoundaryTests(unittest.TestCase):
    def _gate_d_engine(self, *, network_execution_enabled=True):
        return GateDDecisionEngine(
            "a" * 64,
            policy_version="test-policy-0.1",
            now="2026-01-01T00:00:00Z",
            network_execution_enabled=network_execution_enabled,
        )

    def _gate_d_inputs(self, engine, *, operation="provider_call", purpose="provider_call", endpoint="https://example.com/answer", content_lifecycle="NOT_APPLICABLE"):
        subject = {"subject_type": "model", "subject_id": "model-x", "parent_subject_ref": "provider-x"}
        subject_binding = "subject://model-x"
        assertion = {
            "trust_assertion_id": "assertion-model-x",
            "subject": subject,
            "purpose": purpose,
            "allowed_material_classes": ["SYNTHETIC_TEXT"],
            "allowed_features": ["answer"],
            "allowed_zones": ["LOCAL"],
            "issuer": "test-authority",
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
                "feature_profile_ref": "feature-profile://test",
            },
            "scope": {
                "purpose": purpose,
                "material_classes": ["SYNTHETIC_TEXT"],
                "region": "LOCAL",
                "feature_profile": "feature-profile://test",
            },
            "source_authority": "authority://test",
            "evidence_refs": ["evidence://capability-test"],
            "observed_at": "2025-12-31T00:00:00Z",
            "valid_from": "2025-12-31T00:00:00Z",
            "valid_until": "2026-01-02T00:00:00Z",
            "invalidation_epoch": engine.invalidation_epoch,
            "status": "ACTIVE",
        }
        observation["observation_fingerprint"] = sha256_json(observation)
        trust = engine.evaluate_trust(
            subject=subject,
            purpose=purpose,
            material_class="SYNTHETIC_TEXT",
            feature="answer",
            zone="LOCAL",
            assertions=[assertion],
            capability_decision_ref="decision://capability/pending",
        )
        capability = engine.evaluate_capability(
            subject_binding=subject_binding,
            purpose=purpose,
            required_capabilities=["provider_model_feature"],
            observations=[observation],
        )
        network = engine.evaluate_network(
            operation=operation,
            purpose=purpose,
            url=endpoint,
            addresses=["93.184.216.34"],
            content_lifecycle=content_lifecycle,
        )
        request = {
            "request_id": "gate-d-test",
            "project_constraint": "local",
            "query": "synthetic test context",
            "max_results": 20,
            "operation": operation,
            "purpose": purpose,
            "subject": subject,
            "material_manifest_fingerprint": "b" * 64,
            "authorization_lineage_ref": "lineage://test",
        }
        principal_ref = "principal:gate-d-test"
        attestation = TrustZoneAttestation.issue(
            principal_ref=principal_ref,
            zone_id="LOCAL",
            issuer_ref="security-boundary:gate-d-test",
            evidence_refs=("environment://gate-d-test",),
            issued_at="2025-12-31T00:00:00Z",
            valid_until="2026-01-02T00:00:00Z",
        )
        principal = AuthenticatedPrincipal.verified(
            authentication_ref="authn-gate-d-test",
            principal_ref=principal_ref,
            principal_type="service",
            service_principal_ref="service:pmiri",
            trust_zone_attestation=attestation,
            allowed_projects=("local",),
            allowed_operations=(operation,),
            allowed_purposes=(purpose,),
            policy_bundle_ref="policy://gate-d-test",
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
            operation=operation,
            clock=lambda: 100.0,
        )
        evaluation = authorization.evaluate(
            QueryRequest(
                request_id=request["request_id"],
                project_constraint=request["project_constraint"],
                query=request["query"],
                purpose=purpose,
                max_results=request["max_results"],
            ),
            authentication_ref=principal.authentication_ref,
            now=engine.now,
        )
        self.assertTrue(evaluation.allowed)
        self.assertIsNotNone(evaluation.binding)
        binding = evaluation.binding
        envelope = engine.build_integrated_envelope(
            request=request,
            trust_decision=trust,
            capability_decision=capability,
            network_decision=network,
            authorization_binding=binding,
        )
        return trust, capability, network, envelope, request, binding, authorization

    def test_preflight_is_truthfully_blocked_without_attestation(self):
        record = run_preflight(".")
        self.assertEqual(record.overall_result, "BLOCKED")
        self.assertEqual(len(record.checks), 16)
        self.assertFalse(any(check.status == "PASS" for check in record.checks if check.check_id in {"PF-08", "PF-09", "PF-10", "PF-11", "PF-12", "PF-13", "PF-14"}))
        self.assertEqual(validate_preflight_record_shape(record.structured()), ())

    def test_preflight_accepts_only_declared_fixture_case_selection(self):
        record = run_preflight(".", selected_fixture_id="GC-C1-FC01", selected_case_id="GC-C1-FC01-P")
        check = next(item for item in record.structured()["checks"] if item["check_id"] == "PF-07")
        self.assertEqual(check["result"], "READY")
        self.assertEqual(record.selected_fixture_id, "GC-C1-FC01")
        self.assertEqual(record.selected_case_id, "GC-C1-FC01-P")
        self.assertEqual(record.overall_result, "BLOCKED")

    def test_attestation_requires_all_domains_and_exact_values(self):
        evidence = {domain: IsolationObservation(domain, "VERIFIED", f"ref-{domain}", "observed") for domain in DOMAINS}
        self.assertEqual(verify_attestation(evidence), (False, "BLOCKED"))
        self.assertEqual(verify_attestation({}), (False, "BLOCKED"))
        exact = {
            "network": IsolationObservation("network", "DENIED", "ref-network", "observed"),
            "credentials": IsolationObservation("credentials", "DENIED", "ref-credentials", "observed"),
            "filesystem": IsolationObservation("filesystem", "ALLOWLIST_VERIFIED", "ref-filesystem", "observed"),
            "connectors": IsolationObservation("connectors", "DENIED", "ref-connectors", "observed"),
            "determinism": IsolationObservation("determinism", "VERIFIED", "ref-determinism", "observed"),
            "resource_limits": IsolationObservation("resource_limits", "VERIFIED", "ref-resource_limits", "observed"),
            "teardown": IsolationObservation("teardown", "AVAILABLE", "ref-teardown", "observed"),
            "privacy": IsolationObservation("privacy", "VERIFIED", "ref-privacy", "observed"),
        }
        self.assertEqual(verify_attestation(exact), (True, "READY_FOR_REPLAY"))
        for status in ("FAILED", "UNVERIFIED"):
            failed = dict(exact)
            failed["network"] = replace(exact["network"], result=status)
            self.assertEqual(verify_attestation(failed), (False, "ISOLATION_VIOLATION"))

    def test_network_normalization_rejects_private_and_non_https(self):
        self.assertEqual(normalize_url("HTTPS://Example.COM:443/a/../b").safe_url(), "https://example.com/b")
        canonical = normalize_url("HTTPS://Example.COM:443/a/%7e/./b?x=%7e&y=%2B")
        self.assertEqual(canonical.authority, "example.com")
        self.assertEqual(canonical.request_target(), "/a/~/b?x=~&y=%2B")
        self.assertEqual(canonical.fingerprint, normalize_url("https://example.com/a/~/b?x=~&y=%2b").fingerprint)
        with self.assertRaisesRegex(NetworkBoundaryError, "MALFORMED_PERCENT_ENCODING"):
            normalize_url("https://example.com/%zz")
        with self.assertRaisesRegex(NetworkBoundaryError, "ENCODED_DELIMITER_FORBIDDEN"):
            normalize_url("https://example.com/%2f")
        self.assertEqual(NetworkBoundary().evaluate("external_fetch", "http://example.com").action_result, "DENY")
        self.assertEqual(NetworkBoundary().evaluate("external_fetch", "https://127.0.0.1").action_result, "DENY")
        mixed = NetworkPolicy().evaluate_resolution("https://example.com", ["93.184.216.34", "10.0.0.1"])
        self.assertEqual(mixed.resolution_set_status, "DENIED_MIXED")
        self.assertIsNone(mixed.selected_target)
        with self.assertRaises(NetworkBoundaryError):
            NetworkBoundary.validate_redirects(["https://example.com", "http://example.com"])
        with self.assertRaises(NetworkBoundaryError):
            NetworkBoundary.validate_response(response_bytes=1, decompressed_bytes=1, compression_ratio=1, header_bytes=1, content_type=None)

    def test_redirect_and_response_limits_fail_closed_on_each_limit(self):
        with self.assertRaisesRegex(NetworkBoundaryError, "REDIRECT_UNAUTHORIZED"):
            NetworkBoundary.validate_redirects([f"https://example.com/{index}" for index in range(7)])
        with self.assertRaisesRegex(NetworkBoundaryError, "REDIRECT_UNAUTHORIZED"):
            NetworkBoundary.validate_redirects(["https://example.com/answer", "https://example.com/answer"])

        limit_cases = (
            ({"response_bytes": ResourceLimits().max_response_bytes + 1}, "RESOURCE_LIMIT_EXCEEDED"),
            ({"decompressed_bytes": ResourceLimits().max_decompressed_bytes + 1}, "RESOURCE_LIMIT_EXCEEDED"),
            ({"compression_ratio": ResourceLimits().max_compression_ratio + 1}, "RESOURCE_LIMIT_EXCEEDED"),
            ({"header_bytes": ResourceLimits().max_header_bytes + 1}, "RESOURCE_LIMIT_EXCEEDED"),
            ({"content_type": "application/octet-stream"}, "CONTENT_TYPE_DISALLOWED"),
        )
        for overrides, expected in limit_cases:
            values = {
                "response_bytes": 1,
                "decompressed_bytes": 1,
                "compression_ratio": 1,
                "header_bytes": 1,
                "content_type": "text/plain",
            }
            values.update(overrides)
            with self.subTest(overrides=overrides):
                with self.assertRaisesRegex(NetworkBoundaryError, expected):
                    NetworkBoundary.validate_response(**values)

    def test_connection_binding_is_replayable_and_fail_closed(self):
        binding = build_connection_binding(
            endpoint="https://example.com/a/../answer?x=%7e",
            addresses=["93.184.216.34"],
            observed_at="2026-01-01T00:00:00Z",
            connection_epoch=4,
            invalidation_epoch=7,
            destination_identity_ref="destination://example",
        )
        validate_connection_binding(binding)
        SchemaRegistry(".").require_valid(binding, "pmiri://schema/gate-d-r2/connection-binding/0.3")
        self.assertEqual(binding["binding_status"], "VALIDATED")
        self.assertEqual(binding["selected_target"]["ip"], "93.184.216.34")
        self.assertEqual(binding["tls"]["expected_identity_ref"], "destination://example")
        self.assertEqual(binding["tls"]["verified_identity_ref"], "destination://example")

        ipv6 = build_connection_binding(
            endpoint="https://[2606:4700:4700::1111]/answer",
            addresses=["2606:4700:4700:0:0:0:0:1111"],
            observed_at="2026-01-01T00:00:00Z",
            connection_epoch=4,
            invalidation_epoch=7,
        )
        validate_connection_binding(ipv6)
        self.assertEqual(ipv6["normalized_authority"], "[2606:4700:4700::1111]")
        self.assertEqual(ipv6["tls"]["sni"], "2606:4700:4700::1111")
        self.assertEqual(ipv6["selected_target"]["ip"], "2606:4700:4700::1111")

        mixed = build_connection_binding(
            endpoint="https://example.com/answer",
            addresses=["10.0.0.1"],
            observed_at="2026-01-01T00:00:00Z",
            connection_epoch=4,
            invalidation_epoch=7,
        )
        validate_connection_binding(mixed)
        SchemaRegistry(".").require_valid(mixed, "pmiri://schema/gate-d-r2/connection-binding/0.3")
        self.assertEqual(mixed["resolution_set_status"], "DENIED_MIXED")
        self.assertIsNone(mixed["selected_target"])
        self.assertEqual(mixed["binding_status"], "DENIED")

        invalid_resolution = GateDDecisionEngine("a" * 64, now="2026-01-01T00:00:00Z", network_execution_enabled=True).evaluate_network(
            operation="external_fetch",
            purpose="external_fetch",
            url="https://example.com/answer",
            addresses=["not-an-ip"],
        )
        self.assertEqual(invalid_resolution["action_result"], "DENY")
        self.assertEqual(invalid_resolution["resolution_set_status"], "DENIED_MIXED")
        self.assertEqual(invalid_resolution["connection_binding_status"], "DENIED")

        tampered = {**binding, "binding_status": "DENIED"}
        with self.assertRaisesRegex(NetworkBoundaryError, "CONNECTION_BINDING_FINGERPRINT_INVALID"):
            validate_connection_binding(tampered)
        broken_event = {**binding, "revalidation_events": [{**binding["revalidation_events"][0], "connection_epoch": 5}]}
        broken_event["binding_fingerprint"] = sha256_json({key: value for key, value in broken_event.items() if key != "binding_fingerprint"})
        with self.assertRaisesRegex(NetworkBoundaryError, "CONNECTION_INITIAL_EPOCH_INVALID"):
            validate_connection_binding(broken_event)

    def test_network_tls_and_final_revalidation_mismatches_deny_without_target(self):
        endpoint = "https://example.com/answer"
        for kwargs, expected_reason, expected_binding_status in (
            ({"tls_identity_status": "MISMATCHED"}, "TLS_IDENTITY_MISMATCH", "DENIED"),
            ({"final_revalidation_result": "MISMATCHED"}, "DNS_REBINDING", "STALE"),
        ):
            engine = GateDDecisionEngine(
                "a" * 64,
                now="2026-01-01T00:00:00Z",
                network_execution_enabled=True,
            )
            decision = engine.evaluate_network(
                operation="provider_call",
                purpose="provider_call",
                url=endpoint,
                addresses=["93.184.216.34"],
                **kwargs,
            )
            self.assertEqual(decision["action_result"], "DENY")
            self.assertEqual(decision["reason_class"], expected_reason)
            self.assertEqual(decision["connection_binding_status"], expected_binding_status)
            self.assertIsNone(decision.get("selected_target"))

    def test_trust_and_lifecycle_are_fail_closed(self):
        with self.assertRaises(ContractViolation):
            validate_trust_decision({"trust_state": "STALE", "action_result": "ALLOW", "content_lifecycle": "NOT_APPLICABLE"})
        with self.assertRaises(ContractViolation):
            validate_lifecycle({"operation": "external_fetch", "purpose": "external_read", "history_start_state": "NOT_APPLICABLE", "history_terminal_state": "ADMITTED_TYPED_DATA", "admission_state": "ADMITTED_TYPED_DATA", "transitions": []})

    def test_capability_observation_requires_typed_value_and_bound_fingerprint(self):
        engine = self._gate_d_engine()
        observation = {
            "record_type": "PMIRI_D2_CAPABILITY_OBSERVATION",
            "schema_version": "0.3",
            "capability_contract_version": "0.1",
            "capability_observation_id": "capability-validation",
            "subject_binding": "subject://model-x",
            "capability_key": "provider_model_feature",
            "observed_value": {"value_type": "provider_model_feature", "feature_name": "answer", "supported": True, "feature_profile_ref": "feature-profile://test"},
            "scope": {"purpose": "provider_call", "material_classes": ["SYNTHETIC_TEXT"], "region": "LOCAL", "feature_profile": "feature-profile://test"},
            "source_authority": "authority://test",
            "evidence_refs": ["evidence://capability-validation"],
            "observed_at": "2025-12-31T00:00:00Z",
            "valid_from": "2025-12-31T00:00:00Z",
            "valid_until": "2026-01-02T00:00:00Z",
            "invalidation_epoch": 0,
            "status": "ACTIVE",
        }
        observation["observation_fingerprint"] = sha256_json(observation)
        engine.evaluate_capability(subject_binding="subject://model-x", purpose="provider_call", required_capabilities=["provider_model_feature"], observations=[observation])
        tampered = {**observation, "observed_value": {"supported": True}}
        with self.assertRaisesRegex(ContractViolation, "capability_observation_value_binding_invalid"):
            engine.evaluate_capability(subject_binding="subject://model-x", purpose="provider_call", required_capabilities=["provider_model_feature"], observations=[tampered])
        invalid_type = {**observation, "observed_value": {**observation["observed_value"], "supported": "yes"}}
        invalid_type["observation_fingerprint"] = sha256_json({key: value for key, value in invalid_type.items() if key != "observation_fingerprint"})
        with self.assertRaisesRegex(ContractViolation, "capability_observation_value_type_invalid"):
            engine.evaluate_capability(subject_binding="subject://model-x", purpose="provider_call", required_capabilities=["provider_model_feature"], observations=[invalid_type])

    def test_provider_policy_observation_uses_closed_dimension_value_union(self):
        profile = FreshnessProfile("pmiri-policy-test", "1", 60)
        record = create_provider_policy_observation(
            observation_id="policy-validation",
            subject_binding_ref="subject://model-x",
            policy_dimension="destination_identity",
            observed_value={"value_type": "destination_identity", "identity_ref": "destination://test", "normalized_authority": "example.com", "scheme": "HTTPS"},
            purpose="provider_call",
            material_classes=["SYNTHETIC_TEXT"],
            source_authority_class="AUTHORITATIVE_REGISTRY",
            source_ref="policy://test",
            issuer="authority://test",
            observed_at="2025-12-31T00:00:00Z",
            valid_until="2026-01-02T00:00:00Z",
            policy_version="policy-1",
            freshness_profile=profile,
            invalidation_epoch=0,
        )
        validate_provider_policy_observation(record)
        tampered = {**record, "observed_value": {"value_type": "training_use", "training_use": "ALLOWED"}}
        with self.assertRaisesRegex(ContractViolation, "provider_policy_observation_value_binding_invalid"):
            validate_provider_policy_observation(tampered)
        invalid_type = {**record, "observed_value": {**record["observed_value"], "scheme": 443}}
        invalid_type["observation_fingerprint"] = sha256_json({key: value for key, value in invalid_type.items() if key != "observation_fingerprint"})
        with self.assertRaisesRegex(ContractViolation, "provider_policy_observation_value_type_invalid"):
            validate_provider_policy_observation(invalid_type)

    def test_outbound_allow_requires_validated_binding(self):
        record = {"operation": "provider_call", "purpose": "provider_inference", "action_result": "ALLOW", "content_lifecycle": "NOT_APPLICABLE", "reason_class": "NONE"}
        with self.assertRaises(ContractViolation):
            validate_outbound_decision(record)

    def test_lifecycle_transition_and_integrated_binding_are_exact(self):
        lifecycle_fingerprint = "b" * 64
        terminal_response_fingerprint = "c" * 64
        lifecycle = {
            "record_type": "PMIRI_D2_FETCHED_CONTENT_LIFECYCLE",
            "schema_version": "0.3",
            "content_id": "content://test-rejected",
            "operation": "external_fetch",
            "purpose": "external_fetch",
            "origin_binding_ref": "origin://test",
            "destination_binding_ref": "binding://test",
            "response_fingerprint": terminal_response_fingerprint,
            "terminal_response_fingerprint": terminal_response_fingerprint,
            "observed_content_type": "text/plain",
            "response_size_bytes": 0,
            "initial_classification": "EXTERNAL_UNTRUSTED_CONTENT",
            "trust_state": "UNTRUSTED",
            "history_start_state": "NOT_APPLICABLE",
            "history_terminal_state": "REJECTED",
            "admission_state": "REJECTED",
            "retrieval_visibility": "NONE",
            "canonical_or_control_influence_prohibited": True,
            "admission_predicate": {
                "explicit_operation": "external_fetch",
                "explicit_operation_ref": "operation://external_fetch",
                "origin_bound": True,
                "parser_result_ref": "parser://test",
                "classification_ref": "classification://test",
                "validation_result_ref": "validation://test",
                "content_policy_result_ref": "policy://test",
                "instruction_influence_prohibited": True,
                "control_influence_prohibited": True,
            },
            "transitions": [
                {"sequence": 0, "from_state": "NOT_APPLICABLE", "to_state": "QUARANTINED", "event": "FETCH_COMPLETED", "observed_at": "2026-01-01T00:00:00Z", "actor_ref": "actor://test", "reason_class": "NONE"},
                {"sequence": 1, "from_state": "QUARANTINED", "to_state": "REJECTED", "event": "REJECTED", "observed_at": "2026-01-01T00:00:01Z", "actor_ref": "actor://test", "reason_class": "CONTENT_TYPE_DISALLOWED"},
            ],
            "authority_manifest_fingerprint": "a" * 64,
            "lifecycle_fingerprint": "0" * 64,
        }
        lifecycle["lifecycle_fingerprint"] = sha256_json({key: value for key, value in lifecycle.items() if key != "lifecycle_fingerprint"})
        lifecycle_fingerprint = lifecycle["lifecycle_fingerprint"]
        network = {"operation": "external_fetch", "purpose": "external_fetch", "action_result": "DENY", "content_lifecycle": "REJECTED", "reason_class": "CONTENT_TYPE_DISALLOWED", "destination_binding_ref": "binding://test", "fetched_content_lifecycle_ref": "life-1", "fetched_content_lifecycle_fingerprint": lifecycle_fingerprint, "fetched_content_origin_binding_ref": "origin://test", "fetched_content_destination_binding_ref": "binding://test", "fetched_content_admission_state": "REJECTED", "fetched_content_retrieval_visibility": "NONE", "fetched_content_history_terminal_state": "REJECTED", "fetched_content_terminal_response_fingerprint": terminal_response_fingerprint}
        envelope = {"operation": "external_fetch", "purpose": "external_fetch", "action_result": "DENY", "authority_manifest_fingerprint": "a" * 64, "destination_binding_ref": "binding://test", "fetched_content_lifecycle_ref": "life-1", "fetched_content_lifecycle_fingerprint": lifecycle_fingerprint, "fetched_content_origin_binding_ref": "origin://test", "fetched_content_destination_binding_ref": "binding://test", "fetched_content_admission_state": "REJECTED", "fetched_content_retrieval_visibility": "NONE", "fetched_content_history_terminal_state": "REJECTED", "fetched_content_terminal_response_fingerprint": terminal_response_fingerprint}
        validate_external_emission(envelope, network, lifecycle)

        with self.assertRaisesRegex(ContractViolation, "lifecycle_required_for_content_operation"):
            validate_external_emission(envelope, network)

        mismatch_cases = (
            ({"purpose": "retrieval"}, "cross_record_purpose_mismatch"),
            ({"network_binding_fingerprint": "d" * 64}, "network_binding_fingerprint_mismatch"),
            ({"outbound_network_decision_ref": "decision://other"}, "outbound_network_decision_binding_mismatch"),
            ({"outbound_network_decision_fingerprint": "e" * 64}, "outbound_network_decision_binding_mismatch"),
            ({"destination_binding_ref": "binding://other"}, "destination_binding_mismatch"),
            ({"fetched_content_lifecycle_ref": "life-other"}, "lifecycle_ref_mismatch"),
            ({"fetched_content_lifecycle_fingerprint": "f" * 64}, "lifecycle_fingerprint_mismatch"),
            ({"fetched_content_origin_binding_ref": "origin://other"}, "lifecycle_origin_binding_ref_mismatch"),
            ({"fetched_content_destination_binding_ref": "binding://other"}, "lifecycle_destination_binding_ref_mismatch"),
            ({"fetched_content_admission_state": "ADMITTED_TYPED_DATA"}, "lifecycle_admission_state_mismatch"),
            ({"fetched_content_retrieval_visibility": "QUARANTINE_ONLY"}, "lifecycle_retrieval_visibility_mismatch"),
            ({"fetched_content_history_terminal_state": "QUARANTINED"}, "lifecycle_history_terminal_state_mismatch"),
            ({"fetched_content_terminal_response_fingerprint": "1" * 64}, "lifecycle_terminal_response_fingerprint_mismatch"),
        )
        for overrides, expected in mismatch_cases:
            with self.subTest(overrides=overrides):
                with self.assertRaisesRegex(ContractViolation, expected):
                    validate_external_emission({**envelope, **overrides}, network, lifecycle)

        with self.assertRaisesRegex(ContractViolation, "integrated_allow_without_network_allow"):
            validate_external_emission({**envelope, "action_result": "ALLOW"}, network, lifecycle)

        from copy import deepcopy
        for field, expected, value in (
            ("operation", "lifecycle_operation_mismatch", "attachment_fetch"),
            ("purpose", "lifecycle_purpose_mismatch", "retrieval"),
        ):
            with self.subTest(lifecycle_field=field):
                changed_lifecycle = deepcopy(lifecycle)
                changed_lifecycle[field] = value
                if field == "operation":
                    changed_lifecycle["admission_predicate"]["explicit_operation"] = value
                changed_lifecycle["lifecycle_fingerprint"] = sha256_json({key: value for key, value in changed_lifecycle.items() if key != "lifecycle_fingerprint"})
                with self.assertRaisesRegex(ContractViolation, expected):
                    validate_external_emission(envelope, network, changed_lifecycle)

    def test_documentation_registry_and_expected_outcomes_validate(self):
        report = validate_documentation_bundle(".")
        self.assertTrue(report.ok)
        self.assertEqual(report.schema_backend, "standards")
        self.assertEqual(report.scenario_count, 34)
        registry = SchemaRegistry(".")
        matrix = registry.root / "GATE-D-R2" / "PMIRI_GD-R2-05_ADVERSARIAL_SCENARIO_MATRIX.json"
        import json
        scenarios = json.loads(matrix.read_text(encoding="utf-8"))["scenarios"]
        for scenario in scenarios:
            registry.require_valid(scenario["expected"], "pmiri://schema/gate-d-r2/expected-outcome/0.3")

    def test_evidence_record_cannot_promote_unexecuted_case_to_pass(self):
        record = create_evidence_record(
            check_id="R-FC-01",
            fixture_id="fixture-1",
            input_fingerprint="a" * 64,
            expected_dispositions=["BOUNDED_BY_TRUSTED_AUTHORIZATION"],
            forbidden_dispositions=["ALLOWED_WITHIN_ENVELOPE"],
            actual={"disposition": "BLOCKED"},
        )
        self.assertEqual(record.status, "UNVERIFIED")
        self.assertEqual(validate_evidence_record(record.structured()), ())
        self.assertTrue(record.evidence_id.startswith("GC-C1-EV-"))
        self.assertTrue(record.action_trace)
        self.assertTrue(record.actual["output_fingerprint"])
        with self.assertRaises(ValueError):
            create_evidence_record(
                check_id="R-FC-01", fixture_id="fixture-1", input_fingerprint="a" * 64,
                expected_dispositions=["PASS"], forbidden_dispositions=[], actual={}, status="PASS",
            )

    def test_evidence_record_nested_contract_rejects_tampering(self):
        baseline = create_evidence_record(
            check_id="R-FC-01",
            fixture_id="fixture-1",
            input_fingerprint="a" * 64,
            expected_dispositions=["BLOCKED"],
            forbidden_dispositions=["ALLOWED_WITHIN_ENVELOPE"],
            actual={"disposition": "BLOCKED"},
        ).structured()
        mutations = (
            ("authority", lambda record: record.update({"authority_refs": []}), "authority_refs_missing"),
            ("fixture", lambda record: record.update({"fixture": {}}), "fixture_invalid"),
            ("trace", lambda record: record.update({"action_trace": []}), "action_trace_missing"),
            ("trace_step", lambda record: record["action_trace"][0].update({"step": 0}), "action_trace_invalid"),
            ("oracle", lambda record: record.update({"oracle": {}}), "oracle_invalid"),
            ("actual", lambda record: record["actual"].update({"output_fingerprint": "not-a-fingerprint"}), "actual_invalid"),
            ("lineage", lambda record: record.update({"lineage": {}}), "lineage_invalid"),
            ("replay", lambda record: record["replay"].update({"environment_fingerprint": "not-a-fingerprint"}), "replay_invalid"),
            ("review", lambda record: record["review"].update({"review_result": "unknown"}), "review_invalid"),
            ("status", lambda record: record.update({"status": "UNKNOWN"}), "status_invalid"),
            ("identity", lambda record: record.update({"evidence_id": "not-an-evidence-id"}), "evidence_id_invalid"),
            ("check", lambda record: record.update({"check_id": "R-FC-99"}), "evidence_identity_invalid"),
            ("matrix", lambda record: record.update({"matrix_version": "0.2"}), "evidence_identity_invalid"),
        )
        from copy import deepcopy
        for name, mutate, expected in mutations:
            with self.subTest(name=name):
                record = deepcopy(baseline)
                mutate(record)
                self.assertIn(expected, validate_evidence_record(record))

    def test_artifact_seal_detects_tampering(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as temp:
            root = Path(temp)
            artifact = root / "result.json"
            artifact.write_text("{}\n", encoding="utf-8")
            sealed = seal_directory(root, case_id="case-1")
            self.assertEqual(verify_seal(sealed["manifest_path"]), (True, "SEALED"))
            self.assertEqual(sealed["completeness"], "INCOMPLETE")
            (root / "undeclared.txt").write_text("tamper\n", encoding="utf-8")
            self.assertEqual(verify_seal(sealed["manifest_path"]), (False, "filesystem_inventory_mismatch:extra=undeclared.txt"))
            artifact.write_text("{\"changed\":true}\n", encoding="utf-8")
            self.assertEqual(verify_seal(sealed["manifest_path"])[0], False)

    def test_artifact_seal_excludes_derived_outputs_and_handoff_payloads(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "candidate.txt").write_text("candidate", encoding="utf-8")
            (root / "artifacts" / "candidate-report.json").parent.mkdir(parents=True)
            (root / "artifacts" / "candidate-report.json").write_text("report", encoding="utf-8")
            for relative in (
                ".git/config",
                "graphify-out/graph.json",
                ".codebase-memory/graph.db.zst",
                "build/lib/pmiri.py",
                "pmiri.egg-info/PKG-INFO",
                ".venv-pmiri-exact/Lib/site-packages/runtime.py",
                "venv/Scripts/python.exe",
                "artifacts/handoff-release-v99/payload/README.md",
                "artifacts/package-current/pmiri/r_fc.py",
                "artifacts/read-audit.jsonl",
                "artifacts/review-package.json",
            ):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("derived", encoding="utf-8")
            report = seal_directory(root, case_id="case", output_dir=root / "sealed")
            paths = {entry["path"] for entry in report["entries"] if "path" in entry}
            self.assertIn("candidate.txt", paths)
            self.assertIn("artifacts/candidate-report.json", paths)
            self.assertFalse(any(path.startswith(".git/") for path in paths))
            self.assertFalse(any(path.startswith("graphify-out/") for path in paths))
            self.assertFalse(any(path.startswith(".codebase-memory/") for path in paths))
            self.assertFalse(any(path.startswith("build/") for path in paths))
            self.assertFalse(any(path.startswith("pmiri.egg-info/") for path in paths))
            self.assertFalse(any(path.startswith(".venv-pmiri-exact/") for path in paths))
            self.assertFalse(any(path.startswith("venv/") for path in paths))
            self.assertFalse(any(path.startswith("artifacts/handoff") for path in paths))
            self.assertNotIn("artifacts/read-audit.jsonl", paths)
            self.assertFalse(any(path.startswith("artifacts/package-") for path in paths))
            self.assertFalse(any(path == "artifacts/review-package.json" for path in paths))

    def test_artifact_seal_ignores_symlinks_to_outside_content(self):
        with TemporaryDirectory() as temp, TemporaryDirectory() as outside:
            root = Path(temp)
            target = Path(outside) / "outside.txt"
            target.write_text("outside secret", encoding="utf-8")
            link = root / "linked.txt"
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is unavailable")
            sealed = seal_directory(root, case_id="case-symlink")
            paths = {entry["path"] for entry in sealed["entries"] if "path" in entry}
            self.assertNotIn("linked.txt", paths)
            self.assertEqual(verify_seal(sealed["manifest_path"]), (True, "SEALED"))

    def test_runner_package_manifest_is_exact_and_boundary_closed(self):
        package = Path("PMIRI_ALL_DOCUMENTATION_CHECKPOINT_17/GC-C1/PMIRI_GC-C1_REPLAY_RUNNER_0.1.0")
        self.assertEqual(_verify_runner_package(package / "runner-manifest.json"), (True, "pinned_runner_package_matches"))
        with TemporaryDirectory() as temp:
            copied = Path(temp) / "runner"
            shutil.copytree(package, copied)
            manifest_path = copied / "runner-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["package_files"] = manifest["package_files"][:1]
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            self.assertEqual(_verify_runner_package(manifest_path), (False, "runner_package_inventory_invalid"))

    def test_d2_matrix_is_documentarily_closed_but_not_runtime_executed(self):
        report = validate_d2_matrix(".")
        self.assertEqual(report["status"], "D2_DOCUMENTARY_VALIDATED_RUNTIME_BLOCKED")
        self.assertEqual(report["scenario_count"], 34)
        self.assertTrue(all(case["expected"]["runtime_status"] == "BLOCKED" for case in report["cases"]))

    def test_d2_runtime_candidate_executes_all_fixture_oracles_without_external_access(self):
        report = run_d2_runtime_candidate(Path(__file__).parents[1])
        self.assertEqual(report["status"], "D2_RUNTIME_CANDIDATE")
        self.assertEqual(report["scenario_count"], 34)
        self.assertEqual(report["fixture_signal_count"], 34)
        self.assertTrue(report["all_oracles_match"])
        self.assertFalse(report["authority_execution_authorized"])
        self.assertEqual(report["external_provider_access"], "NOT_PERFORMED")
        self.assertEqual(report["external_connector_access"], "NOT_PERFORMED")
        self.assertEqual(report["external_network_access"], "NOT_PERFORMED")
        self.assertTrue(report["documentation_runtime_status_preserved"])

    def test_r_fc_status_emits_seventeen_blocked_schema_shaped_records_without_execution(self):
        report = run_r_fc_blocked_candidate(Path(__file__).parents[1])
        self.assertEqual(report["status"], "R_FC_REPLAY_BLOCKED")
        self.assertEqual(report["executed_case_count"], 0)
        self.assertEqual(report["blocked_case_count"], 17)
        self.assertEqual(report["r_fc_pass"], "NONE")
        self.assertTrue(all(case["executed"] is False for case in report["cases"]))
        self.assertTrue(all(case["schema_errors"] == [] for case in report["cases"]))

    def test_decision_cache_rejects_stale_epoch_or_profile(self):
        cache = DecisionCache()
        cache.put(CachedDecision("k", {"action": "ALLOW"}, 1, "p1", "f1"))
        self.assertEqual(cache.get("k", invalidation_epoch=1, freshness_profile_id="p1", freshness_profile_fingerprint="f1"), {"action": "ALLOW"})
        self.assertIsNone(cache.get("k", invalidation_epoch=2, freshness_profile_id="p1", freshness_profile_fingerprint="f1"))
        self.assertIsNone(cache.get("k", invalidation_epoch=1, freshness_profile_id="p2", freshness_profile_fingerprint="f2"))

    def test_redaction_keeps_constraint_and_freshness_is_epoch_bound(self):
        redacted = constrained_redact("claim with qualifier", remove_terms=["qualifier"], required_obligations=["qualifier"], citations={"c1": "a1"})
        self.assertEqual(redacted.action_result, "ALLOW_WITH_CONSTRAINTS")
        self.assertTrue(redacted.constraint_refs)
        profile = FreshnessProfile("profile-1", "1.0", 60)
        observation = PolicyObservation.create("retention", "NO_TRAINING", "2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z", 3, profile)
        self.assertTrue(observation.is_fresh(now="2026-01-01T00:00:30Z", current_epoch=3, profile=profile))
        self.assertFalse(observation.is_fresh(now="2026-01-01T00:00:30Z", current_epoch=4, profile=profile))

    def test_attestation_serializes_all_domains_and_keeps_status_truthful(self):
        observations = {
            "network": IsolationObservation("network", "DENIED", "ref-network", "observed"),
            "credentials": IsolationObservation("credentials", "DENIED", "ref-credentials", "observed"),
            "filesystem": IsolationObservation("filesystem", "ALLOWLIST_VERIFIED", "ref-filesystem", "observed"),
            "connectors": IsolationObservation("connectors", "DENIED", "ref-connectors", "observed"),
            "determinism": IsolationObservation("determinism", "VERIFIED", "ref-determinism", "observed"),
            "resource_limits": IsolationObservation("resource_limits", "VERIFIED", "ref-resource_limits", "observed"),
            "teardown": IsolationObservation("teardown", "AVAILABLE", "ref-teardown", "observed"),
            "privacy": IsolationObservation("privacy", "VERIFIED", "ref-privacy", "observed"),
        }
        record = create_attestation(
            authorization_id="auth-1",
            case_id="case-1",
            launcher={"launcher_id": "pmiri-gc-c1-clean-room-launcher", "launcher_version": "0.1.0"},
            fingerprints={key: "a" * 64 for key in {"runner_source", "runner_manifest", "authority_bundle", "evidence_schema", "fixture_catalog", "preflight_matrix", "profile"}},
            observations=observations,
            case_root_policy="FRESH_CASE_ROOT",
            case_root_fingerprint="a" * 64,
        )
        self.assertEqual(record["status"], "VERIFIED")
        self.assertEqual(record["outcome"], "READY_FOR_REPLAY")
        self.assertEqual(len(record["attestation_sha256"]), 64)
        with TemporaryDirectory() as temp:
            path = Path(temp) / "attestation.json"
            write_attestation(record, path)
            loaded, loaded_observations = load_attestation(path)
            self.assertEqual(loaded["attestation_sha256"], record["attestation_sha256"])
            self.assertEqual(set(loaded_observations), set(DOMAINS))

    def test_replay_runner_blocks_before_case_execution_without_attestation(self):
        called = []
        result = run_case(
            case_id="case-1",
            identity={"runner_id": "pmiri-gc-c1-replay", "runner_version": "0.1.0", "latest_alias_allowed": False, "self_upgrade_allowed": False},
            isolation=None,
            fingerprints={},
            case=lambda: called.append(True) or {"disposition": "PASS"},
        )
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(called, [])

    def test_gate_d_exact_observations_authorize_in_memory_provider_only(self):
        engine = self._gate_d_engine()
        trust, capability, network, envelope, request, binding, authorization = self._gate_d_inputs(engine)
        self.assertEqual(trust["trust_state"], "TRUSTED_FOR_BOUND_PURPOSE")
        self.assertEqual(capability["capability_state"], "FRESH")
        self.assertEqual(network["action_result"], "ALLOW")
        self.assertEqual(envelope["action_result"], "ALLOW")
        provider = InMemoryProviderTransport({"text": "synthetic"})
        receipt = EnforcedTransportRuntime(engine, provider=provider).execute_provider(
            {"text": "bounded synthetic context"},
            envelope=envelope,
            trust_decision=trust,
            capability_decision=capability,
            network_decision=network,
            authorization_binding=binding,
            authorization_request=request,
            authorization_revalidator=authorization,
        )
        self.assertEqual(receipt.status, "EXECUTED")
        self.assertEqual(receipt.transport_called, True)
        self.assertEqual(len(provider.calls), 1)

    def test_gate_d_connector_path_revalidates_binding_and_lifecycle(self):
        engine = self._gate_d_engine()
        endpoint = "https://connector.example.test/data"
        trust, capability, network, envelope, request, binding, authorization = self._gate_d_inputs(
            engine,
            operation="connector_fetch",
            purpose="external_fetch",
            endpoint=endpoint,
            content_lifecycle="QUARANTINED",
        )
        lifecycle = {
            "record_type": "PMIRI_D2_FETCHED_CONTENT_LIFECYCLE",
            "schema_version": "0.3",
            "content_id": "content://test",
            "operation": "connector_fetch",
            "purpose": "external_fetch",
            "origin_binding_ref": network["fetched_content_origin_binding_ref"],
            "destination_binding_ref": network["fetched_content_destination_binding_ref"],
            "response_fingerprint": network["fetched_content_terminal_response_fingerprint"],
            "terminal_response_fingerprint": network["fetched_content_terminal_response_fingerprint"],
            "observed_content_type": "text/plain",
            "response_size_bytes": 0,
            "initial_classification": "EXTERNAL_UNTRUSTED_CONTENT",
            "trust_state": "UNTRUSTED",
            "history_start_state": "NOT_APPLICABLE",
            "history_terminal_state": "QUARANTINED",
            "admission_state": "QUARANTINED",
            "retrieval_visibility": "QUARANTINE_ONLY",
            "canonical_or_control_influence_prohibited": True,
            "admission_predicate": {
                "explicit_operation": "connector_fetch",
                "explicit_operation_ref": "operation://connector_fetch",
                "origin_bound": True,
                "parser_result_ref": "parser://test",
                "classification_ref": "classification://test",
                "validation_result_ref": "validation://test",
                "content_policy_result_ref": "policy://test",
                "instruction_influence_prohibited": True,
                "control_influence_prohibited": True,
            },
            "transitions": [
                {
                    "sequence": 0,
                    "from_state": "NOT_APPLICABLE",
                    "to_state": "QUARANTINED",
                    "event": "FETCH_COMPLETED",
                    "observed_at": "2026-01-01T00:00:00Z",
                    "actor_ref": "actor://test",
                    "reason_class": "NONE",
                }
            ],
            "authority_manifest_fingerprint": "a" * 64,
            "lifecycle_fingerprint": "0" * 64,
        }
        lifecycle["lifecycle_fingerprint"] = sha256_json({key: value for key, value in lifecycle.items() if key != "lifecycle_fingerprint"})
        network = engine.evaluate_network(
            operation="connector_fetch",
            purpose="external_fetch",
            url=endpoint,
            addresses=["93.184.216.34"],
            content_lifecycle="QUARANTINED",
            lifecycle=lifecycle,
            lifecycle_ref="life://connector-test",
        )
        envelope = engine.build_integrated_envelope(
            request=request,
            trust_decision=trust,
            capability_decision=capability,
            network_decision=network,
            authorization_binding=binding,
        )
        connector = InMemoryConnectorTransport(b"synthetic connector\n")
        receipt = EnforcedTransportRuntime(engine, connector=connector).execute_connector(
            endpoint,
            envelope=envelope,
            trust_decision=trust,
            capability_decision=capability,
            network_decision=network,
            lifecycle=lifecycle,
            authorization_binding=binding,
            authorization_request=request,
            authorization_revalidator=authorization,
        )
        self.assertEqual(receipt.status, "EXECUTED")
        self.assertTrue(receipt.transport_called)
        self.assertEqual(connector.calls, [endpoint])

    def test_gate_d_external_emission_requires_server_derived_binding(self):
        engine = self._gate_d_engine()
        trust, capability, network, _, _, _, _ = self._gate_d_inputs(engine)
        request = {
            "request_id": "gate-d-no-binding",
            "project_constraint": "local",
            "query": "synthetic test context",
            "max_results": 20,
            "operation": "provider_call",
            "purpose": "provider_call",
            "subject": {"subject_type": "model", "subject_id": "model-x", "parent_subject_ref": "provider-x"},
        }
        envelope = engine.build_integrated_envelope(
            request=request,
            trust_decision=trust,
            capability_decision=capability,
            network_decision=network,
        )
        self.assertEqual(envelope["action_result"], "DENY")
        self.assertEqual(envelope["reason_class"], "AUTHORITY_MISSING")
        provider = InMemoryProviderTransport()
        receipt = EnforcedTransportRuntime(engine, provider=provider).execute_provider(
            {"text": "must remain local"},
            envelope=envelope,
            trust_decision=trust,
            capability_decision=capability,
            network_decision=network,
        )
        self.assertFalse(receipt.transport_called)
        self.assertEqual(provider.calls, [])

    def test_gate_d_rejects_binding_substitution_before_transport(self):
        engine = self._gate_d_engine()
        trust, capability, network, envelope, request, binding, authorization = self._gate_d_inputs(engine)
        substituted_binding = replace(binding, purpose="local_read")
        provider = InMemoryProviderTransport()
        receipt = EnforcedTransportRuntime(engine, provider=provider).execute_provider(
            {"text": "must remain local"},
            envelope=envelope,
            trust_decision=trust,
            capability_decision=capability,
            network_decision=network,
            authorization_binding=substituted_binding,
            authorization_request=request,
            authorization_revalidator=authorization,
        )
        self.assertEqual(receipt.reason_class, "AUTHORIZATION_BINDING_MISMATCH")
        self.assertFalse(receipt.transport_called)
        self.assertEqual(provider.calls, [])

    def test_gate_d_rejects_envelope_network_binding_substitution(self):
        engine = self._gate_d_engine()
        trust, capability, network, envelope, request, binding, authorization = self._gate_d_inputs(engine)
        substituted = {**envelope, "network_binding_fingerprint": "c" * 64}
        substituted["decision_fingerprint"] = decision_fingerprint(substituted)
        provider = InMemoryProviderTransport()
        receipt = EnforcedTransportRuntime(engine, provider=provider).execute_provider(
            {"text": "must remain local"},
            envelope=substituted,
            trust_decision=trust,
            capability_decision=capability,
            network_decision=network,
            authorization_binding=binding,
            authorization_request=request,
            authorization_revalidator=authorization,
        )
        self.assertEqual(receipt.reason_class, "network_binding_fingerprint_mismatch")
        self.assertFalse(receipt.transport_called)
        self.assertEqual(provider.calls, [])

    def test_gate_d_revalidates_authority_after_policy_change(self):
        engine = self._gate_d_engine()
        trust, capability, network, envelope, request, binding, authorization = self._gate_d_inputs(engine)
        authorization.advance_policy_epoch(1)
        provider = InMemoryProviderTransport()
        receipt = EnforcedTransportRuntime(engine, provider=provider).execute_provider(
            {"text": "must remain local"},
            envelope=envelope,
            trust_decision=trust,
            capability_decision=capability,
            network_decision=network,
            authorization_binding=binding,
            authorization_request=request,
            authorization_revalidator=authorization,
        )
        self.assertEqual(receipt.reason_class, "AUTHORITY_REVALIDATION_FAILED")
        self.assertFalse(receipt.transport_called)
        self.assertEqual(provider.calls, [])

    def test_gate_d_requires_trusted_revalidator_for_external_emission(self):
        engine = self._gate_d_engine()
        trust, capability, network, envelope, request, binding, _ = self._gate_d_inputs(engine)
        provider = InMemoryProviderTransport()
        receipt = EnforcedTransportRuntime(engine, provider=provider).execute_provider(
            {"text": "must remain local"},
            envelope=envelope,
            trust_decision=trust,
            capability_decision=capability,
            network_decision=network,
            authorization_binding=binding,
            authorization_request=request,
        )
        self.assertEqual(receipt.reason_class, "AUTHORITY_REVALIDATION_FAILED")
        self.assertFalse(receipt.transport_called)
        self.assertEqual(provider.calls, [])

    def test_gate_d_rejects_non_in_memory_provider_without_explicit_authorization(self):
        engine = self._gate_d_engine()
        trust, capability, network, envelope, request, binding, authorization = self._gate_d_inputs(engine)

        class ExternalLikeProvider:
            def __init__(self):
                self.calls = []

            def send(self, payload):
                self.calls.append(payload)
                return {"unexpected": "execution"}

        provider = ExternalLikeProvider()
        receipt = EnforcedTransportRuntime(engine, provider=provider).execute_provider(
            {"text": "must remain blocked"},
            envelope=envelope,
            trust_decision=trust,
            capability_decision=capability,
            network_decision=network,
            authorization_binding=binding,
            authorization_request=request,
            authorization_revalidator=authorization,
        )
        self.assertEqual(receipt.status, "BLOCKED")
        self.assertEqual(receipt.reason_class, "EXTERNAL_PROVIDER_NOT_AUTHORIZED")
        self.assertFalse(receipt.transport_called)
        self.assertEqual(provider.calls, [])

    def test_gate_d_substitution_is_denied_without_transport_call(self):
        engine = self._gate_d_engine()
        trust, capability, network, _, _, binding, authorization = self._gate_d_inputs(engine)
        denied_trust = engine.evaluate_trust(
            subject={"subject_type": "model", "subject_id": "unregistered", "parent_subject_ref": "provider-x"},
            purpose="provider_call",
            material_class="SYNTHETIC_TEXT",
            feature="answer",
            zone="LOCAL",
            assertions=[],
            capability_decision_ref=capability["decision_id"],
        )
        request = {
            "request_id": "gate-d-substitution",
            "project_constraint": "local",
            "query": "synthetic test context",
            "max_results": 20,
            "operation": "provider_call",
            "purpose": "provider_call",
            "subject": {"subject_id": "unregistered"},
        }
        envelope = engine.build_integrated_envelope(request=request, trust_decision=denied_trust, capability_decision=capability, network_decision=network)
        provider = InMemoryProviderTransport()
        receipt = EnforcedTransportRuntime(engine, provider=provider).execute_provider(
            {"text": "must not be sent"},
            envelope=envelope,
            trust_decision=denied_trust,
            capability_decision=capability,
            network_decision=network,
            authorization_binding=binding,
            authorization_request=request,
            authorization_revalidator=authorization,
        )
        self.assertEqual(envelope["action_result"], "DENY")
        self.assertFalse(receipt.transport_called)
        self.assertEqual(provider.calls, [])

    def test_gate_d_epoch_change_rejects_stale_envelope_before_call(self):
        engine = self._gate_d_engine()
        trust, capability, network, envelope, request, binding, authorization = self._gate_d_inputs(engine)
        engine.invalidate()
        provider = InMemoryProviderTransport()
        receipt = EnforcedTransportRuntime(engine, provider=provider).execute_provider(
            {"text": "stale"},
            envelope=envelope,
            trust_decision=trust,
            capability_decision=capability,
            network_decision=network,
            authorization_binding=binding,
            authorization_request=request,
            authorization_revalidator=authorization,
        )
        self.assertEqual(receipt.reason_class, "POLICY_EPOCH_CHANGED")
        self.assertFalse(receipt.transport_called)
        self.assertEqual(provider.calls, [])

    def test_gate_d_network_disabled_keeps_external_path_denied(self):
        engine = self._gate_d_engine(network_execution_enabled=False)
        trust, capability, network, envelope, request, binding, authorization = self._gate_d_inputs(engine)
        self.assertEqual(network["reason_class"], "EXACT_BINDING_MISSING")
        self.assertEqual(envelope["action_result"], "DENY")

    def test_gate_d_runtime_records_match_bundled_schemas(self):
        engine = self._gate_d_engine()
        trust, capability, network, envelope, _, _, _ = self._gate_d_inputs(engine)
        registry = SchemaRegistry(".")
        registry.require_valid(trust, "pmiri://schema/gate-d-r2/trust-decision/0.3")
        registry.require_valid(capability, "pmiri://schema/gate-d-r2/capability-decision/0.2")
        registry.require_valid(network, "pmiri://schema/gate-d-r2/outbound-network-decision/0.3")
        registry.require_valid(envelope, "pmiri://schema/gate-d-r2/integrated-decision-envelope/0.3")

    def test_r1_delegation_uses_intersection_and_rejects_empty_authority(self):
        self.assertEqual(
            intersect_authority(
                [{"operation": ["read", "send"], "project": ["alpha", "beta"]}, {"operation": ["read"], "project": ["alpha"]}]
            ),
            {"operation": ("read",), "project": ("alpha",)},
        )
        chain = AuthorizationSubjectChain.derive(
            service_principal_ref="service://pmiri",
            originating_trust_zone_attestation_ref="zone://local",
            operation_ref="operation://query",
            purpose_binding_ref="purpose://retrieval",
            scopes=[{"operation": ["read"], "project": ["alpha"]}],
        )
        self.assertEqual(chain.effective_authority["project"], ("alpha",))
        with self.assertRaises(SecurityContractViolation):
            AuthorizationSubjectChain.derive(
                service_principal_ref="service://pmiri",
                originating_trust_zone_attestation_ref="zone://local",
                operation_ref="operation://query",
                purpose_binding_ref="purpose://retrieval",
                scopes=[{"operation": ["read"]}, {"operation": ["send"]}],
            )

    def test_r1_purpose_binding_cannot_be_relabelled(self):
        binding = PurposeBinding.create(operation_ref="operation://provider", recognized_purpose="provider_call", derivation_ref="policy://r1")
        binding.verify_requested_purpose("provider_call")
        with self.assertRaises(SecurityContractViolation):
            binding.verify_requested_purpose("retrieval")

    def test_r1_unknown_classification_and_mosaic_assessment_fail_closed(self):
        manifest = EgressMaterialManifest.create(
            source_refs=["evidence://1"],
            security_lineage_refs=["classification://1"],
            derived_sensitivity_refs=["assessment://1"],
            semantic_obligation_refs=["obligation://1"],
            material_members=["span://1"],
            policy_epoch=1,
        )
        validity = SecurityDecisionValidity(
            subject_chain_fingerprint="a" * 64,
            trust_zone_fingerprint="b" * 64,
            purpose="provider_call",
            material_manifest_fingerprint=manifest.fingerprint,
            operation="provider_call",
            policy_version="r1",
            policy_epoch=1,
            destination_binding_fingerprint="c" * 64,
            valid_until="2026-01-02T00:00:00Z",
        )
        sensitivity = DerivedSensitivityAssessment.assess(
            derived_artifact_ref="artifact://1",
            input_security_lineage_refs=["classification://1"],
            aggregation_semantics_ref="semantics://concat",
            policy_epoch=1,
        )
        classification = SecurityClassificationBinding(
            binding_id="classification://1",
            target_kind="evidence",
            target_id="1",
            classification="CLOUD_OK",
            assigning_authority_ref="authority://r1",
            policy_basis_ref="policy://r1",
            provenance_ref="source://1",
            valid_from="2026-01-01T00:00:00Z",
            valid_until="2026-01-02T00:00:00Z",
        )
        allowed = EgressDecision.evaluate(
            validity=validity,
            current_validity=validity,
            manifest=manifest,
            destination_binding_fingerprint="c" * 64,
            destination_kind="EXTERNAL_PROVIDER",
            classifications=[classification],
            sensitivity=sensitivity,
            now="2026-01-01T12:00:00Z",
        )
        self.assertEqual(allowed.result, "ALLOW_AS_IS")
        denied = EgressDecision.evaluate(
            validity=validity,
            current_validity=validity,
            manifest=manifest,
            destination_binding_fingerprint="c" * 64,
            destination_kind="EXTERNAL_PROVIDER",
            classifications=[None],
            sensitivity=sensitivity,
            now="2026-01-01T12:00:00Z",
        )
        self.assertEqual(denied.result, "DENY")
        restricted = DerivedSensitivityAssessment.assess(
            derived_artifact_ref="artifact://1",
            input_security_lineage_refs=["classification://1"],
            aggregation_semantics_ref="semantics://mosaic",
            policy_epoch=1,
            additional_restriction_required=True,
        )
        self.assertEqual(
            EgressDecision.evaluate(
                validity=validity,
                current_validity=validity,
                manifest=manifest,
                destination_binding_fingerprint="c" * 64,
                destination_kind="EXTERNAL_PROVIDER",
                classifications=[classification],
                sensitivity=restricted,
                now="2026-01-01T12:00:00Z",
            ).result,
            "RECOMPILE_REQUIRED_WITH_CONSTRAINTS",
        )
        denial_cases = (
            (replace(validity, policy_version="r2"), validity.destination_binding_fingerprint, classification, sensitivity, "RECOMPILE_REQUIRED_WITH_CONSTRAINTS", "POLICY_EPOCH_CHANGED"),
            (replace(validity, material_manifest_fingerprint="d" * 64), validity.destination_binding_fingerprint, classification, sensitivity, "DENY", "MATERIAL_FINGERPRINT_MISMATCH"),
            (validity, "d" * 64, classification, sensitivity, "DENY", "EXACT_BINDING_MISSING"),
            (validity, validity.destination_binding_fingerprint, replace(classification, classification="LOCAL_ONLY"), sensitivity, "DENY", "CLASSIFICATION_MISMATCH"),
            (validity, validity.destination_binding_fingerprint, classification, DerivedSensitivityAssessment.assess(derived_artifact_ref="artifact://1", input_security_lineage_refs=[], aggregation_semantics_ref="semantics://unknown", policy_epoch=1), "INDETERMINATE", "CLASSIFICATION_UNKNOWN"),
        )
        for case_validity, destination, case_classification, case_sensitivity, result, reason in denial_cases:
            with self.subTest(result=result, reason=reason):
                decision = EgressDecision.evaluate(
                    validity=case_validity,
                    current_validity=validity if reason == "POLICY_EPOCH_CHANGED" else case_validity,
                    manifest=manifest,
                    destination_binding_fingerprint=destination,
                    destination_kind="EXTERNAL_PROVIDER",
                    classifications=[case_classification],
                    sensitivity=case_sensitivity,
                    now="2026-01-01T12:00:00Z",
                )
                self.assertEqual((decision.result, decision.reason), (result, reason))

    def test_credential_boundary_is_exact_and_secret_never_enters_public_record(self):
        boundary = ConnectorCredentialBoundary(
            boundary_id="boundary-1",
            connector_subject_ref="connector://test",
            operation="connector_fetch",
            connector_process_ref="process://test",
            destination_ref="destination://test",
            operation_scope=("connector_fetch",),
            injection_channel="PROCESS_MEMORY_HANDLE",
            visibility_prohibitions=tuple(sorted(VISIBILITY_PROHIBITIONS)),
            valid_from="2026-01-01T00:00:00Z",
            valid_until="2026-01-02T00:00:00Z",
            credential_epoch=3,
            rotation_ref="rotation://1",
            revocation_ref="revocation://1",
            source_ref="authority://credential",
            authority_manifest_fingerprint="a" * 64,
        )
        manager = CredentialManager()
        bound = manager.bind(
            boundary,
            b"secret-value",
            operation="connector_fetch",
            connector_process_ref="process://test",
            destination_ref="destination://test",
            current_epoch=3,
            now="2026-01-01T12:00:00Z",
        )
        self.assertEqual(bound.action_result, "ALLOW")
        self.assertEqual(repr(bound.handle), "OpaqueCredential(<redacted>)")
        self.assertNotIn("secret-value", str(bound.public_dict()))
        received = []
        bound.handle.inject(received.append)
        self.assertEqual(received, [b"secret-value"])
        denied = manager.bind(
            boundary,
            b"secret-value",
            operation="connector_fetch",
            connector_process_ref="process://other",
            destination_ref="destination://test",
            current_epoch=3,
            now="2026-01-01T12:00:00Z",
        )
        self.assertEqual(denied.action_result, "DENY")
        self.assertIsNone(denied.handle)
        SchemaRegistry(".").require_valid(boundary.public_record(), "pmiri://schema/gate-d-r2/connector-credential-boundary/0.2")

    def test_controlled_replay_is_fresh_case_scoped_and_sealed(self):
        isolation = {
            "network": IsolationObservation("network", "DENIED", "obs-network", "external observation"),
            "credentials": IsolationObservation("credentials", "DENIED", "obs-credentials", "external observation"),
            "filesystem": IsolationObservation("filesystem", "ALLOWLIST_VERIFIED", "obs-filesystem", "external observation"),
            "connectors": IsolationObservation("connectors", "DENIED", "obs-connectors", "external observation"),
            "determinism": IsolationObservation("determinism", "VERIFIED", "obs-determinism", "external observation"),
            "resource_limits": IsolationObservation("resource_limits", "VERIFIED", "obs-resource", "external observation"),
            "teardown": IsolationObservation("teardown", "AVAILABLE", "obs-teardown", "external observation"),
            "privacy": IsolationObservation("privacy", "VERIFIED", "obs-privacy", "external observation"),
        }
        fingerprints = {key: "a" * 64 for key in ("runner_source", "runner_manifest", "authority_bundle", "evidence_schema", "fixture_catalog", "preflight_matrix", "preflight_record_schema")}
        result = run_controlled_case(
            case_id="GC-C1-FC01-P",
            identity={"runner_id": "pmiri-gc-c1-replay", "runner_version": "0.1.0", "latest_alias_allowed": False, "self_upgrade_allowed": False},
            isolation=isolation,
            fingerprints=fingerprints,
            inputs={"fixture.txt": b"synthetic fixture\n"},
            case=lambda root: {"disposition": "ALLOWED_WITHIN_ENVELOPE", "input_exists": (root / "inputs" / "fixture.txt").is_file()},
        )
        self.assertEqual(result.status, "RECORDED")
        self.assertEqual(result.reason, "case_completed_and_integrity_sealed_incomplete")
        self.assertEqual(result.replay.status, "RECORDED")
        self.assertTrue(result.artifact_manifest_fingerprint)
        self.assertTrue(result.output_fingerprint)

    def test_controlled_replay_does_not_invoke_case_without_attestation(self):
        called = []
        result = run_controlled_case(
            case_id="GC-C1-FC01-P",
            identity={"runner_id": "pmiri-gc-c1-replay", "runner_version": "0.1.0", "latest_alias_allowed": False, "self_upgrade_allowed": False},
            isolation=None,
            fingerprints={key: "a" * 64 for key in ("runner_source", "runner_manifest", "authority_bundle", "evidence_schema", "fixture_catalog", "preflight_matrix", "preflight_record_schema")},
            inputs={"fixture.txt": b"synthetic fixture\n"},
            case=lambda root: called.append(root) or {"disposition": "must-not-run"},
        )
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(called, [])


if __name__ == "__main__":
    unittest.main()
