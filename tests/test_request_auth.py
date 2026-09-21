from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from pmiri.read_projection import ReadProjectionService
from pmiri.models import QueryRequest
from pmiri.request_auth import (
    AuthenticatedPrincipal,
    AuthenticationRegistry,
    FixedWindowRateLimiter,
    RequestAuthorizationService,
    TrustZoneAttestation,
)
from pmiri.runtime import LocalEvidenceRuntime
from pmiri.store import LocalStore


ISSUED = "2025-12-31T00:00:00Z"
NOW = "2026-01-01T00:00:00Z"
EXPIRES = "2026-01-02T00:00:00Z"


class RequestAuthorizationTests(unittest.TestCase):
    def _principal(self, *, projects=("project",), authentication_ref="authn-user", epoch=3, allowed_operations=("read",)):
        principal_ref = "principal:user"
        attestation = TrustZoneAttestation.issue(
            principal_ref=principal_ref,
            zone_id="LOCAL",
            issuer_ref="security-boundary:test",
            evidence_refs=("environment://test",),
            issued_at=ISSUED,
            valid_until=EXPIRES,
        )
        return AuthenticatedPrincipal.verified(
            authentication_ref=authentication_ref,
            principal_ref=principal_ref,
            principal_type="human",
            service_principal_ref="service:pmiri",
            trust_zone_attestation=attestation,
            allowed_projects=projects,
            allowed_operations=allowed_operations,
            allowed_purposes=("local_read",),
            policy_bundle_ref="policy://read-v1",
            policy_version="1",
            policy_epoch=epoch,
            issued_at=ISSUED,
            valid_until=EXPIRES,
        )

    def _authorized_service(self, *, projects=("project",), max_requests=60, epoch=3, with_source=True, allowed_operations=("read",)):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        store = LocalStore(Path(temp.name) / "store")
        store.initialize()
        if with_source:
            store.register_bytes("project", "guide.md", b"release status is ready\n", capture_time=ISSUED)
        registry = AuthenticationRegistry()
        registry.register(self._principal(projects=projects, epoch=epoch, allowed_operations=allowed_operations))
        auth = RequestAuthorizationService(
            registry,
            current_policy_epoch=epoch,
            rate_limiter=FixedWindowRateLimiter(max_requests=max_requests, window_seconds=60),
            clock=lambda: 100.0,
        )
        return ReadProjectionService(LocalEvidenceRuntime(store), auth)

    def test_operation_not_allowed_is_an_explicit_denial(self):
        service = self._authorized_service(allowed_operations=("provider_call",))
        evaluation = service.authorization.evaluate(
            QueryRequest("auth-operation-denied", "project", "release"),
            authentication_ref="authn-user",
            now=NOW,
        )
        self.assertFalse(evaluation.allowed)
        self.assertEqual(evaluation.reason, "OPERATION_NOT_ALLOWED")
        self.assertIsNone(evaluation.binding)

    def test_revalidate_rejects_request_and_policy_epoch_substitution(self):
        service = self._authorized_service()
        authorization = service.authorization
        request = QueryRequest("auth-revalidate", "project", "release")
        evaluation = authorization.evaluate(request, authentication_ref="authn-user", now=NOW)
        self.assertTrue(evaluation.allowed)
        self.assertIsNotNone(evaluation.binding)
        binding = evaluation.binding

        changed_request = QueryRequest("auth-revalidate", "project", "different")
        self.assertFalse(authorization.revalidate(changed_request, binding, now=NOW))

        from dataclasses import replace
        self.assertFalse(authorization.revalidate(request, replace(binding, policy_epoch=binding.policy_epoch + 1), now=NOW))

    def test_api_and_mcp_use_same_authenticated_server_binding(self):
        service = self._authorized_service()
        api = service.api_authenticated(
            {"request_id": "auth-api", "project_constraint": "project", "query": "release"},
            authentication_ref="authn-user",
            now=NOW,
        )
        mcp = service.mcp_authenticated(
            {"request_id": "auth-mcp", "project_constraint": "project", "query": "release"},
            authentication_ref="authn-user",
            now=NOW,
        )
        self.assertTrue(api["evidence"])
        self.assertTrue(mcp["evidence"])
        self.assertNotIn("principal_ref", api["lineage"])
        self.assertNotIn("trust_zone", api["lineage"])
        self.assertEqual(api["lineage"]["scope"], mcp["lineage"]["scope"])

    def test_client_authorization_ref_cannot_widen_authenticated_request(self):
        service = self._authorized_service()
        normal = service.api_authenticated(
            {"request_id": "auth-normal", "project_constraint": "project", "query": "release"},
            authentication_ref="authn-user",
            now=NOW,
        )
        forged = service.api_authenticated(
            {
                "request_id": "auth-forged",
                "project_constraint": "project",
                "query": "release",
                "authorization_ref": "auth-wider",
            },
            authentication_ref="authn-user",
            now=NOW,
        )
        self.assertTrue(normal["evidence"])
        self.assertTrue(forged["evidence"])
        self.assertEqual(normal["result"]["disposition"], forged["result"]["disposition"])
        self.assertEqual(normal["lineage"]["scope"], forged["lineage"]["scope"])

    def test_scope_purpose_unknown_auth_and_stale_epoch_are_empty(self):
        service = self._authorized_service()
        base = {"project_constraint": "project", "query": "release"}
        unknown = service.api_authenticated({**base, "request_id": "auth-unknown"}, authentication_ref="forged", now=NOW)
        purpose = service.api_authenticated({**base, "request_id": "auth-purpose", "purpose": "provider_call"}, authentication_ref="authn-user", now=NOW)
        scope = service.api_authenticated({**base, "request_id": "auth-scope", "project_constraint": "other"}, authentication_ref="authn-user", now=NOW)
        self.assertEqual(unknown["result"], {"disposition": "EMPTY", "coverage": "unknown"})
        self.assertEqual(purpose["result"], {"disposition": "EMPTY", "coverage": "unknown"})
        self.assertEqual(scope["result"], {"disposition": "EMPTY", "coverage": "unknown"})
        service.authorization.advance_policy_epoch(4)
        stale = service.api_authenticated({**base, "request_id": "auth-stale"}, authentication_ref="authn-user", now=NOW)
        self.assertEqual(stale["result"], {"disposition": "EMPTY", "coverage": "unknown"})

    def test_replay_and_rate_limit_fail_closed(self):
        service = self._authorized_service(max_requests=2)
        raw = {"request_id": "auth-replay", "project_constraint": "project", "query": "release"}
        first = service.api_authenticated(raw, authentication_ref="authn-user", now=NOW)
        replay = service.mcp_authenticated(raw, authentication_ref="authn-user", now=NOW)
        third = service.api_authenticated({**raw, "request_id": "auth-third"}, authentication_ref="authn-user", now=NOW)
        self.assertTrue(first["evidence"])
        self.assertEqual(replay["result"], {"disposition": "EMPTY", "coverage": "unknown"})
        self.assertEqual(third["result"], {"disposition": "EMPTY", "coverage": "unknown"})

    def test_policy_revocation_after_retrieval_is_caught_before_disclosure(self):
        service = self._authorized_service()
        inner = service.runtime
        authorization = service.authorization

        class EpochChangingRuntime:
            def query(self, request):
                result = inner.query(request)
                authorization.advance_policy_epoch(4)
                return result

        service.runtime = EpochChangingRuntime()
        response = service.api_authenticated(
            {"request_id": "auth-revoked-before-response", "project_constraint": "project", "query": "release"},
            authentication_ref="authn-user",
            now=NOW,
        )
        self.assertEqual(response["result"], {"disposition": "EMPTY", "coverage": "unknown"})
        self.assertEqual(response["evidence"], [])

    def test_disclosure_equivalence_hides_cross_project_existence(self):
        denied = self._authorized_service(projects=("project",))
        empty = self._authorized_service(projects=("other",), with_source=False)
        raw = {"request_id": "equivalence", "project_constraint": "other", "query": "release"}
        denied_result = denied.api_authenticated(raw, authentication_ref="authn-user", now=NOW)
        empty_result = empty.api_authenticated(raw, authentication_ref="authn-user", now=NOW)
        self.assertEqual(denied_result, empty_result)

    def test_caller_boolean_cannot_bypass_configured_authorization_service(self):
        service = self._authorized_service()
        with self.assertRaisesRegex(ValueError, "caller_authorization_flag_not_authority"):
            service.api_disclosed(
                {"request_id": "auth-bypass", "project_constraint": "project", "query": "release"},
                authorized=True,
            )
        with self.assertRaisesRegex(ValueError, "authenticated_adapter_required"):
            service.api({"request_id": "auth-bypass-2", "project_constraint": "project", "query": "release"})


if __name__ == "__main__":
    unittest.main()
