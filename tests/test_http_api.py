from __future__ import annotations

import json
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.client import HTTPConnection
from pathlib import Path
from tempfile import TemporaryDirectory

from pmiri.audit import JsonlAuditSink
from pmiri.http_api import AUTHENTICATION_HEADER, LocalReadHTTPError, LocalReadHTTPServer, LocalReadMetrics
from pmiri.read_operations import ReadOperationService
from pmiri.read_projection import ReadProjectionService
from pmiri.request_auth import (
    AuthenticatedPrincipal,
    AuthenticationRegistry,
    FixedWindowRateLimiter,
    RequestAuthorizationService,
    TrustZoneAttestation,
)
from pmiri.runtime import LocalEvidenceRuntime
from pmiri.store import LocalStore


class LocalReadHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        issued = now.isoformat().replace("+00:00", "Z")
        expires = (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        store = LocalStore(Path(self.temp.name) / "store")
        store.initialize()
        store.register_bytes("project", "guide.md", b"release status is ready\n", capture_time=issued)
        principal_ref = "principal:http-user"
        attestation = TrustZoneAttestation.issue(
            principal_ref=principal_ref,
            zone_id="LOCAL",
            issuer_ref="security-boundary:test",
            evidence_refs=("environment://test",),
            issued_at=issued,
            valid_until=expires,
        )
        principal = AuthenticatedPrincipal.verified(
            authentication_ref="authn-http-user",
            principal_ref=principal_ref,
            principal_type="human",
            service_principal_ref="service:pmiri",
            trust_zone_attestation=attestation,
            allowed_projects=("project",),
            allowed_purposes=("local_read",),
            policy_bundle_ref="policy://read-v1",
            policy_version="1",
            policy_epoch=3,
            issued_at=issued,
            valid_until=expires,
        )
        registry = AuthenticationRegistry()
        registry.register(principal)
        authorization = RequestAuthorizationService(
            registry,
            current_policy_epoch=3,
            rate_limiter=FixedWindowRateLimiter(max_requests=20, window_seconds=60),
        )
        projection = ReadProjectionService(LocalEvidenceRuntime(store), authorization)
        self.service = ReadOperationService(projection)
        self.audit = JsonlAuditSink(Path(self.temp.name) / "audit.jsonl")
        self.server = LocalReadHTTPServer(("127.0.0.1", 0), self.service, audit_sink=self.audit)
        self.addCleanup(self.server.server_close)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop_server)

    def _stop_server(self):
        self.server.shutdown()
        self.thread.join(timeout=2)

    def _request(self, method, path, body=None, headers=None):
        connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        payload = None if body is None else json.dumps(body).encode("utf-8")
        connection.request(method, path, body=payload, headers=headers or {})
        response = connection.getresponse()
        result = response.status, json.loads(response.read().decode("utf-8"))
        connection.close()
        return result

    def test_health_and_authenticated_read(self):
        status, health = self._request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(health, {"status": "OK", "transport": "LOOPBACK_ONLY"})
        status, result = self._request(
            "POST",
            "/v1/read/search",
            {"request_id": "http-read-1", "project_constraint": "project", "query": "release"},
            {"Content-Type": "application/json", AUTHENTICATION_HEADER: "authn-http-user"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(result["operation"], "search")
        self.assertTrue(result["projection"]["evidence"])
        self.assertEqual(result["emission_fence"]["status"], "EMIT_VALID")
        events = self.audit.read_verified()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["outcome"], "EMITTED")
        event_text = json.dumps(events[0], ensure_ascii=False)
        self.assertNotIn("release", event_text)
        self.assertNotIn("authn-http-user", event_text)

    def test_metrics_are_low_sensitivity_and_count_outcomes(self):
        metrics = LocalReadMetrics()
        self.server.metrics = metrics
        status, _ = self._request("GET", "/healthz")
        self.assertEqual(status, 200)
        status, _ = self._request("GET", "/metrics")
        self.assertEqual(status, 200)
        status, _ = self._request(
            "POST",
            "/v1/read/search",
            {"request_id": "http-metrics-1", "project_constraint": "project", "query": "release"},
            {"Content-Type": "application/json"},
        )
        self.assertEqual(status, 401)
        status, body = self._request("GET", "/metrics")
        self.assertEqual(status, 200)
        self.assertEqual(body["metrics"]["http_requests_total"], 4)
        self.assertEqual(body["metrics"]["http_requests_rejected_total"], 1)
        self.assertEqual(body["metrics"]["http_requests_emitted_total"], 0)
        body_text = json.dumps(body, ensure_ascii=False).casefold()
        self.assertNotIn("project", body_text)
        self.assertNotIn("authentication", body_text)

    def test_request_body_limit_rejects_before_runtime(self):
        limited = LocalReadHTTPServer(
            ("127.0.0.1", 0),
            self.service,
            max_request_bytes=64,
            audit_sink=self.audit,
        )
        thread = threading.Thread(target=limited.serve_forever, daemon=True)
        thread.start()
        connection = HTTPConnection("127.0.0.1", limited.server_port, timeout=3)
        try:
            body = json.dumps({"query": "x" * 256}).encode("utf-8")
            connection.request(
                "POST",
                "/v1/read/search",
                body=body,
                headers={
                    "Content-Type": "application/json",
                    AUTHENTICATION_HEADER: "authn-http-user",
                },
            )
            response = connection.getresponse()
            payload = json.loads(response.read().decode("utf-8"))
        finally:
            connection.close()
            limited.shutdown()
            thread.join(timeout=2)
            limited.server_close()

        self.assertEqual(response.status, 413)
        self.assertEqual(payload, {"error": {"code": "REQUEST_REJECTED"}})
        events = self.audit.read_verified()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["outcome"], "REJECTED")
        self.assertEqual(events[0]["operation"], "search")
        self.assertEqual(events[0]["status_code"], 413)

    def test_missing_auth_and_operation_substitution_are_generic_denials(self):
        status, missing = self._request(
            "POST",
            "/v1/read/search",
            {"request_id": "http-read-2", "project_constraint": "project", "query": "release"},
            {"Content-Type": "application/json"},
        )
        self.assertEqual(status, 401)
        self.assertEqual(missing, {"error": {"code": "REQUEST_REJECTED"}})
        self.assertEqual(self.audit.read_verified()[0]["outcome"], "REJECTED")
        status, substituted = self._request(
            "POST",
            "/v1/read/search",
            {"operation": "status", "request_id": "http-read-3", "project_constraint": "project", "query": "release"},
            {"Content-Type": "application/json", AUTHENTICATION_HEADER: "authn-http-user"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(substituted, {"error": {"code": "REQUEST_REJECTED"}})

    def test_server_rejects_non_loopback_and_unauthorized_construction(self):
        with self.assertRaisesRegex(LocalReadHTTPError, "loopback_only_bind_required"):
            LocalReadHTTPServer(("0.0.0.0", 0), self.service)
        store = LocalStore(Path(self.temp.name) / "unauthorized-store")
        store.initialize()
        service = ReadOperationService(ReadProjectionService(LocalEvidenceRuntime(store)))
        with self.assertRaisesRegex(LocalReadHTTPError, "server_authorization_service_required"):
            LocalReadHTTPServer(("127.0.0.1", 0), service)


if __name__ == "__main__":
    unittest.main()
