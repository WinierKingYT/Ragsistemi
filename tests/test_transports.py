from __future__ import annotations

import json
import ssl
import unittest
from unittest.mock import MagicMock, patch

from pmiri.credentials import OpaqueCredential
from pmiri.gate_d import GateDDecisionEngine
from pmiri.network import ResourceLimits, build_connection_binding
from pmiri.transports import HttpsConnectorTransport, HttpsJsonProviderTransport, TransportAuthorizationError, _PinnedHTTPSConnection


class _FakeResponse:
    status = 200

    def __init__(self, body: bytes, content_type: str):
        self.body = body
        self.content_type = content_type

    def getheader(self, name: str):
        return self.content_type if name.casefold() == "content-type" else None

    def getheaders(self):
        return [("Content-Type", self.content_type)]

    def read(self, size: int = -1):
        return self.body if size < 0 else self.body[:size]


class _FakeConnection:
    def __init__(self, response: _FakeResponse):
        self.response = response
        self.requests = []
        self.closed = False

    def request(self, method, path, body=None, headers=None):
        self.requests.append((method, path, body, dict(headers or {})))

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


class TransportTests(unittest.TestCase):
    def _decision(self, endpoint: str, operation: str = "provider_call"):
        return GateDDecisionEngine("a" * 64, now="2026-01-01T00:00:00Z", network_execution_enabled=True).evaluate_network(
            operation=operation, purpose="provider_call" if operation == "provider_call" else "external_fetch", url=endpoint, addresses=["8.8.8.8"]
        )

    def _binding(self, endpoint: str, decision):
        return build_connection_binding(
            endpoint=endpoint,
            addresses=["8.8.8.8"],
            observed_at="2026-01-01T00:00:00Z",
            connection_epoch=decision["connection_epoch"],
            invalidation_epoch=decision["invalidation_epoch"],
            destination_identity_ref=decision["destination_identity_ref"],
        )

    def test_real_transport_is_closed_without_explicit_authorization(self):
        with self.assertRaisesRegex(TransportAuthorizationError, "external_transport_not_authorized"):
            HttpsJsonProviderTransport("https://provider.example.test/answer", network_decision=self._decision("https://provider.example.test/answer"))

    def test_provider_transport_uses_bound_endpoint_and_redacts_credential_value(self):
        endpoint = "https://provider.example.test/answer"
        fake = _FakeConnection(_FakeResponse(b'{"text":"ok"}', "application/json"))
        decision = self._decision(endpoint)
        transport = HttpsJsonProviderTransport(
            endpoint,
            network_decision=decision,
            connection_binding=self._binding(endpoint, decision),
            credential=OpaqueCredential(b"secret", "a" * 64),
            authorized=True,
            connection_factory=lambda target, selected_ip, timeout: fake,
        )
        result = transport.send({"prompt": "hello"})
        self.assertEqual(result["text"], "ok")
        method, path, body, headers = fake.requests[0]
        self.assertEqual((method, path), ("POST", "/answer"))
        self.assertEqual(json.loads(body), {"prompt": "hello"})
        self.assertNotIn("secret", repr(headers))
        self.assertTrue(fake.closed)

    def test_transport_factory_receives_prevalidated_selected_address(self):
        endpoint = "https://provider.example.test/answer"
        fake = _FakeConnection(_FakeResponse(b'{"text":"ok"}', "application/json"))
        calls = []
        decision = self._decision(endpoint)

        def factory(target, selected_ip, timeout):
            calls.append((target, selected_ip, timeout))
            return fake

        transport = HttpsJsonProviderTransport(
            endpoint,
            network_decision=decision,
            connection_binding=self._binding(endpoint, decision),
            authorized=True,
            connection_factory=factory,
        )
        transport.send({"prompt": "hello"})

        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0].host, "provider.example.test")
        self.assertEqual(calls[0][1], "8.8.8.8")
        self.assertGreater(calls[0][2], 0)

    def test_default_pinned_connection_receives_deployment_tls_context(self):
        endpoint = "https://connector.example.test/data"
        fake = _FakeConnection(_FakeResponse(b"ok\n", "text/plain"))
        decision = self._decision(endpoint, "connector_fetch")
        context = ssl.create_default_context()

        with patch("pmiri.transports._PinnedHTTPSConnection", return_value=fake) as connection_type:
            transport = HttpsConnectorTransport(
                endpoint,
                network_decision=decision,
                connection_binding=self._binding(endpoint, decision),
                authorized=True,
                tls_context=context,
            )
            self.assertEqual(transport.fetch(endpoint), b"ok\n")

        connection_type.assert_called_once()
        args, kwargs = connection_type.call_args
        self.assertEqual(args[:2], ("connector.example.test", "8.8.8.8"))
        self.assertGreater(kwargs["timeout"], 0)
        self.assertIs(kwargs["context"], context)

    def test_pinned_connection_uses_selected_ip_and_hostname_for_tls_sni(self):
        raw_socket = object()
        wrapped_socket = object()
        context = MagicMock()
        context.wrap_socket.return_value = wrapped_socket

        with patch("pmiri.transports.socket.create_connection", return_value=raw_socket) as create_connection:
            connection = _PinnedHTTPSConnection(
                "connector.example.test",
                "8.8.8.8",
                timeout=1.25,
                context=context,
            )
            connection.connect()

        create_connection.assert_called_once_with(("8.8.8.8", 443), 1.25)
        context.wrap_socket.assert_called_once_with(raw_socket, server_hostname="connector.example.test")
        self.assertIs(connection.sock, wrapped_socket)

    def test_connector_rejects_target_substitution_before_connection(self):
        endpoint = "https://connector.example.test/data"
        fake = _FakeConnection(_FakeResponse(b"ok\n", "text/plain"))
        decision = self._decision(endpoint, "connector_fetch")
        transport = HttpsConnectorTransport(
            endpoint,
            network_decision=decision,
            connection_binding=self._binding(endpoint, decision),
            authorized=True,
            connection_factory=lambda target, selected_ip, timeout: fake,
        )
        with self.assertRaisesRegex(TransportAuthorizationError, "target_binding_mismatch"):
            transport.fetch("https://connector.example.test/other")
        self.assertFalse(fake.requests)

    def test_provider_rejects_query_target_substitution_before_connection(self):
        endpoint = "https://provider.example.test/answer?mode=fast"
        fake = _FakeConnection(_FakeResponse(b'{"text":"ok"}', "application/json"))
        decision = self._decision(endpoint)
        with self.assertRaisesRegex(TransportAuthorizationError, "target_binding_mismatch"):
            HttpsJsonProviderTransport(
                "https://provider.example.test/answer?mode=slow",
                network_decision=decision,
                connection_binding=self._binding(endpoint, decision),
                authorized=True,
                connection_factory=lambda target, selected_ip, timeout: fake,
            )
        self.assertFalse(fake.requests)

    def test_response_limits_are_enforced_before_result_is_returned(self):
        endpoint = "https://provider.example.test/answer"
        fake = _FakeConnection(_FakeResponse(b"1234", "text/plain"))
        decision = self._decision(endpoint, "connector_fetch")
        transport = HttpsConnectorTransport(
            endpoint,
            network_decision=decision,
            connection_binding=self._binding(endpoint, decision),
            authorized=True,
            limits=ResourceLimits(max_response_bytes=3),
            connection_factory=lambda target, selected_ip, timeout: fake,
        )
        with self.assertRaisesRegex(ValueError, "RESOURCE_LIMIT_EXCEEDED"):
            transport.fetch(endpoint)
        self.assertTrue(fake.closed)

    def test_authorized_transport_requires_the_full_connection_binding(self):
        endpoint = "https://provider.example.test/answer"
        with self.assertRaisesRegex(TransportAuthorizationError, "connection_binding_required"):
            HttpsJsonProviderTransport(
                endpoint,
                network_decision=self._decision(endpoint),
                authorized=True,
            )


if __name__ == "__main__":
    unittest.main()
