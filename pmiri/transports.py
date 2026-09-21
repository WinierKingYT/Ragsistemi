"""Explicit HTTPS provider/connector transports behind the Gate-D fence.

These adapters contain the real I/O seam but do not enable it by default.
Construction requires an explicit external-execution opt-in plus a matching
``ALLOW`` network decision.  The enforced runtime remains the final authority
and blocks these transports unless its external authorization flag is true.
DNS answers are supplied as part of the decision boundary; the adapter connects
to the selected address while retaining the normalized hostname for TLS/SNI.
"""

from __future__ import annotations

import base64
import http.client
import json
import socket
import ssl
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .canonical import canonical_json, sha256_bytes, sha256_json
from .credentials import OpaqueCredential
from .network import (
    CANONICALIZATION_PROFILE_FINGERPRINT,
    CANONICALIZATION_PROFILE_ID,
    NetworkBoundary,
    NetworkBoundaryError,
    NormalizedTarget,
    ResourceLimits,
    normalize_url,
    validate_connection_binding,
)


class TransportAuthorizationError(ValueError):
    pass


@dataclass(frozen=True)
class TransportResponse:
    status: int
    content_type: str
    body: bytes
    response_fingerprint: str

    def public_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "content_type": self.content_type,
            "byte_length": len(self.body),
            "response_fingerprint": self.response_fingerprint,
        }


def _header_bytes(headers: list[tuple[str, str]]) -> int:
    return sum(len(name.encode("utf-8")) + len(value.encode("utf-8")) + 4 for name, value in headers)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that pins TCP connection to a prevalidated address."""

    def __init__(self, hostname: str, selected_ip: str, *, timeout: float, context: ssl.SSLContext | None):
        super().__init__(hostname, 443, timeout=timeout, context=context or ssl.create_default_context())
        self._selected_ip = selected_ip

    def connect(self) -> None:  # pragma: no cover - network requires external authorization
        sock = socket.create_connection((self._selected_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _validate_binding(
    endpoint: str,
    decision: Mapping[str, Any],
    expected_operation: str,
    connection_binding: Mapping[str, Any] | None,
) -> NormalizedTarget:
    try:
        target = normalize_url(endpoint)
    except NetworkBoundaryError as exc:
        raise TransportAuthorizationError("transport_endpoint_invalid") from exc
    if decision.get("action_result") not in {"ALLOW", "ALLOW_WITH_CONSTRAINTS"}:
        raise TransportAuthorizationError("network_decision_not_allow")
    if decision.get("operation") != expected_operation:
        raise TransportAuthorizationError("network_operation_binding_mismatch")
    if decision.get("canonicalization_profile_id") != CANONICALIZATION_PROFILE_ID or decision.get("canonicalization_profile_fingerprint") != CANONICALIZATION_PROFILE_FINGERPRINT:
        raise TransportAuthorizationError("canonicalization_profile_mismatch")
    if decision.get("resolution_set_status") != "ALL_ALLOWLISTED_PUBLIC":
        raise TransportAuthorizationError("network_resolution_not_allowlisted")
    if decision.get("connection_binding_status") != "VALIDATED":
        raise TransportAuthorizationError("connection_binding_not_validated")
    if decision.get("final_revalidation_result") != "MATCHED":
        raise TransportAuthorizationError("network_final_revalidation_missing")
    if decision.get("tls_identity_status") != "MATCHED":
        raise TransportAuthorizationError("tls_identity_not_matched")
    if not isinstance(connection_binding, Mapping):
        raise TransportAuthorizationError("connection_binding_required")
    try:
        validate_connection_binding(dict(connection_binding))
    except NetworkBoundaryError as exc:
        raise TransportAuthorizationError("connection_binding_invalid") from exc
    if connection_binding.get("binding_fingerprint") != decision.get("connection_binding_fingerprint"):
        raise TransportAuthorizationError("connection_binding_fingerprint_mismatch")
    if connection_binding.get("connection_binding_id") != decision.get("connection_binding_ref"):
        raise TransportAuthorizationError("connection_binding_reference_mismatch")
    if connection_binding.get("destination_identity_ref") != decision.get("destination_identity_ref"):
        raise TransportAuthorizationError("connection_destination_binding_mismatch")
    if connection_binding.get("canonicalization_profile_id") != decision.get("canonicalization_profile_id") or connection_binding.get("canonicalization_profile_fingerprint") != decision.get("canonicalization_profile_fingerprint"):
        raise TransportAuthorizationError("connection_canonicalization_profile_mismatch")
    selected = connection_binding.get("selected_target")
    if not isinstance(selected, Mapping):
        raise TransportAuthorizationError("connection_selected_target_missing")
    if any(decision.get(decision_key) != selected.get(binding_key) for decision_key, binding_key in (("selected_target_resolution_ref", "resolution_entry_ref"), ("selected_target_ip", "ip"), ("selected_target_family", "family"))):
        raise TransportAuthorizationError("connection_selected_target_mismatch")
    if decision.get("tls_identity_fingerprint") != connection_binding.get("tls", {}).get("identity_binding_fingerprint"):
        raise TransportAuthorizationError("connection_tls_fingerprint_mismatch")
    final_event = connection_binding.get("revalidation_events", [])[-1]
    if decision.get("final_revalidation_event_sequence") != final_event.get("sequence") or decision.get("final_revalidation_result") != final_event.get("result"):
        raise TransportAuthorizationError("connection_final_revalidation_mismatch")
    if decision.get("connection_epoch") != connection_binding.get("connection_epoch") or decision.get("invalidation_epoch") != connection_binding.get("invalidation_epoch"):
        raise TransportAuthorizationError("connection_epoch_mismatch")
    normalized = decision.get("normalized_target")
    if (
        not isinstance(normalized, Mapping)
        or normalized.get("scheme") != "HTTPS"
        or normalized.get("authority") != target.authority
        or normalized.get("path_class") != target.request_target()
    ):
        raise TransportAuthorizationError("transport_target_binding_mismatch")
    if not isinstance(decision.get("selected_target_ip"), str) or not decision["selected_target_ip"]:
        raise TransportAuthorizationError("selected_target_missing")
    return target


class _AuthorizedHttpsTransport:
    operation = ""

    def __init__(
        self,
        endpoint: str,
        *,
        network_decision: Mapping[str, Any],
        credential: OpaqueCredential | None = None,
        authorized: bool = False,
        connection_binding: Mapping[str, Any] | None = None,
        limits: ResourceLimits = ResourceLimits(),
        connection_factory: Callable[..., Any] | None = None,
        tls_context: ssl.SSLContext | None = None,
    ):
        if not authorized:
            raise TransportAuthorizationError("external_transport_not_authorized")
        self.target = _validate_binding(endpoint, network_decision, self.operation, connection_binding)
        self.network_decision = dict(network_decision)
        self.connection_binding = dict(connection_binding) if connection_binding is not None else None
        self.selected_ip = str(network_decision["selected_target_ip"])
        self.credential = credential
        self.limits = limits
        self.connection_factory = connection_factory
        self.tls_context = tls_context

    def _connection(self):
        timeout = self.limits.total_timeout_ms / 1000
        if self.connection_factory is not None:
            return self.connection_factory(self.target, self.selected_ip, timeout)
        return _PinnedHTTPSConnection(self.target.host, self.selected_ip, timeout=timeout, context=self.tls_context)

    def _headers(self, extra: Mapping[str, str] | None = None) -> dict[str, str]:
        headers = {"Accept": "application/json, text/plain, text/markdown", "User-Agent": "pmiri-gate-d/0.1"}
        if extra:
            headers.update(extra)
        if self.credential is not None:
            encoded = self.credential.inject(lambda secret: base64.b64encode(secret).decode("ascii"))
            headers["Authorization"] = "Bearer " + encoded
        return headers

    def _request(self, method: str, *, body: bytes | None = None, headers: Mapping[str, str] | None = None) -> TransportResponse:
        connection = self._connection()
        try:
            connection.request(method, self.target.path + (("?" + self.target.query) if self.target.query is not None else ""), body=body, headers=self._headers(headers))
            response = connection.getresponse()
            raw_content_type = response.getheader("Content-Type") or ""
            content_type = raw_content_type.split(";", 1)[0].strip().casefold()
            body_bytes = response.read(self.limits.max_response_bytes + 1)
            if len(body_bytes) > self.limits.max_response_bytes:
                raise NetworkBoundaryError("RESOURCE_LIMIT_EXCEEDED")
            header_pairs = [(str(name), str(value)) for name, value in response.getheaders()]
            NetworkBoundary.validate_response(
                response_bytes=len(body_bytes),
                decompressed_bytes=len(body_bytes),
                compression_ratio=1,
                header_bytes=_header_bytes(header_pairs),
                content_type=content_type,
                limits=self.limits,
            )
            if not 200 <= int(response.status) < 300:
                raise TransportAuthorizationError("http_status_not_success")
            return TransportResponse(int(response.status), content_type, body_bytes, sha256_bytes(body_bytes))
        finally:
            connection.close()


class HttpsJsonProviderTransport(_AuthorizedHttpsTransport):
    """POST JSON to an explicitly authorized provider endpoint."""

    operation = "provider_call"

    def send(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        if not isinstance(payload, Mapping):
            raise TransportAuthorizationError("provider_payload_invalid")
        body = canonical_json(dict(payload))
        response = self._request("POST", body=body, headers={"Content-Type": "application/json"})
        try:
            decoded = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TransportAuthorizationError("provider_response_invalid_json") from exc
        if not isinstance(decoded, Mapping):
            raise TransportAuthorizationError("provider_response_must_be_object")
        return {**dict(decoded), "response_fingerprint": response.response_fingerprint}


class HttpsConnectorTransport(_AuthorizedHttpsTransport):
    """GET one pre-bound connector endpoint without following redirects."""

    operation = "connector_fetch"

    def fetch(self, target: str) -> bytes:
        requested = normalize_url(target)
        if requested.fingerprint != self.target.fingerprint:
            raise TransportAuthorizationError("connector_target_binding_mismatch")
        response = self._request("GET", headers={"Accept": "text/plain, text/markdown, application/json"})
        return response.body


__all__ = ["HttpsConnectorTransport", "HttpsJsonProviderTransport", "TransportAuthorizationError", "TransportResponse"]
