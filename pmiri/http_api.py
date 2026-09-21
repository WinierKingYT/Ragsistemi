"""Loopback-only HTTP read boundary for the local deployment candidate.

This adapter exposes the already-tested ``ReadOperationService`` over a small
stdlib HTTP surface. It requires a configured server-side authorization
service, accepts the authentication reference only from a trusted gateway
header, and never enables provider or external network transport. Binding to
anything other than IPv4 loopback is rejected deliberately; production
hosting, TLS termination and identity verification remain deployment seams.
"""

from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock
from typing import Any
from urllib.parse import urlsplit

from .audit import JsonlAuditSink, ReadAuditEvent
from .read_operations import READ_OPERATIONS, ReadOperationService


AUTHENTICATION_HEADER = "X-PMIRI-Authentication-Ref"
DEFAULT_MAX_REQUEST_BYTES = 1024 * 1024


class LocalReadHTTPError(ValueError):
    """Raised when the loopback candidate server configuration is unsafe."""


class LocalReadMetrics:
    """Thread-safe low-sensitivity counters for the loopback candidate."""

    _NAMES = (
        "http_requests_total",
        "http_requests_emitted_total",
        "http_requests_rejected_total",
        "audit_write_failures_total",
    )

    def __init__(self) -> None:
        self._lock = Lock()
        self._values = {name: 0 for name in self._NAMES}

    def increment(self, name: str) -> None:
        if name not in self._values:
            raise ValueError("metric_name_invalid")
        with self._lock:
            self._values[name] += 1

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return {"status": "OK", "transport": "LOOPBACK_ONLY", "metrics": dict(self._values)}


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


class LocalReadHTTPServer(ThreadingHTTPServer):
    """A loopback-only server for authenticated read operations."""

    daemon_threads = True
    allow_reuse_address = False

    def __init__(
        self,
        server_address: tuple[str, int],
        operation_service: ReadOperationService,
        *,
        max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,
        audit_sink: JsonlAuditSink | None = None,
        metrics: LocalReadMetrics | None = None,
    ) -> None:
        host, _port = server_address
        if host != "127.0.0.1":
            raise LocalReadHTTPError("loopback_only_bind_required")
        if operation_service.projection.authorization is None:
            raise LocalReadHTTPError("server_authorization_service_required")
        if not isinstance(max_request_bytes, int) or isinstance(max_request_bytes, bool) or not 1 <= max_request_bytes <= 8 * 1024 * 1024:
            raise LocalReadHTTPError("request_limit_invalid")
        self.operation_service = operation_service
        self.max_request_bytes = max_request_bytes
        self.audit_sink = audit_sink
        self.metrics = metrics or LocalReadMetrics()
        handler = self._handler_type()
        super().__init__(server_address, handler)

    def _handler_type(self) -> type[BaseHTTPRequestHandler]:
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            server_version = "PMIRI-LocalRead/0.1"
            sys_version = ""

            def log_message(self, _format: str, *_args: object) -> None:
                # Request data and authentication references must not reach a
                # default access log. Deployments should attach a redacted,
                # role-controlled audit sink at the gateway boundary.
                return

            def _send(self, status: HTTPStatus, body: Any) -> None:
                encoded = _json_bytes(body)
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(encoded)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(encoded)

            def _audit_rejection(self, operation: str | None, status: HTTPStatus) -> bool:
                if server.audit_sink is None:
                    return True
                try:
                    server.audit_sink.append(ReadAuditEvent.rejected(operation=operation, status_code=int(status)))
                except Exception:
                    server.metrics.increment("audit_write_failures_total")
                    return False
                return True

            def _reject(self, status: HTTPStatus = HTTPStatus.BAD_REQUEST, *, operation: str | None = None) -> None:
                server.metrics.increment("http_requests_rejected_total")
                if not self._audit_rejection(operation, status):
                    status = HTTPStatus.SERVICE_UNAVAILABLE
                self._send(status, {"error": {"code": "REQUEST_REJECTED"}})

            def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
                server.metrics.increment("http_requests_total")
                parsed = urlsplit(self.path)
                if parsed.path == "/healthz" and not parsed.query:
                    self._send(HTTPStatus.OK, {"status": "OK", "transport": "LOOPBACK_ONLY"})
                    return
                if parsed.path == "/metrics" and not parsed.query:
                    self._send(HTTPStatus.OK, server.metrics.snapshot())
                    return
                self._reject(HTTPStatus.NOT_FOUND)

            def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
                server.metrics.increment("http_requests_total")
                parsed = urlsplit(self.path)
                prefix = "/v1/read/"
                if parsed.query or not parsed.path.startswith(prefix):
                    self._reject(HTTPStatus.NOT_FOUND)
                    return
                operation = parsed.path[len(prefix):]
                if operation not in READ_OPERATIONS or "/" in operation:
                    self._reject(HTTPStatus.NOT_FOUND, operation=operation)
                    return
                if self.headers.get("Content-Type", "").split(";", 1)[0].strip().casefold() != "application/json":
                    self._reject(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, operation=operation)
                    return
                try:
                    content_length = int(self.headers.get("Content-Length", "-1"))
                except ValueError:
                    content_length = -1
                if content_length < 0 or content_length > server.max_request_bytes:
                    self._reject(HTTPStatus.REQUEST_ENTITY_TOO_LARGE if content_length > server.max_request_bytes else HTTPStatus.LENGTH_REQUIRED, operation=operation)
                    return
                try:
                    raw = json.loads(self.rfile.read(content_length).decode("utf-8"))
                    if not isinstance(raw, dict):
                        raise ValueError("request_object_required")
                    authentication_ref = self.headers.get(AUTHENTICATION_HEADER)
                    if not authentication_ref:
                        self._reject(HTTPStatus.UNAUTHORIZED, operation=operation)
                        return
                    response = server.operation_service.api_authenticated(
                        operation,
                        raw,
                        authentication_ref=authentication_ref,
                    )
                except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
                    self._reject(HTTPStatus.BAD_REQUEST, operation=operation)
                    return
                except Exception:
                    # Internal authorization/runtime details must not cross
                    # the HTTP boundary.
                    self._reject(HTTPStatus.INTERNAL_SERVER_ERROR, operation=operation)
                    return
                if server.audit_sink is not None:
                    try:
                        fence = response.get("emission_fence", {})
                        server.audit_sink.append(
                            ReadAuditEvent.emitted(
                                operation=operation,
                                projection_fingerprint=fence.get("projection_fingerprint"),
                                typed_result_fingerprint=fence.get("typed_result_fingerprint"),
                            )
                        )
                    except Exception:
                        server.metrics.increment("audit_write_failures_total")
                        server.metrics.increment("http_requests_rejected_total")
                        self._send(HTTPStatus.SERVICE_UNAVAILABLE, {"error": {"code": "REQUEST_REJECTED"}})
                        return
                server.metrics.increment("http_requests_emitted_total")
                self._send(HTTPStatus.OK, response)

        return Handler


__all__ = ["AUTHENTICATION_HEADER", "DEFAULT_MAX_REQUEST_BYTES", "LocalReadHTTPError", "LocalReadHTTPServer", "LocalReadMetrics"]
