"""Protocol-neutral read projection for API/MCP parity.

Both transport facades call the same server-side handler.  Client-provided
authorization references, cursors or adapter labels are never used to widen
the request.  The returned continuation token is a stateless fingerprint, not
an authority-bearing session handle.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .canonical import is_sha256, sha256_json
from .disclosure import project_query_result
from .models import QueryRequest
from .request_auth import RequestAuthorizationService
from .runtime import LocalEvidenceRuntime


PROJECTION_VERSION = "0.1"


@dataclass(frozen=True)
class ProjectionRequest:
    request_id: str
    project_constraint: str
    query: str
    purpose: str = "local_read"
    max_results: int = 20
    client_authorization_ref: str | None = None
    client_cursor: str | None = None

    @classmethod
    def from_mapping(cls, raw: Mapping[str, object]) -> "ProjectionRequest":
        if not isinstance(raw, Mapping):
            raise ValueError("projection_request_must_be_object")
        allowed = {"request_id", "project_constraint", "query", "purpose", "max_results", "authorization_ref", "cursor"}
        if set(raw) - allowed:
            raise ValueError("projection_request_field_not_allowed")
        values = {
            "request_id": raw.get("request_id"),
            "project_constraint": raw.get("project_constraint"),
            "query": raw.get("query"),
            "purpose": raw.get("purpose", "local_read"),
            "max_results": raw.get("max_results", 20),
            "client_authorization_ref": raw.get("authorization_ref"),
            "client_cursor": raw.get("cursor"),
        }
        if not all(isinstance(values[key], str) for key in ("request_id", "project_constraint", "query", "purpose")):
            raise ValueError("projection_request_types_invalid")
        if values["client_authorization_ref"] is not None and not isinstance(values["client_authorization_ref"], str):
            raise ValueError("projection_authorization_ref_invalid")
        if values["client_cursor"] is not None and not isinstance(values["client_cursor"], str):
            raise ValueError("projection_cursor_invalid")
        if not isinstance(values["max_results"], int) or isinstance(values["max_results"], bool):
            raise ValueError("projection_max_results_invalid")
        request = cls(**values)
        request.query_request().normalized()
        if request.client_cursor is not None and (
            len(request.client_cursor) != 71
            or not request.client_cursor.startswith("cursor_")
            or not is_sha256(request.client_cursor[7:])
        ):
            # Cursors are opaque, but a malformed token is still rejected.
            raise ValueError("projection_cursor_invalid")
        return request

    def query_request(self) -> QueryRequest:
        return QueryRequest(self.request_id, self.project_constraint, self.query, self.purpose, self.max_results)


def _server_binding(request: QueryRequest) -> dict[str, str]:
    normalized = request.normalized()
    request_fingerprint = sha256_json(normalized)
    return {
        "authorization_ref": "auth_" + sha256_json({"request_fingerprint": request_fingerprint, "scope": "server-derived-local-read"})[:32],
        "request_fingerprint": request_fingerprint,
        "scope": request.project_constraint,
    }


class ReadProjectionService:
    """Shared semantic handler for protocol-neutral API and MCP adapters."""

    def __init__(self, runtime: LocalEvidenceRuntime, authorization: RequestAuthorizationService | None = None):
        self.runtime = runtime
        self.authorization = authorization

    def _handle(self, raw: Mapping[str, object]) -> dict[str, Any]:
        projection = ProjectionRequest.from_mapping(raw)
        request = projection.query_request()
        binding = _server_binding(request)
        result = self.runtime.query(request).structured()
        # The server binding is authoritative; transport-supplied values are
        # deliberately excluded from this semantic output.
        continuation = "cursor_" + sha256_json({"binding": binding, "evidence": result["lineage"]["evidence_refs"]})
        return {
            "projection_version": PROJECTION_VERSION,
            "request": result["request"],
            "result": result["result"],
            "evidence": result["evidence"],
            "lineage": {**result["lineage"], **binding},
            "context": result["context"],
            "continuation": continuation,
        }

    def _handle_disclosed(
        self,
        raw: Mapping[str, object],
        *,
        authorized: bool,
        server_binding: Mapping[str, str] | None = None,
        revalidate: Callable[[QueryRequest], bool] | None = None,
    ) -> dict[str, Any]:
        projection = ProjectionRequest.from_mapping(raw)
        request = projection.query_request()
        binding = dict(server_binding or _server_binding(request))
        runtime_result = self.runtime.query(request)
        if authorized and revalidate is not None and not revalidate(request):
            authorized = False
        result = project_query_result(runtime_result, authorized=authorized)
        continuation = "cursor_" + sha256_json({"binding": binding, "evidence": result["lineage"]["evidence_refs"]})
        result["lineage"] = {**result["lineage"], **binding}
        result["continuation"] = continuation
        return result

    def _handle_authenticated(
        self,
        raw: Mapping[str, object],
        *,
        authentication_ref: str | None,
        now: str | None,
    ) -> dict[str, Any]:
        if self.authorization is None:
            raise ValueError("authorization_service_required")
        projection = ProjectionRequest.from_mapping(raw)
        evaluation = self.authorization.evaluate(
            projection.query_request(),
            authentication_ref=authentication_ref,
            now=now,
        )
        # A denied request follows the same runtime and disclosure shape.  The
        # only binding returned to the caller is a neutral server-derived one;
        # principal, zone and denial reasons never cross this boundary.
        public_binding = evaluation.binding.public_lineage() if evaluation.binding is not None else None
        return self._handle_disclosed(
            raw,
            authorized=evaluation.allowed,
            server_binding=public_binding,
            revalidate=(
                (lambda request: self.authorization.revalidate(request, evaluation.binding, now=now))
                if evaluation.binding is not None
                else None
            ),
        )

    def api(self, raw: Mapping[str, object]) -> dict[str, Any]:
        if self.authorization is not None:
            raise ValueError("authenticated_adapter_required")
        return self._handle(raw)

    def mcp(self, raw: Mapping[str, object]) -> dict[str, Any]:
        if self.authorization is not None:
            raise ValueError("authenticated_adapter_required")
        return self._handle(raw)

    def api_disclosed(self, raw: Mapping[str, object], *, authorized: bool) -> dict[str, Any]:
        if self.authorization is not None:
            raise ValueError("caller_authorization_flag_not_authority")
        return self._handle_disclosed(raw, authorized=authorized)

    def mcp_disclosed(self, raw: Mapping[str, object], *, authorized: bool) -> dict[str, Any]:
        if self.authorization is not None:
            raise ValueError("caller_authorization_flag_not_authority")
        return self._handle_disclosed(raw, authorized=authorized)

    def api_authenticated(
        self,
        raw: Mapping[str, object],
        *,
        authentication_ref: str | None,
        now: str | None = None,
    ) -> dict[str, Any]:
        return self._handle_authenticated(raw, authentication_ref=authentication_ref, now=now)

    def mcp_authenticated(
        self,
        raw: Mapping[str, object],
        *,
        authentication_ref: str | None,
        now: str | None = None,
    ) -> dict[str, Any]:
        return self._handle_authenticated(raw, authentication_ref=authentication_ref, now=now)


def semantic_projection(response: Mapping[str, Any]) -> dict[str, Any]:
    """Remove transport-neutral continuation metadata for parity comparison."""
    return {
        "projection_version": response.get("projection_version", response.get("disclosure_version")),
        "request": response["request"],
        "result": response["result"],
        "evidence": response["evidence"],
        "lineage": response["lineage"],
        "context": response["context"],
        "continuation": response["continuation"],
    }


def parity_fingerprint(api_response: Mapping[str, Any], mcp_response: Mapping[str, Any]) -> tuple[bool, str, str]:
    """Compare canonical API/MCP semantics, returning both fingerprints."""
    api_fingerprint = sha256_json(semantic_projection(api_response))
    mcp_fingerprint = sha256_json(semantic_projection(mcp_response))
    return api_fingerprint == mcp_fingerprint, api_fingerprint, mcp_fingerprint


__all__ = ["PROJECTION_VERSION", "ProjectionRequest", "ReadProjectionService", "parity_fingerprint", "semantic_projection"]
