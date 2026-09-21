"""Universal external-read operation registry and final response fence.

The Gate-C contract names seven read operations, but it does not assign them
different local storage semantics. This module keeps the semantic handler
shared while binding the operation name into a typed result, the continuation
scope and a final disclosure/emission fence. Transport adapters may not add an
eighth operation or override the typed result with presentation text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .canonical import sha256_json
from .disclosure import disclosure_fingerprint
from .read_projection import ReadProjectionService, semantic_projection


READ_OPERATIONS = (
    "search",
    "fetch_evidence",
    "resolve_current_state",
    "retrieve_history",
    "timeline",
    "explain",
    "status",
)


class ExternalReadEmissionError(ValueError):
    """Raised when a projected read response no longer matches its fence."""


@dataclass(frozen=True)
class ExternalReadEmissionFence:
    """Immutable final fence for one typed API/MCP read response."""

    operation: str
    projection_fingerprint: str
    typed_result_fingerprint: str
    status: str = "EMIT_VALID"

    @classmethod
    def create(cls, operation: str, projection: Mapping[str, Any], typed_result: Mapping[str, Any]) -> "ExternalReadEmissionFence":
        if operation not in READ_OPERATIONS:
            raise ExternalReadEmissionError("read_operation_unknown")
        return cls(
            operation=operation,
            projection_fingerprint=disclosure_fingerprint(projection),
            typed_result_fingerprint=sha256_json(dict(typed_result)),
        )

    def structured(self) -> dict[str, Any]:
        return {
            "record_type": "PMIRI_EXTERNAL_READ_EMISSION_FENCE",
            "schema_version": "0.1",
            "operation": self.operation,
            "projection_fingerprint": self.projection_fingerprint,
            "typed_result_fingerprint": self.typed_result_fingerprint,
            "status": self.status,
        }

    def assert_valid(self, envelope: Mapping[str, Any]) -> None:
        if self.status != "EMIT_VALID":
            raise ExternalReadEmissionError("read_emission_not_valid")
        if envelope.get("operation") != self.operation:
            raise ExternalReadEmissionError("read_operation_binding_mismatch")
        projection = envelope.get("projection")
        typed_result = envelope.get("typed_result")
        if not isinstance(projection, Mapping) or not isinstance(typed_result, Mapping):
            raise ExternalReadEmissionError("read_emission_shape_invalid")
        if disclosure_fingerprint(projection) != self.projection_fingerprint:
            raise ExternalReadEmissionError("read_projection_fingerprint_mismatch")
        if sha256_json(dict(typed_result)) != self.typed_result_fingerprint:
            raise ExternalReadEmissionError("read_typed_result_fingerprint_mismatch")
        if typed_result.get("operation") != self.operation:
            raise ExternalReadEmissionError("read_typed_result_operation_mismatch")
        result = projection.get("result")
        lineage = projection.get("lineage")
        if not isinstance(result, Mapping) or not isinstance(lineage, Mapping):
            raise ExternalReadEmissionError("read_projection_authority_shape_invalid")
        if typed_result.get("projection_fingerprint") != self.projection_fingerprint:
            raise ExternalReadEmissionError("read_typed_result_projection_binding_mismatch")
        if typed_result.get("disposition") != result.get("disposition"):
            raise ExternalReadEmissionError("read_typed_result_not_authoritative")
        if typed_result.get("coverage") != result.get("coverage"):
            raise ExternalReadEmissionError("read_typed_result_coverage_mismatch")
        if typed_result.get("authorization_ref") != lineage.get("authorization_ref"):
            raise ExternalReadEmissionError("read_typed_result_authorization_mismatch")
        if typed_result.get("evidence_refs") != list(lineage.get("evidence_refs", [])):
            raise ExternalReadEmissionError("read_typed_result_evidence_mismatch")


def _strip_transport_operation(operation: str, raw: Mapping[str, object]) -> dict[str, object]:
    if operation not in READ_OPERATIONS:
        raise ExternalReadEmissionError("read_operation_unknown")
    if not isinstance(raw, Mapping):
        raise ExternalReadEmissionError("read_request_must_be_object")
    supplied = raw.get("operation")
    if supplied is not None and supplied != operation:
        raise ExternalReadEmissionError("read_operation_substitution")
    return {key: value for key, value in raw.items() if key != "operation"}


def _operation_cursor(operation: str, projection: Mapping[str, Any]) -> str:
    """Derive a continuation token bound to both the read operation and request."""
    lineage = projection.get("lineage")
    base_cursor = projection.get("continuation")
    if not isinstance(lineage, Mapping) or not isinstance(base_cursor, str):
        raise ExternalReadEmissionError("read_continuation_binding_missing")
    return "cursor_" + sha256_json(
        {
            "operation": operation,
            "request_fingerprint": lineage.get("request_fingerprint"),
            "base_continuation": base_cursor,
        }
    )


class ReadOperationService:
    """Expose every declared read operation through one projection handler."""

    def __init__(self, projection: ReadProjectionService):
        self.projection = projection

    def _execute(
        self,
        operation: str,
        raw: Mapping[str, object],
        *,
        adapter: str,
        authorized: bool | None = None,
        authentication_ref: str | None = None,
        now: str | None = None,
    ) -> dict[str, Any]:
        payload = _strip_transport_operation(operation, raw)
        if self.projection.authorization is not None:
            if authorized is not None:
                raise ExternalReadEmissionError("caller_authorization_flag_not_authority")
            if adapter == "api":
                projection = self.projection.api_authenticated(payload, authentication_ref=authentication_ref, now=now)
            elif adapter == "mcp":
                projection = self.projection.mcp_authenticated(payload, authentication_ref=authentication_ref, now=now)
            else:
                raise ExternalReadEmissionError("read_adapter_unknown")
        elif authentication_ref is not None:
            raise ExternalReadEmissionError("authorization_service_required")
        elif adapter == "api":
            projection = self.projection.api(payload) if authorized is None else self.projection.api_disclosed(payload, authorized=authorized)
        elif adapter == "mcp":
            projection = self.projection.mcp(payload) if authorized is None else self.projection.mcp_disclosed(payload, authorized=authorized)
        else:
            raise ExternalReadEmissionError("read_adapter_unknown")
        expected_cursor = _operation_cursor(operation, projection)
        supplied_cursor = payload.get("cursor")
        if supplied_cursor is not None and supplied_cursor != expected_cursor:
            raise ExternalReadEmissionError("read_cursor_binding_mismatch")
        # The projection handler's cursor is transport-neutral, but the
        # externally visible cursor is additionally bound to this operation.
        projection = {**projection, "continuation": expected_cursor}
        typed_result = {
            "record_type": "PMIRI_EXTERNAL_READ_TYPED_RESULT",
            "schema_version": "0.1",
            "operation": operation,
            "disposition": projection["result"]["disposition"],
            "coverage": projection["result"]["coverage"],
            "authorization_ref": projection["lineage"].get("authorization_ref"),
            "evidence_refs": list(projection["lineage"].get("evidence_refs", [])),
            "projection_fingerprint": disclosure_fingerprint(projection),
        }
        envelope = {"operation": operation, "projection": projection, "typed_result": typed_result}
        fence = ExternalReadEmissionFence.create(operation, projection, typed_result)
        fence.assert_valid(envelope)
        return {**envelope, "emission_fence": fence.structured()}

    def api(self, operation: str, raw: Mapping[str, object], *, authorized: bool | None = None) -> dict[str, Any]:
        return self._execute(operation, raw, adapter="api", authorized=authorized)

    def mcp(self, operation: str, raw: Mapping[str, object], *, authorized: bool | None = None) -> dict[str, Any]:
        return self._execute(operation, raw, adapter="mcp", authorized=authorized)

    def api_authenticated(self, operation: str, raw: Mapping[str, object], *, authentication_ref: str | None, now: str | None = None) -> dict[str, Any]:
        return self._execute(operation, raw, adapter="api", authentication_ref=authentication_ref, now=now)

    def mcp_authenticated(self, operation: str, raw: Mapping[str, object], *, authentication_ref: str | None, now: str | None = None) -> dict[str, Any]:
        return self._execute(operation, raw, adapter="mcp", authentication_ref=authentication_ref, now=now)


def operation_parity_fingerprint(api_response: Mapping[str, Any], mcp_response: Mapping[str, Any]) -> tuple[bool, str, str]:
    """Compare operation, typed result and projected semantic content."""
    api_projection = api_response.get("projection")
    mcp_projection = mcp_response.get("projection")
    if not isinstance(api_projection, Mapping) or not isinstance(mcp_projection, Mapping):
        raise ExternalReadEmissionError("read_projection_missing")
    api_value = {
        "operation": api_response.get("operation"),
        "projection": semantic_projection(api_projection),
        "typed_result": api_response.get("typed_result"),
    }
    mcp_value = {
        "operation": mcp_response.get("operation"),
        "projection": semantic_projection(mcp_projection),
        "typed_result": mcp_response.get("typed_result"),
    }
    api_fingerprint = sha256_json(api_value)
    mcp_fingerprint = sha256_json(mcp_value)
    return api_fingerprint == mcp_fingerprint, api_fingerprint, mcp_fingerprint


__all__ = [
    "ExternalReadEmissionError",
    "ExternalReadEmissionFence",
    "READ_OPERATIONS",
    "ReadOperationService",
    "operation_parity_fingerprint",
]
