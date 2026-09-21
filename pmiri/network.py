"""Gate-D network boundary: canonicalize safely, never fetch by default."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit

from .canonical import is_sha256, sha256_json


class NetworkBoundaryError(ValueError):
    pass


CANONICALIZATION_PROFILE_ID = "D2-NETWORK-CANONICALIZATION-001"
CANONICALIZATION_PROFILE_FINGERPRINT = "04a8c5d312d2c17967cd90c874e8bcf779324349c043d0c53a6c828a260e3bbd"


@dataclass(frozen=True)
class ResourceLimits:
    max_redirect_hops: int = 5
    max_response_bytes: int = 10 * 1024 * 1024
    max_decompressed_bytes: int = 50 * 1024 * 1024
    max_compression_ratio: int = 100
    max_header_bytes: int = 65536
    max_url_length: int = 8192
    connect_timeout_ms: int = 5000
    read_timeout_ms: int = 15000
    total_timeout_ms: int = 30000
    max_concurrent_fetches: int = 8

    def fingerprint(self) -> str:
        return sha256_json(self.__dict__)


@dataclass(frozen=True)
class NormalizedTarget:
    scheme: str
    host: str
    port: int
    path: str
    query: str | None
    fingerprint: str

    @property
    def authority(self) -> str:
        return "[" + self.host + "]" if ":" in self.host and not self.host.startswith("[") else self.host

    def request_target(self) -> str:
        """Return the exact canonical origin-form path/query binding."""
        return self.path + (f"?{self.query}" if self.query is not None else "")

    def safe_url(self) -> str:
        return f"{self.scheme.lower()}://{self.authority}{self.request_target()}"


@dataclass(frozen=True)
class NetworkDecision:
    operation: str
    action_result: str
    reason_class: str
    normalized_target: NormalizedTarget | None = None
    resolution_set_status: str = "DENIED_MIXED"
    connection_binding_status: str = "DENIED"

    def public_dict(self) -> dict:
        return {
            "operation": self.operation,
            "action_result": self.action_result,
            "reason_class": self.reason_class,
            "normalized_target": self.normalized_target.safe_url() if self.normalized_target else None,
            "resolution_set_status": self.resolution_set_status,
            "connection_binding_status": self.connection_binding_status,
        }


def build_connection_binding(
    *,
    endpoint: str,
    addresses: list[str],
    observed_at: str,
    connection_epoch: int,
    invalidation_epoch: int,
    tls_identity_status: str = "MATCHED",
    final_revalidation_result: str = "MATCHED",
    resolver_ref: str = "resolver://supplied-observation",
    destination_identity_ref: str | None = None,
    proxy_mode: str = "DIRECT",
    proxy_identity_ref: str | None = None,
    execution_enabled: bool = True,
) -> dict:
    """Build a schema-shaped connection binding from supplied observations."""
    target = normalize_url(endpoint)
    destination_identity_ref = destination_identity_ref or "destination://" + target.authority
    if not isinstance(addresses, list) or not all(isinstance(address, str) for address in addresses):
        raise NetworkBoundaryError("RESOLUTION_SET_INVALID")
    entries = []
    for index, address in enumerate(addresses):
        try:
            parsed = ipaddress.ip_address(address)
            normalized_ip = str(parsed)
            family = "IPv6" if parsed.version == 6 else "IPv4"
            policy_status = classify_address(normalized_ip)
        except ValueError:
            # An invalid resolver answer is evidence of an unapproved
            # resolution set, not a reason to turn a fail-closed decision into
            # an uncaught exception.
            normalized_ip = address
            family = "IPv4"
            policy_status = "DENIED_UNALLOWLISTED"
        entries.append(
            {
                "resolution_entry_id": f"resolution://{target.fingerprint[:24]}/{index}",
                "ip": normalized_ip,
                "family": family,
                "policy_status": policy_status,
                "observed_at": observed_at,
                "allowlist_ref": "allowlist://public-addresses",
            }
        )
    all_public = bool(entries) and all(entry["policy_status"] == "ALLOWLISTED_PUBLIC" for entry in entries)
    resolution_set_status = "ALL_ALLOWLISTED_PUBLIC" if all_public else "DENIED_MIXED"
    selected = (
        {
            "resolution_entry_ref": entries[0]["resolution_entry_id"],
            "ip": entries[0]["ip"],
            "family": entries[0]["family"],
            "policy_status": entries[0]["policy_status"],
        }
        if all_public else None
    )
    if proxy_mode not in {"DIRECT", "EXPLICIT_PROXY", "DENY"}:
        raise NetworkBoundaryError("PROXY_MODE_INVALID")
    if proxy_mode == "EXPLICIT_PROXY" and not proxy_identity_ref:
        raise NetworkBoundaryError("PROXY_IDENTITY_MISSING")
    if proxy_mode != "EXPLICIT_PROXY" and proxy_identity_ref is not None:
        raise NetworkBoundaryError("PROXY_IDENTITY_FORBIDDEN")
    if not isinstance(connection_epoch, int) or connection_epoch < 0 or not isinstance(invalidation_epoch, int) or invalidation_epoch < 0:
        raise NetworkBoundaryError("CONNECTION_EPOCH_INVALID")
    if tls_identity_status not in {"MATCHED", "MISMATCHED"} or final_revalidation_result not in {"MATCHED", "MISMATCHED", "DENIED"}:
        raise NetworkBoundaryError("REVALIDATION_RESULT_INVALID")
    if resolution_set_status != "ALL_ALLOWLISTED_PUBLIC":
        binding_status = "DENIED"
        event_result = "DENIED"
    elif tls_identity_status != "MATCHED":
        binding_status = "DENIED"
        event_result = "MISMATCHED"
    elif final_revalidation_result != "MATCHED":
        binding_status = "STALE"
        event_result = "MISMATCHED"
    elif not execution_enabled:
        binding_status = "DENIED"
        event_result = "DENIED"
    else:
        binding_status = "VALIDATED"
        event_result = "MATCHED"
    record = {
        "record_type": "PMIRI_D2_CONNECTION_BINDING",
        "schema_version": "0.3",
        "connection_binding_id": "connection://" + target.fingerprint[:32],
        "destination_identity_ref": destination_identity_ref,
        "canonicalization_profile_id": CANONICALIZATION_PROFILE_ID,
        "canonicalization_profile_fingerprint": CANONICALIZATION_PROFILE_FINGERPRINT,
        "normalized_authority": target.authority,
        "resolver_ref": resolver_ref,
        "resolved_addresses": entries,
        "resolution_set_status": resolution_set_status,
        "selected_target": selected,
        "proxy": {"mode": proxy_mode, **({"proxy_identity_ref": proxy_identity_ref} if proxy_identity_ref else {})},
        "tls": {
            "scheme": "HTTPS",
            "sni": target.host,
            "certificate_fingerprint": sha256_json({"authority": target.authority, "tls": tls_identity_status}),
            "identity_status": tls_identity_status,
            "expected_identity_ref": destination_identity_ref,
            "verified_identity_ref": destination_identity_ref if tls_identity_status == "MATCHED" else "identity://mismatch",
            "identity_binding_fingerprint": sha256_json({"authority": target.authority, "status": tls_identity_status}),
        },
        "revalidation_events": [{
            "sequence": 0,
            "event_type": "INITIAL_RESOLUTION",
            "observed_at": observed_at,
            "result": event_result,
            "prior_connection_epoch": connection_epoch,
            "connection_epoch": connection_epoch,
            "prior_invalidation_epoch": invalidation_epoch,
            "invalidation_epoch": invalidation_epoch,
            "reason_class": "NONE" if event_result == "MATCHED" else "EXACT_BINDING_MISSING",
        }],
        "connection_epoch": connection_epoch,
        "invalidation_epoch": invalidation_epoch,
        "binding_status": binding_status,
    }
    record["binding_fingerprint"] = sha256_json(record)
    validate_connection_binding(record)
    return record


def validate_connection_binding(record: dict) -> None:
    """Recompute the security-relevant fields of a connection binding."""
    required = (
        "record_type", "schema_version", "connection_binding_id", "destination_identity_ref",
        "canonicalization_profile_id", "canonicalization_profile_fingerprint", "normalized_authority",
        "resolver_ref", "resolved_addresses", "resolution_set_status", "selected_target", "proxy", "tls",
        "revalidation_events", "connection_epoch", "invalidation_epoch", "binding_status", "binding_fingerprint",
    )
    if any(field not in record for field in required):
        raise NetworkBoundaryError("CONNECTION_BINDING_FIELD_MISSING")
    if record["record_type"] != "PMIRI_D2_CONNECTION_BINDING" or record["schema_version"] != "0.3":
        raise NetworkBoundaryError("CONNECTION_BINDING_SCHEMA_INVALID")
    if set(record) != set(required) or not isinstance(record["destination_identity_ref"], str) or not record["destination_identity_ref"]:
        raise NetworkBoundaryError("CONNECTION_BINDING_FIELD_SET_INVALID")
    if record["canonicalization_profile_id"] != CANONICALIZATION_PROFILE_ID or record["canonicalization_profile_fingerprint"] != CANONICALIZATION_PROFILE_FINGERPRINT:
        raise NetworkBoundaryError("CANONICALIZATION_PROFILE_MISMATCH")
    if not is_sha256(record["binding_fingerprint"]) or record["binding_fingerprint"] != sha256_json({key: value for key, value in record.items() if key != "binding_fingerprint"}):
        raise NetworkBoundaryError("CONNECTION_BINDING_FINGERPRINT_INVALID")
    if record["resolution_set_status"] not in {"ALL_ALLOWLISTED_PUBLIC", "DENIED_MIXED"}:
        raise NetworkBoundaryError("CONNECTION_RESOLUTION_SET_INVALID")
    if record["binding_status"] not in {"VALIDATED", "DENIED", "STALE"}:
        raise NetworkBoundaryError("CONNECTION_BINDING_STATUS_INVALID")
    if any(not isinstance(record[field], int) or isinstance(record[field], bool) or record[field] < 0 for field in ("connection_epoch", "invalidation_epoch")):
        raise NetworkBoundaryError("CONNECTION_EPOCH_INVALID")
    addresses = record["resolved_addresses"]
    if not isinstance(addresses, list) or not addresses:
        raise NetworkBoundaryError("CONNECTION_RESOLUTION_EMPTY")
    statuses = []
    for entry in addresses:
        if not isinstance(entry, dict) or not all(key in entry for key in ("resolution_entry_id", "ip", "family", "policy_status", "observed_at", "allowlist_ref")):
            raise NetworkBoundaryError("CONNECTION_RESOLUTION_ENTRY_INVALID")
        if set(entry) != {"resolution_entry_id", "ip", "family", "policy_status", "observed_at", "allowlist_ref"}:
            raise NetworkBoundaryError("CONNECTION_RESOLUTION_ENTRY_FIELD_SET_INVALID")
        try:
            parsed = ipaddress.ip_address(entry["ip"])
        except ValueError:
            if entry["policy_status"] != "DENIED_UNALLOWLISTED" or entry["family"] != "IPv4":
                raise NetworkBoundaryError("CONNECTION_RESOLUTION_ENTRY_MISMATCH")
        else:
            expected_family = "IPv6" if parsed.version == 6 else "IPv4"
            if entry["ip"] != str(parsed) or entry["family"] != expected_family or entry["policy_status"] != classify_address(entry["ip"]):
                raise NetworkBoundaryError("CONNECTION_RESOLUTION_ENTRY_MISMATCH")
        statuses.append(entry["policy_status"])
    expected_set_status = "ALL_ALLOWLISTED_PUBLIC" if all(status == "ALLOWLISTED_PUBLIC" for status in statuses) else "DENIED_MIXED"
    if record["resolution_set_status"] != expected_set_status:
        raise NetworkBoundaryError("CONNECTION_RESOLUTION_SET_MISMATCH")
    selected = record["selected_target"]
    if expected_set_status == "ALL_ALLOWLISTED_PUBLIC":
        if not isinstance(selected, dict) or selected.get("resolution_entry_ref") not in {entry["resolution_entry_id"] for entry in addresses}:
            raise NetworkBoundaryError("CONNECTION_SELECTED_TARGET_MISSING")
        selected_entry = next(entry for entry in addresses if entry["resolution_entry_id"] == selected["resolution_entry_ref"])
        if any(selected.get(key) != selected_entry.get(source_key) for key, source_key in (("ip", "ip"), ("family", "family"), ("policy_status", "policy_status"))):
            raise NetworkBoundaryError("CONNECTION_SELECTED_TARGET_MISMATCH")
    elif selected is not None:
        if not isinstance(selected, dict) or set(selected) != {"resolution_entry_ref", "ip", "family", "policy_status"} or selected.get("policy_status") != "ALLOWLISTED_PUBLIC":
            raise NetworkBoundaryError("CONNECTION_DENIED_SELECTION_INVALID")
        if all(status != "ALLOWLISTED_PUBLIC" for status in statuses):
            raise NetworkBoundaryError("CONNECTION_DENIED_SELECTION_INVALID")
    proxy = record["proxy"]
    if not isinstance(proxy, dict) or proxy.get("mode") not in {"DIRECT", "EXPLICIT_PROXY", "DENY"}:
        raise NetworkBoundaryError("CONNECTION_PROXY_INVALID")
    if proxy["mode"] == "EXPLICIT_PROXY" and not proxy.get("proxy_identity_ref"):
        raise NetworkBoundaryError("CONNECTION_PROXY_IDENTITY_MISSING")
    if proxy["mode"] != "EXPLICIT_PROXY" and "proxy_identity_ref" in proxy:
        raise NetworkBoundaryError("CONNECTION_PROXY_IDENTITY_FORBIDDEN")
    if set(proxy) - {"mode", "proxy_identity_ref"}:
        raise NetworkBoundaryError("CONNECTION_PROXY_FIELD_SET_INVALID")
    tls = record["tls"]
    tls_required = {"scheme", "sni", "certificate_fingerprint", "identity_status", "expected_identity_ref", "verified_identity_ref", "identity_binding_fingerprint"}
    if not isinstance(tls, dict) or set(tls) != tls_required or tls.get("scheme") != "HTTPS" or tls.get("identity_status") not in {"MATCHED", "MISMATCHED"}:
        raise NetworkBoundaryError("CONNECTION_TLS_INVALID")
    expected_sni = record["normalized_authority"][1:-1] if record["normalized_authority"].startswith("[") and record["normalized_authority"].endswith("]") else record["normalized_authority"]
    if tls.get("sni") != expected_sni or tls.get("expected_identity_ref") != record["destination_identity_ref"]:
        raise NetworkBoundaryError("CONNECTION_TLS_IDENTITY_BINDING_INVALID")
    if tls.get("certificate_fingerprint") != sha256_json({"authority": record["normalized_authority"], "tls": tls["identity_status"]}):
        raise NetworkBoundaryError("CONNECTION_TLS_CERTIFICATE_FINGERPRINT_INVALID")
    if tls.get("identity_binding_fingerprint") != sha256_json({"authority": record["normalized_authority"], "status": tls["identity_status"]}):
        raise NetworkBoundaryError("CONNECTION_TLS_FINGERPRINT_INVALID")
    if tls["identity_status"] == "MATCHED" and tls.get("verified_identity_ref") != tls.get("expected_identity_ref"):
        raise NetworkBoundaryError("CONNECTION_TLS_VERIFIED_IDENTITY_INVALID")
    if tls["identity_status"] == "MISMATCHED" and tls.get("verified_identity_ref") == tls.get("expected_identity_ref"):
        raise NetworkBoundaryError("CONNECTION_TLS_MISMATCH_NOT_PROVEN")
    events = record["revalidation_events"]
    if not isinstance(events, list) or not events:
        raise NetworkBoundaryError("CONNECTION_REVALIDATION_EMPTY")
    previous_time = None
    for index, event in enumerate(events):
        event_required = {"sequence", "event_type", "observed_at", "result", "prior_connection_epoch", "connection_epoch", "prior_invalidation_epoch", "invalidation_epoch"}
        if not isinstance(event, dict) or set(event) - (event_required | {"reason_class"}) or not event_required.issubset(event):
            raise NetworkBoundaryError("CONNECTION_REVALIDATION_EVENT_INVALID")
        if "reason_class" in event and event["reason_class"] not in {"NONE", "EXACT_BINDING_MISSING"}:
            raise NetworkBoundaryError("CONNECTION_REVALIDATION_REASON_INVALID")
        if event.get("sequence") != index:
            raise NetworkBoundaryError("CONNECTION_REVALIDATION_SEQUENCE_INVALID")
        if index == 0 and event.get("event_type") != "INITIAL_RESOLUTION":
            raise NetworkBoundaryError("CONNECTION_INITIAL_EVENT_INVALID")
        if previous_time is not None and event.get("observed_at") < previous_time:
            raise NetworkBoundaryError("CONNECTION_REVALIDATION_TIME_INVALID")
        previous_time = event.get("observed_at")
        if event.get("event_type") == "INITIAL_RESOLUTION":
            if event.get("prior_connection_epoch") != event.get("connection_epoch") or event.get("prior_invalidation_epoch") != event.get("invalidation_epoch"):
                raise NetworkBoundaryError("CONNECTION_INITIAL_EPOCH_INVALID")
        elif event.get("event_type") == "POLICY_EPOCH_CHANGE":
            if event.get("connection_epoch") != event.get("prior_connection_epoch") or event.get("invalidation_epoch") != event.get("prior_invalidation_epoch", -1) + 1:
                raise NetworkBoundaryError("CONNECTION_POLICY_EPOCH_INVALID")
        elif event.get("connection_epoch") != event.get("prior_connection_epoch", -1) + 1 or event.get("invalidation_epoch") != event.get("prior_invalidation_epoch"):
            raise NetworkBoundaryError("CONNECTION_REVALIDATION_EPOCH_INVALID")
    last = events[-1]
    if record["connection_epoch"] != last.get("connection_epoch") or record["invalidation_epoch"] != last.get("invalidation_epoch"):
        raise NetworkBoundaryError("CONNECTION_FINAL_EPOCH_MISMATCH")
    if record["binding_status"] == "VALIDATED":
        if expected_set_status != "ALL_ALLOWLISTED_PUBLIC" or selected is None or record["tls"].get("identity_status") != "MATCHED" or last.get("result") != "MATCHED":
            raise NetworkBoundaryError("CONNECTION_VALIDATED_STATE_INVALID")


ALLOWED_OPERATIONS = frozenset({"provider_call", "connector_fetch", "attachment_fetch", "external_fetch"})
DENIED_SCHEMES = frozenset({"file", "data", "javascript", "gopher", "ftp"})


_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_HEX = frozenset("0123456789abcdefABCDEF")


def _canonicalize_percent_encoding(value: str) -> str:
    output: list[str] = []
    index = 0
    while index < len(value):
        character = value[index]
        if character != "%":
            output.append(character)
            index += 1
            continue
        if index + 2 >= len(value) or value[index + 1] not in _HEX or value[index + 2] not in _HEX:
            raise NetworkBoundaryError("MALFORMED_PERCENT_ENCODING")
        encoded = value[index + 1:index + 3]
        byte = int(encoded, 16)
        if byte in {0x2F, 0x5C}:
            raise NetworkBoundaryError("ENCODED_DELIMITER_FORBIDDEN")
        decoded = chr(byte)
        output.append(decoded if decoded in _UNRESERVED else "%" + encoded.upper())
        index += 3
    return "".join(output)


def _remove_dot_segments(path: str) -> str:
    """Apply RFC 3986 section 5.2.4 without collapsing repeated slashes."""
    input_buffer = path if path.startswith("/") else "/" + path
    output: list[str] = []
    while input_buffer:
        if input_buffer.startswith("../"):
            input_buffer = input_buffer[3:]
        elif input_buffer.startswith("./"):
            input_buffer = input_buffer[2:]
        elif input_buffer.startswith("/./"):
            input_buffer = input_buffer[2:]
        elif input_buffer == "/.":
            input_buffer = "/"
        elif input_buffer.startswith("/../"):
            input_buffer = input_buffer[3:]
            if output:
                output.pop()
        elif input_buffer == "/..":
            input_buffer = "/"
            if output:
                output.pop()
        elif input_buffer in {".", ".."}:
            input_buffer = ""
        else:
            separator = input_buffer.find("/", 1) if input_buffer.startswith("/") else input_buffer.find("/")
            if separator == -1:
                output.append(input_buffer)
                input_buffer = ""
            else:
                output.append(input_buffer[:separator])
                input_buffer = input_buffer[separator:]
    normalized = "".join(output)
    return normalized if normalized.startswith("/") and normalized else "/"


def normalize_url(url: str) -> NormalizedTarget:
    if not isinstance(url, str) or len(url) > 8192 or any(ord(ch) < 0x20 for ch in url):
        raise NetworkBoundaryError("URL_INVALID")
    try:
        parsed: SplitResult = urlsplit(url)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise NetworkBoundaryError("URL_INVALID") from exc
    if parsed.scheme.casefold() != "https":
        raise NetworkBoundaryError("SCHEME_NOT_ALLOWED")
    if parsed.username is not None or parsed.password is not None:
        raise NetworkBoundaryError("URL_USERINFO_FORBIDDEN")
    if not host or parsed.fragment:
        raise NetworkBoundaryError("URL_AUTHORITY_OR_FRAGMENT_INVALID")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if not host.isascii():
            try:
                import idna  # type: ignore
            except ImportError as exc:
                raise NetworkBoundaryError("IDNA_VALIDATOR_UNAVAILABLE") from exc
            try:
                host_ascii = idna.encode(host, uts46=True, std3_rules=True, transitional=False).decode("ascii").casefold().rstrip(".")
            except (UnicodeError, idna.IDNAError) as exc:
                raise NetworkBoundaryError("HOST_INVALID") from exc
        else:
            host_ascii = host.casefold().rstrip(".")
        labels = host_ascii.split(".")
        if not host_ascii or any(
            not label or len(label) > 63 or label[0] == "-" or label[-1] == "-" or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in label)
            for label in labels
        ):
            raise NetworkBoundaryError("HOST_INVALID")
    else:
        host_ascii = address.compressed
    authority = "[" + host_ascii + "]" if ":" in host_ascii and not host_ascii.startswith("[") else host_ascii
    effective_port = 443 if port is None else port
    if effective_port != 443:
        raise NetworkBoundaryError("PORT_NOT_ALLOWED")
    if "\\" in parsed.path or "\\" in parsed.query:
        raise NetworkBoundaryError("AMBIGUOUS_AUTHORITY")
    path = _remove_dot_segments(_canonicalize_percent_encoding(parsed.path or "/"))
    query = _canonicalize_percent_encoding(parsed.query) if parsed.query != "" else None
    payload = {"scheme": "HTTPS", "authority": authority, "path": path, "query": query}
    return NormalizedTarget("HTTPS", host_ascii, 443, path, query, sha256_json(payload))


def classify_address(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return "INVALID"
    if address.is_private or address.is_loopback or address.is_link_local or address.is_unspecified:
        return "DENIED_PRIVATE"
    if address.is_multicast or address.is_reserved or not address.is_global:
        return "DENIED_RESERVED"
    return "ALLOWLISTED_PUBLIC"


class NetworkBoundary:
    """No network calls are implemented. Every external operation is denied."""

    def evaluate(self, operation: str, url: str) -> NetworkDecision:
        if operation not in ALLOWED_OPERATIONS:
            return NetworkDecision(operation, "DENY", "INTERNAL_CONTRACT_INVALID")
        try:
            target = normalize_url(url)
        except NetworkBoundaryError as exc:
            return NetworkDecision(operation, "DENY", str(exc))
        return NetworkDecision(operation, "DENY", "OUTBOUND_NETWORK_DISABLED", normalized_target=target)

    def fetch(self, operation: str, url: str) -> bytes:
        decision = self.evaluate(operation, url)
        raise NetworkBoundaryError(f"{decision.reason_class}: external fetch is not authorized in S0")

    @staticmethod
    def validate_redirects(urls: list[str], *, max_hops: int = 5) -> tuple[NormalizedTarget, ...]:
        if len(urls) > max_hops + 1 or len(set(urls)) != len(urls):
            raise NetworkBoundaryError("REDIRECT_UNAUTHORIZED")
        targets = tuple(normalize_url(url) for url in urls)
        if any(previous.scheme != current.scheme for previous, current in zip(targets, targets[1:])):
            raise NetworkBoundaryError("REDIRECT_UNAUTHORIZED")
        return targets

    @staticmethod
    def validate_response(*, response_bytes: int, decompressed_bytes: int, compression_ratio: float, header_bytes: int, content_type: str | None, limits: ResourceLimits = ResourceLimits()) -> None:
        if response_bytes > limits.max_response_bytes or decompressed_bytes > limits.max_decompressed_bytes:
            raise NetworkBoundaryError("RESOURCE_LIMIT_EXCEEDED")
        if compression_ratio > limits.max_compression_ratio or header_bytes > limits.max_header_bytes:
            raise NetworkBoundaryError("RESOURCE_LIMIT_EXCEEDED")
        if content_type is None or content_type not in {"text/plain", "text/markdown", "application/json"}:
            raise NetworkBoundaryError("CONTENT_TYPE_DISALLOWED")
