"""Encrypted, opt-in trace retention with key-domain separation.

Raw query/context/candidate capture is disabled by default.  When explicitly
enabled, payloads are encrypted with AES-GCM and the per-domain key is
protected by the current Windows user's DPAPI.  Access and expiry are checked
before decryption; plaintext is never written to the trace directory.
"""

from __future__ import annotations

import base64
import binascii
import ctypes
import json
import os
import re
import secrets
import tempfile
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping, Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from .canonical import canonical_json, is_sha256, sha256_bytes, sha256_json, utc_now


_TRACE_ID_RE = re.compile(r"^trace_[0-9a-f]{32}$")
_KEY_THREAD_LOCKS: dict[str, threading.Lock] = {}
_KEY_THREAD_LOCKS_GUARD = threading.Lock()


class KeyManagementError(RuntimeError):
    pass


class KeyProvider(Protocol):
    def get_key(self, domain_id: str) -> bytes: ...


def _thread_lock_for_key_path(path: Path) -> threading.Lock:
    key = str(path.resolve())
    with _KEY_THREAD_LOCKS_GUARD:
        lock = _KEY_THREAD_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _KEY_THREAD_LOCKS[key] = lock
        return lock


def _parse_time(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp_invalid")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timestamp_must_be_timezone_aware")
    return parsed.astimezone(timezone.utc)


def _valid_domain(domain_id: str) -> bool:
    return isinstance(domain_id, str) and 1 <= len(domain_id) <= 64 and all(ch.isupper() or ch.isdigit() or ch in "_-" for ch in domain_id)


@contextmanager
def _key_file_lock(path: Path) -> Iterator[None]:
    """Serialize per-domain key reads/creation across threads and processes."""

    with _thread_lock_for_key_path(path):
        lock_path = path.with_suffix(path.suffix + ".lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
        locked = False
        try:
            if os.name == "nt":
                import msvcrt

                if os.fstat(descriptor).st_size == 0:
                    os.write(descriptor, b"0")
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
                locked = True
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX)
                locked = True
            yield
        finally:
            if locked:
                if os.name == "nt":
                    import msvcrt

                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)


class DpapiKeyProvider:
    """Persist per-domain AES keys protected by Windows user-scope DPAPI."""

    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()

    @staticmethod
    def _entropy(domain_id: str) -> bytes:
        return sha256_json({"pmiri_key_domain": domain_id}).encode("ascii")

    @staticmethod
    def _protect(plaintext: bytes, entropy: bytes) -> bytes:
        if os.name != "nt":
            raise KeyManagementError("dpapi_unavailable")
        from ctypes import wintypes

        class Blob(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

        source_buffer = (ctypes.c_ubyte * len(plaintext)).from_buffer_copy(plaintext)
        entropy_buffer = (ctypes.c_ubyte * len(entropy)).from_buffer_copy(entropy)
        source = Blob(len(plaintext), source_buffer)
        entropy_blob = Blob(len(entropy), entropy_buffer)
        output = Blob()
        crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        if not crypt32.CryptProtectData(ctypes.byref(source), None, ctypes.byref(entropy_blob), None, None, 0x1, ctypes.byref(output)):
            raise KeyManagementError("dpapi_protect_failed")
        try:
            return ctypes.string_at(output.pbData, output.cbData)
        finally:
            kernel32.LocalFree(output.pbData)

    @staticmethod
    def _unprotect(ciphertext: bytes, entropy: bytes) -> bytes:
        if os.name != "nt":
            raise KeyManagementError("dpapi_unavailable")
        from ctypes import wintypes

        class Blob(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

        source_buffer = (ctypes.c_ubyte * len(ciphertext)).from_buffer_copy(ciphertext)
        entropy_buffer = (ctypes.c_ubyte * len(entropy)).from_buffer_copy(entropy)
        source = Blob(len(ciphertext), source_buffer)
        entropy_blob = Blob(len(entropy), entropy_buffer)
        output = Blob()
        crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        if not crypt32.CryptUnprotectData(ctypes.byref(source), None, ctypes.byref(entropy_blob), None, None, 0x1, ctypes.byref(output)):
            raise KeyManagementError("dpapi_unprotect_failed")
        try:
            return ctypes.string_at(output.pbData, output.cbData)
        finally:
            kernel32.LocalFree(output.pbData)

    def _path(self, domain_id: str) -> Path:
        if not _valid_domain(domain_id):
            raise KeyManagementError("key_domain_invalid")
        return self.root / ("dpapi-" + sha256_json({"domain": domain_id})[:32] + ".json")

    def get_key(self, domain_id: str) -> bytes:
        path = self._path(domain_id)
        entropy = self._entropy(domain_id)
        self.root.mkdir(parents=True, exist_ok=True)
        with _key_file_lock(path):
            if path.exists():
                try:
                    record = json.loads(path.read_text(encoding="utf-8"))
                    if (
                        record.get("version") != "0.1"
                        or record.get("domain_id") != domain_id
                        or record.get("scope") != "CURRENT_USER"
                        or record.get("algorithm") != "DPAPI_USER_SCOPE"
                        or not is_sha256(record.get("ciphertext_sha256"))
                    ):
                        raise KeyManagementError("key_record_invalid")
                    protected = base64.b64decode(record["protected_key"], validate=True)
                    if sha256_bytes(protected) != record["ciphertext_sha256"]:
                        raise KeyManagementError("key_record_fingerprint_mismatch")
                    key = self._unprotect(protected, entropy)
                except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, KeyError, TypeError, binascii.Error) as exc:
                    raise KeyManagementError("key_record_invalid") from exc
                if len(key) != 32:
                    raise KeyManagementError("key_length_invalid")
                return key
            key = secrets.token_bytes(32)
            protected = self._protect(key, entropy)
            record = {
                "version": "0.1",
                "domain_id": domain_id,
                "scope": "CURRENT_USER",
                "algorithm": "DPAPI_USER_SCOPE",
                "protected_key": base64.b64encode(protected).decode("ascii"),
                "ciphertext_sha256": sha256_bytes(protected),
            }
            descriptor, temporary_name = tempfile.mkstemp(prefix="dpapi-key-", suffix=".tmp", dir=self.root)
            temporary = Path(temporary_name)
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                    stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                os.chmod(temporary, 0o600)
                temporary.replace(path)
            finally:
                if temporary.exists():
                    temporary.unlink()
            return key


@dataclass(frozen=True)
class TraceRetentionPolicy:
    capture_enabled: bool = False
    ttl_seconds: int = 0
    key_domain: str = "TRACE"
    allowed_access_roles: tuple[str, ...] = ("independent_reviewer",)

    def validate(self) -> None:
        if self.capture_enabled and not 1 <= self.ttl_seconds <= 30 * 24 * 60 * 60:
            raise ValueError("trace_ttl_invalid")
        if not _valid_domain(self.key_domain):
            raise ValueError("trace_key_domain_invalid")
        if not self.allowed_access_roles or any(not isinstance(role, str) or not role for role in self.allowed_access_roles):
            raise ValueError("trace_access_roles_invalid")


@dataclass(frozen=True)
class TraceCaptureResult:
    status: str
    reason: str
    trace_id: str | None = None
    payload_fingerprint: str | None = None
    expires_at: str | None = None

    def structured(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason": self.reason,
            "trace_id": self.trace_id,
            "payload_fingerprint": self.payload_fingerprint,
            "expires_at": self.expires_at,
        }


class EncryptedTraceStore:
    """Opt-in trace store with encrypted payloads and TTL/access enforcement."""

    def __init__(self, root: str | Path, *, key_provider: KeyProvider, policy: TraceRetentionPolicy | None = None):
        self.root = Path(root).resolve()
        self.key_provider = key_provider
        self.policy = policy or TraceRetentionPolicy()
        self.policy.validate()

    def capture(self, payload: Mapping[str, Any], *, actor_role: str, captured_at: str | None = None) -> TraceCaptureResult:
        if not self.policy.capture_enabled:
            return TraceCaptureResult("DISABLED", "raw_trace_capture_disabled_by_policy")
        if actor_role not in self.policy.allowed_access_roles:
            return TraceCaptureResult("DENIED", "trace_capture_role_not_authorized")
        if not isinstance(payload, Mapping):
            return TraceCaptureResult("DENIED", "trace_payload_invalid")
        captured_at = captured_at or utc_now()
        try:
            expires_at = (_parse_time(captured_at) + timedelta(seconds=self.policy.ttl_seconds)).isoformat().replace("+00:00", "Z")
            plaintext = canonical_json(dict(payload))
            key = self.key_provider.get_key(self.policy.key_domain)
            if len(key) != 32:
                raise KeyManagementError("key_length_invalid")
            nonce = secrets.token_bytes(12)
            aad = canonical_json({"domain_id": self.policy.key_domain, "captured_at": captured_at, "expires_at": expires_at})
            ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
            trace_id = "trace_" + secrets.token_hex(16)
            record = {
                "version": "0.1",
                "trace_id": trace_id,
                "key_domain": self.policy.key_domain,
                "captured_at": captured_at,
                "expires_at": expires_at,
                "payload_fingerprint": sha256_bytes(plaintext),
                "algorithm": "AES-256-GCM",
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "aad_fingerprint": sha256_bytes(aad),
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            }
            self.root.mkdir(parents=True, exist_ok=True)
            path = self.root / (trace_id + ".json")
            descriptor, temporary_name = tempfile.mkstemp(prefix="trace-", suffix=".tmp", dir=self.root)
            temporary = Path(temporary_name)
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                    stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                os.chmod(temporary, 0o600)
                temporary.replace(path)
            finally:
                if temporary.exists():
                    temporary.unlink()
            return TraceCaptureResult("RECORDED", "encrypted_trace_recorded", trace_id, record["payload_fingerprint"], expires_at)
        except (OSError, TypeError, ValueError, KeyManagementError) as exc:
            return TraceCaptureResult("BLOCKED", type(exc).__name__ + ":" + str(exc))

    def read(self, trace_id: str, *, actor_role: str, now: str | None = None) -> dict[str, Any]:
        if actor_role not in self.policy.allowed_access_roles:
            raise PermissionError("trace_access_denied")
        if not isinstance(trace_id, str) or _TRACE_ID_RE.fullmatch(trace_id) is None:
            raise ValueError("trace_id_invalid")
        path = self.root / (trace_id + ".json")
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
            if record.get("trace_id") != trace_id or record.get("key_domain") != self.policy.key_domain:
                raise ValueError("trace_record_invalid")
            current = _parse_time(now or utc_now())
            if current >= _parse_time(record["expires_at"]):
                raise PermissionError("trace_expired")
            aad = canonical_json({"domain_id": record["key_domain"], "captured_at": record["captured_at"], "expires_at": record["expires_at"]})
            if sha256_bytes(aad) != record.get("aad_fingerprint"):
                raise ValueError("trace_aad_fingerprint_mismatch")
            ciphertext = base64.b64decode(record["ciphertext"], validate=True)
            plaintext = AESGCM(self.key_provider.get_key(record["key_domain"])).decrypt(base64.b64decode(record["nonce"], validate=True), ciphertext, aad)
            if sha256_bytes(plaintext) != record.get("payload_fingerprint"):
                raise ValueError("trace_payload_fingerprint_mismatch")
            payload = json.loads(plaintext.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("trace_payload_invalid")
            return payload
        except FileNotFoundError as exc:
            raise KeyError("trace_not_found") from exc
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError, binascii.Error, InvalidTag) as exc:
            if isinstance(exc, PermissionError):
                raise
            raise ValueError("trace_record_invalid") from exc

    def purge(self, *, now: str | None = None) -> int:
        current = _parse_time(now or utc_now())
        removed = 0
        if not self.root.exists():
            return 0
        for path in self.root.glob("trace_*.json"):
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
                if current >= _parse_time(record["expires_at"]):
                    path.unlink()
                    removed += 1
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
                continue
        return removed


__all__ = ["DpapiKeyProvider", "EncryptedTraceStore", "KeyManagementError", "TraceCaptureResult", "TraceRetentionPolicy"]
