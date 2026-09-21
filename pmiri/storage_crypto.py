"""Versioned AES-GCM content-at-rest encryption for SQLite blobs.

The SQLite schema keeps the plaintext content fingerprint as the lookup key,
but stores only an authenticated ciphertext blob when a cipher is configured.
Project/source metadata remains queryable by design; deployments that classify
metadata as secret must put the control plane behind an encrypted volume or
provide a separate metadata-encryption adapter.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import secrets
from typing import Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .canonical import canonical_json, sha256_bytes


class StorageEncryptionError(ValueError):
    pass


class StorageKeyProvider(Protocol):
    def get_key(self, domain_id: str) -> bytes: ...


class KeyEscrowAdapter(Protocol):
    """Deployment-owned key escrow notification port.

    The adapter receives only a key reference and fingerprint, never raw key
    material. Rotation does not become active until this notification returns
    successfully.
    """

    def escrow(self, *, domain_id: str, key_version: str, key_fingerprint: str) -> None:
        ...


class BlobCipher(Protocol):
    def encrypt(self, fingerprint: str, plaintext: bytes) -> bytes: ...

    def decrypt(self, fingerprint: str, ciphertext: bytes) -> bytes: ...


_VERSION_RE = re.compile(r"^[A-Z][A-Z0-9_-]{0,15}$")


class AesGcmBlobCipher:
    """Authenticated, versioned AES-256-GCM cipher with in-process rotation."""

    VERSION = "0.1"
    ALGORITHM = "AES-256-GCM"

    def __init__(
        self,
        key_provider: StorageKeyProvider,
        *,
        domain_id: str = "STORE_BLOB",
        current_key_version: str = "V1",
        accepted_key_versions: tuple[str, ...] | None = None,
        key_escrow: KeyEscrowAdapter | None = None,
    ) -> None:
        self.key_provider = key_provider
        if key_escrow is not None and not callable(getattr(key_escrow, "escrow", None)):
            raise StorageEncryptionError("storage_key_escrow_invalid")
        self.key_escrow = key_escrow
        self.domain_id = domain_id
        self._validate_version(current_key_version)
        accepted = set(accepted_key_versions or ())
        accepted.add(current_key_version)
        for version in accepted:
            self._validate_version(version)
        if not isinstance(domain_id, str) or not domain_id or len(domain_id) > 48 or not re.fullmatch(r"[A-Z][A-Z0-9_-]*", domain_id):
            raise StorageEncryptionError("storage_key_domain_invalid")
        self.current_key_version = current_key_version
        self.accepted_key_versions = frozenset(accepted)

    @staticmethod
    def _validate_version(version: str) -> None:
        if not isinstance(version, str) or not _VERSION_RE.fullmatch(version):
            raise StorageEncryptionError("storage_key_version_invalid")

    def _key(self, version: str) -> bytes:
        try:
            key = self.key_provider.get_key(f"{self.domain_id}_{version}")
        except Exception as exc:  # key providers must fail closed at this boundary
            raise StorageEncryptionError("storage_key_unavailable") from exc
        if not isinstance(key, bytes) or len(key) != 32:
            raise StorageEncryptionError("storage_key_length_invalid")
        return key

    def rotate(self, new_key_version: str) -> None:
        self._validate_version(new_key_version)
        # The provider is probed before switching the active version, so a
        # missing KMS/DPAPI key cannot leave the cipher in a half-rotated state.
        new_key = self._key(new_key_version)
        if self.key_escrow is not None:
            try:
                self.key_escrow.escrow(
                    domain_id=self.domain_id,
                    key_version=new_key_version,
                    key_fingerprint=sha256_bytes(new_key),
                )
            except Exception as exc:  # escrow failure must not activate a key
                raise StorageEncryptionError("storage_key_escrow_failed") from exc
        self.current_key_version = new_key_version
        self.accepted_key_versions = frozenset(set(self.accepted_key_versions) | {new_key_version})

    def encrypt(self, fingerprint: str, plaintext: bytes) -> bytes:
        if not isinstance(fingerprint, str) or len(fingerprint) != 64:
            raise StorageEncryptionError("storage_plaintext_fingerprint_invalid")
        if not isinstance(plaintext, bytes):
            raise StorageEncryptionError("storage_plaintext_bytes_required")
        version = self.current_key_version
        nonce = secrets.token_bytes(12)
        aad = canonical_json({"domain_id": self.domain_id, "key_version": version, "fingerprint": fingerprint})
        ciphertext = AESGCM(self._key(version)).encrypt(nonce, plaintext, aad)
        envelope = {
            "version": self.VERSION,
            "algorithm": self.ALGORITHM,
            "domain_id": self.domain_id,
            "key_version": version,
            "fingerprint": fingerprint,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }
        return canonical_json(envelope)

    def decrypt(self, fingerprint: str, ciphertext: bytes) -> bytes:
        try:
            envelope = json.loads(ciphertext)
            if not isinstance(envelope, dict):
                raise StorageEncryptionError("storage_envelope_invalid")
            version = envelope.get("key_version")
            if envelope.get("version") != self.VERSION or envelope.get("algorithm") != self.ALGORITHM:
                raise StorageEncryptionError("storage_envelope_invalid")
            if envelope.get("domain_id") != self.domain_id or envelope.get("fingerprint") != fingerprint:
                raise StorageEncryptionError("storage_envelope_binding_mismatch")
            if version not in self.accepted_key_versions:
                raise StorageEncryptionError("storage_key_version_not_accepted")
            nonce = base64.b64decode(envelope["nonce"], validate=True)
            encoded = base64.b64decode(envelope["ciphertext"], validate=True)
            if len(nonce) != 12:
                raise StorageEncryptionError("storage_nonce_invalid")
            aad = canonical_json({"domain_id": self.domain_id, "key_version": version, "fingerprint": fingerprint})
            plaintext = AESGCM(self._key(version)).decrypt(nonce, encoded, aad)
            if sha256_bytes(plaintext) != fingerprint:
                raise StorageEncryptionError("storage_plaintext_fingerprint_mismatch")
            return plaintext
        except StorageEncryptionError:
            raise
        except (TypeError, ValueError, KeyError, json.JSONDecodeError, binascii.Error, InvalidTag) as exc:
            raise StorageEncryptionError("storage_ciphertext_invalid") from exc


__all__ = [
    "AesGcmBlobCipher",
    "BlobCipher",
    "KeyEscrowAdapter",
    "StorageEncryptionError",
    "StorageKeyProvider",
]
