from __future__ import annotations

import json
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.client import HTTPConnection
from pathlib import Path
from tempfile import TemporaryDirectory

from pmiri.request_auth import AuthenticatedPrincipal, FixedWindowRateLimiter, ReplayGuard, TrustZoneAttestation
from pmiri.server import LocalServerConfigurationError, ServerAuthorizationAdapters, build_local_read_server
from pmiri.store import SQLiteStore


class _InjectedRegistry:
    def __init__(self, principal=None):
        self.principal = principal
        self.revoked = set()

    def resolve(self, authentication_ref):
        if self.principal is None or authentication_ref in self.revoked:
            return None
        return self.principal if authentication_ref == self.principal.authentication_ref else None

    def register(self, principal):
        self.principal = principal
        self.revoked.discard(principal.authentication_ref)

    def revoke(self, authentication_ref):
        self.revoked.add(authentication_ref)


class _InjectedPolicyEpoch:
    def __init__(self, value=7):
        self.value = value

    def get(self):
        return self.value

    def advance(self, value):
        if value < self.value:
            raise ValueError("policy_epoch_cannot_move_backwards")
        self.value = value


class _PassthroughBlobCipher:
    def encrypt(self, fingerprint, plaintext):
        return plaintext

    def decrypt(self, fingerprint, ciphertext):
        return ciphertext


class _UnavailablePolicyEpoch(_InjectedPolicyEpoch):
    def get(self):
        raise RuntimeError("control_plane_unavailable")


class _InvalidBlobCipher:
    pass


class LocalServerAssemblyTests(unittest.TestCase):
    def test_factory_requires_an_initialized_store(self):
        with TemporaryDirectory() as temp:
            with self.assertRaisesRegex(LocalServerConfigurationError, "storage_not_initialized"):
                build_local_read_server(Path(temp) / "missing", Path(temp) / "control.db", port=0, audit_path=None)

    def test_factory_starts_loopback_server_with_empty_control_plane(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            store = SQLiteStore(root / "store")
            store.initialize()
            server = build_local_read_server(root / "store", root / "control.db", port=0, audit_path=root / "audit.jsonl")
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
                connection.request("GET", "/healthz")
                health = connection.getresponse()
                self.assertEqual(health.status, 200)
                self.assertEqual(json.loads(health.read().decode("utf-8"))["transport"], "LOOPBACK_ONLY")
                connection.close()

                connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
                connection.request(
                    "POST",
                    "/v1/read/search",
                    body=json.dumps({"request_id": "server-test", "project_constraint": "project", "query": "release"}),
                    headers={"Content-Type": "application/json", "X-PMIRI-Authentication-Ref": "missing"},
                )
                denied = connection.getresponse()
                self.assertEqual(denied.status, 200)
                self.assertEqual(json.loads(denied.read().decode("utf-8"))["projection"]["result"]["disposition"], "EMPTY")
                connection.close()
            finally:
                server.shutdown()
                thread.join(timeout=3)
                server.server_close()

    def test_factory_accepts_injected_identity_coordination_and_blob_adapters(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            store = SQLiteStore(root / "store")
            store.initialize()
            registry = _InjectedRegistry()
            replay_guard = ReplayGuard()
            rate_limiter = FixedWindowRateLimiter()
            policy_epoch = _InjectedPolicyEpoch()
            blob_cipher = _PassthroughBlobCipher()

            server = build_local_read_server(
                root / "store",
                root / "unused-control.db",
                port=0,
                audit_path=None,
                authorization_adapters=ServerAuthorizationAdapters(
                    registry,
                    replay_guard,
                    rate_limiter,
                    policy_epoch,
                ),
                blob_cipher=blob_cipher,
            )
            try:
                authorization = server.operation_service.projection.authorization
                self.assertIs(authorization.registry, registry)
                self.assertIs(authorization.replay_guard, replay_guard)
                self.assertIs(authorization.rate_limiter, rate_limiter)
                self.assertIs(authorization.policy_epoch_store, policy_epoch)
                self.assertIs(server.operation_service.projection.runtime.store.blob_cipher, blob_cipher)
                authorization.advance_policy_epoch(8)
                self.assertEqual(policy_epoch.get(), 8)
                self.assertFalse((root / "unused-control.db").exists())
            finally:
                server.server_close()

    def test_injected_identity_adapter_authenticates_and_revocation_takes_effect(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            store = SQLiteStore(root / "store")
            store.initialize()
            store.register_bytes("project", "guide.md", b"release status is ready\n")
            now = datetime.now(timezone.utc).replace(microsecond=0)
            issued = now.isoformat().replace("+00:00", "Z")
            expires = (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
            principal_ref = "principal:injected"
            principal = AuthenticatedPrincipal.verified(
                authentication_ref="authn-injected",
                principal_ref=principal_ref,
                principal_type="human",
                service_principal_ref="service:pmiri",
                trust_zone_attestation=TrustZoneAttestation.issue(
                    principal_ref=principal_ref,
                    zone_id="LOCAL",
                    issuer_ref="security-boundary:test",
                    evidence_refs=("environment://injected-adapter",),
                    issued_at=issued,
                    valid_until=expires,
                ),
                allowed_projects=("project",),
                allowed_purposes=("local_read",),
                policy_bundle_ref="policy://read-v1",
                policy_version="1",
                policy_epoch=7,
                issued_at=issued,
                valid_until=expires,
            )
            registry = _InjectedRegistry(principal)
            server = build_local_read_server(
                root / "store",
                root / "unused-control.db",
                port=0,
                audit_path=None,
                authorization_adapters=ServerAuthorizationAdapters(
                    registry,
                    ReplayGuard(),
                    FixedWindowRateLimiter(),
                    _InjectedPolicyEpoch(7),
                ),
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
                connection.request(
                    "POST",
                    "/v1/read/search",
                    body=json.dumps({"request_id": "injected-read-1", "project_constraint": "project", "query": "release"}),
                    headers={"Content-Type": "application/json", "X-PMIRI-Authentication-Ref": "authn-injected"},
                )
                allowed = connection.getresponse()
                allowed_body = json.loads(allowed.read().decode("utf-8"))
                connection.close()
                self.assertEqual(allowed.status, 200)
                self.assertTrue(allowed_body["projection"]["evidence"])

                registry.revoke("authn-injected")
                connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
                connection.request(
                    "POST",
                    "/v1/read/search",
                    body=json.dumps({"request_id": "injected-read-2", "project_constraint": "project", "query": "release"}),
                    headers={"Content-Type": "application/json", "X-PMIRI-Authentication-Ref": "authn-injected"},
                )
                denied = connection.getresponse()
                denied_body = json.loads(denied.read().decode("utf-8"))
                connection.close()
                self.assertEqual(denied.status, 200)
                self.assertEqual(denied_body["projection"]["result"]["disposition"], "EMPTY")
                self.assertFalse(denied_body["projection"]["evidence"])
            finally:
                server.shutdown()
                thread.join(timeout=3)
                server.server_close()

    def test_factory_rejects_invalid_injected_adapters_before_server_creation(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            store = SQLiteStore(root / "store")
            store.initialize()
            invalid = ServerAuthorizationAdapters(
                registry=object(),
                replay_guard=ReplayGuard(),
                rate_limiter=FixedWindowRateLimiter(),
                policy_epoch_store=_InjectedPolicyEpoch(),
            )
            with self.assertRaisesRegex(LocalServerConfigurationError, "authorization_adapters_invalid"):
                build_local_read_server(
                    root / "store",
                    root / "unused-control.db",
                    port=0,
                    audit_path=None,
                    authorization_adapters=invalid,
                )
            self.assertFalse((root / "unused-control.db").exists())

    def test_factory_rejects_invalid_injected_policy_epoch(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            store = SQLiteStore(root / "store")
            store.initialize()
            invalid_epoch = _InjectedPolicyEpoch(True)
            adapters = ServerAuthorizationAdapters(
                registry=_InjectedRegistry(),
                replay_guard=ReplayGuard(),
                rate_limiter=FixedWindowRateLimiter(),
                policy_epoch_store=invalid_epoch,
            )
            with self.assertRaisesRegex(LocalServerConfigurationError, "authorization_epoch_invalid"):
                build_local_read_server(
                    root / "store",
                    root / "unused-control.db",
                    port=0,
                    audit_path=None,
                    authorization_adapters=adapters,
                )

    def test_factory_rejects_unavailable_injected_policy_epoch(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            store = SQLiteStore(root / "store")
            store.initialize()
            adapters = ServerAuthorizationAdapters(
                registry=_InjectedRegistry(),
                replay_guard=ReplayGuard(),
                rate_limiter=FixedWindowRateLimiter(),
                policy_epoch_store=_UnavailablePolicyEpoch(),
            )
            with self.assertRaisesRegex(LocalServerConfigurationError, "authorization_epoch_unavailable"):
                build_local_read_server(
                    root / "store",
                    root / "unused-control.db",
                    port=0,
                    audit_path=None,
                    authorization_adapters=adapters,
                )

    def test_factory_rejects_invalid_blob_cipher_before_server_creation(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            store = SQLiteStore(root / "store")
            store.initialize()
            with self.assertRaisesRegex(LocalServerConfigurationError, "blob_cipher_invalid"):
                build_local_read_server(
                    root / "store",
                    root / "unused-control.db",
                    port=0,
                    audit_path=None,
                    blob_cipher=_InvalidBlobCipher(),
                )


if __name__ == "__main__":
    unittest.main()
