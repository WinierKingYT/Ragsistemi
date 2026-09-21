from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from pmiri.control_plane import (
    SQLiteAuthenticationRegistry,
    SQLitePolicyEpoch,
    SQLiteRateLimiter,
    SQLiteReplayGuard,
)
from pmiri.read_projection import ReadProjectionService
from pmiri.request_auth import AuthenticatedPrincipal, RequestAuthorizationError, RequestAuthorizationService, TrustZoneAttestation
from pmiri.gate_d import GateDDecisionEngine
from pmiri.runtime import LocalEvidenceRuntime
from pmiri.store import LocalStore


ISSUED = "2025-12-31T00:00:00Z"
EXPIRES = "2026-01-02T00:00:00Z"


def make_principal() -> AuthenticatedPrincipal:
    principal_ref = "principal:durable"
    attestation = TrustZoneAttestation.issue(
        principal_ref=principal_ref,
        zone_id="LOCAL",
        issuer_ref="security-boundary:test",
        evidence_refs=("environment://test",),
        issued_at=ISSUED,
        valid_until=EXPIRES,
    )
    return AuthenticatedPrincipal.verified(
        authentication_ref="authn-durable",
        principal_ref=principal_ref,
        principal_type="service",
        service_principal_ref="service:pmiri",
        trust_zone_attestation=attestation,
        allowed_projects=("project",),
        policy_bundle_ref="policy://read-v1",
        policy_version="1",
        policy_epoch=4,
        issued_at=ISSUED,
        valid_until=EXPIRES,
    )


class ControlPlaneTests(unittest.TestCase):
    def test_principal_registry_persists_and_revoke_is_fail_closed(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "control.db"
            first = SQLiteAuthenticationRegistry(path)
            first.initialize()
            principal = make_principal()
            first.register(principal)

            second = SQLiteAuthenticationRegistry(path)
            self.assertEqual(second.resolve(principal.authentication_ref), principal)
            self.assertTrue(second.revoke(principal.authentication_ref))
            self.assertIsNone(first.resolve(principal.authentication_ref))
            self.assertFalse(second.revoke(principal.authentication_ref))
            with self.assertRaisesRegex(RequestAuthorizationError, "principal_revoked"):
                second.register(principal)

    def test_registry_detects_tampered_principal_payload(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "control.db"
            registry = SQLiteAuthenticationRegistry(path)
            registry.initialize()
            principal = make_principal()
            registry.register(principal)
            connection = sqlite3.connect(path)
            try:
                connection.execute(
                    "UPDATE authenticated_principals SET payload_json=? WHERE authentication_ref=?",
                    ('{"authentication_ref":"authn-durable"}', principal.authentication_ref),
                )
                connection.commit()
            finally:
                connection.close()
            self.assertIsNone(registry.resolve(principal.authentication_ref))

    def test_replay_guard_is_shared_and_expiry_is_transactional(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "control.db"
            first = SQLiteReplayGuard(path)
            first.initialize()
            second = SQLiteReplayGuard(path)
            self.assertTrue(first.consume(request_id="r1", fingerprint="a" * 64, expires_at=EXPIRES, now=ISSUED))
            self.assertFalse(second.consume(request_id="r1", fingerprint="b" * 64, expires_at=EXPIRES, now=ISSUED))
            self.assertTrue(second.consume(request_id="r2", fingerprint="c" * 64, expires_at=EXPIRES, now=ISSUED))
            self.assertTrue(first.consume(request_id="r1", fingerprint="d" * 64, expires_at=EXPIRES, now="2026-01-03T00:00:00Z"))

    def test_replay_guard_allows_one_concurrent_consumer(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "control.db"
            guard = SQLiteReplayGuard(path)
            guard.initialize()
            with ThreadPoolExecutor(max_workers=8) as executor:
                results = list(
                    executor.map(
                        lambda index: guard.consume(
                            request_id="concurrent-request",
                            fingerprint=str(index) * 64,
                            expires_at=EXPIRES,
                            now=ISSUED,
                        ),
                        range(16),
                    )
                )
            self.assertEqual(sum(results), 1)

    def test_rate_limiter_is_shared_across_workers(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "control.db"
            first = SQLiteRateLimiter(path, max_requests=2, window_seconds=60)
            first.initialize()
            second = SQLiteRateLimiter(path, max_requests=2, window_seconds=60)
            self.assertTrue(first.consume(key="principal:op", now=100.0))
            self.assertTrue(second.consume(key="principal:op", now=101.0))
            self.assertFalse(first.consume(key="principal:op", now=102.0))
            self.assertTrue(second.consume(key="principal:op", now=161.0))

    def test_rate_limiter_never_exceeds_limit_under_concurrency(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "control.db"
            limiter = SQLiteRateLimiter(path, max_requests=4, window_seconds=60)
            limiter.initialize()
            with ThreadPoolExecutor(max_workers=8) as executor:
                results = list(
                    executor.map(
                        lambda _index: limiter.consume(key="concurrent-principal", now=100.0),
                        range(16),
                    )
                )
            self.assertEqual(sum(results), 4)

    def test_policy_epoch_is_monotonic_and_shared(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "control.db"
            first = SQLitePolicyEpoch(path, initial_epoch=4)
            first.initialize()
            second = SQLitePolicyEpoch(path, initial_epoch=0)
            self.assertEqual(second.get(), 4)
            first.advance(5)
            self.assertEqual(second.get(), 5)
            with self.assertRaisesRegex(ValueError, "cannot_move_backwards"):
                second.advance(4)

    def test_policy_epoch_bumps_are_unique_under_concurrency(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "control.db"
            epoch = SQLitePolicyEpoch(path, initial_epoch=0)
            epoch.initialize()
            with ThreadPoolExecutor(max_workers=8) as executor:
                values = list(executor.map(lambda _index: epoch.bump(), range(16)))
            self.assertEqual(sorted(values), list(range(1, 17)))
            self.assertEqual(epoch.get(), 16)

    def test_gate_d_invalidation_uses_shared_durable_epoch(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "control.db"
            epoch = SQLitePolicyEpoch(path, initial_epoch=0)
            epoch.initialize()
            engine = GateDDecisionEngine("a" * 64, policy_epoch_store=epoch, now="2026-01-01T00:00:00Z")
            self.assertEqual(engine.invalidation_epoch, 0)
            self.assertEqual(engine.invalidate(), 1)
            self.assertEqual(epoch.get(), 1)
            self.assertEqual(engine.invalidation_epoch, 1)

    def test_authenticated_read_uses_durable_control_plane_adapters(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            control_path = root / "control.db"
            registry = SQLiteAuthenticationRegistry(control_path)
            replay = SQLiteReplayGuard(control_path)
            limiter = SQLiteRateLimiter(control_path, max_requests=2, window_seconds=60)
            epoch = SQLitePolicyEpoch(control_path, initial_epoch=4)
            registry.initialize()
            replay.initialize()
            limiter.initialize()
            epoch.initialize()
            principal = make_principal()
            registry.register(principal)
            authorization = RequestAuthorizationService(
                registry,
                current_policy_epoch=4,
                replay_guard=replay,
                rate_limiter=limiter,
                policy_epoch_store=epoch,
                clock=lambda: 100.0,
            )
            store = LocalStore(root / "store")
            store.initialize()
            store.register_bytes("project", "guide.md", b"release status is ready\n", capture_time=ISSUED)
            service = ReadProjectionService(LocalEvidenceRuntime(store), authorization)
            first = service.api_authenticated(
                {"request_id": "durable-1", "project_constraint": "project", "query": "release"},
                authentication_ref=principal.authentication_ref,
                now="2026-01-01T00:00:00Z",
            )
            self.assertTrue(first["evidence"])
            self.assertTrue(registry.revoke(principal.authentication_ref))
            revoked = service.api_authenticated(
                {"request_id": "durable-2", "project_constraint": "project", "query": "release"},
                authentication_ref=principal.authentication_ref,
                now="2026-01-01T00:00:00Z",
            )
            self.assertEqual(revoked["result"], {"disposition": "EMPTY", "coverage": "unknown"})


if __name__ == "__main__":
    unittest.main()
