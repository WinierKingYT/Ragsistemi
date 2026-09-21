"""PMIRI local-first evidence runtime."""

from .models import (
    Coverage,
    Disposition,
    EvidenceItem,
    EvidenceSet,
    QueryRequest,
    QueryResult,
    SourceRecord,
)
from .store import LocalStore
from .gate_d import GateDDecisionEngine
from .control_plane import SQLiteAuthenticationRegistry, SQLitePolicyEpoch, SQLiteRateLimiter, SQLiteReplayGuard
from .storage_crypto import AesGcmBlobCipher, KeyEscrowAdapter, StorageEncryptionError, StorageKeyProvider
from .request_auth import (
    AuthenticatedPrincipal,
    AuthenticationRegistry,
    FixedWindowRateLimiter,
    ReplayGuard,
    RequestAuthorizationBinding,
    RequestAuthorizationService,
    TrustZoneAttestation,
)
from .http_api import LocalReadMetrics
from .server import (
    AuthorizationRegistryAdapter,
    LocalServerConfigurationError,
    PolicyEpochAdapter,
    RateLimiterAdapter,
    ReplayGuardAdapter,
    ServerAuthorizationAdapters,
    build_local_read_server,
)
from .handoff import HandoffError, create_handoff_bundle, verify_handoff
from .review_package import ReviewPackageError, build_review_package, validate_review_package

__all__ = [
    "Coverage",
    "Disposition",
    "EvidenceItem",
    "EvidenceSet",
    "LocalStore",
    "GateDDecisionEngine",
    "AuthenticatedPrincipal",
    "AuthenticationRegistry",
    "FixedWindowRateLimiter",
    "ReplayGuard",
    "RequestAuthorizationBinding",
    "RequestAuthorizationService",
    "TrustZoneAttestation",
    "SQLiteAuthenticationRegistry",
    "SQLitePolicyEpoch",
    "SQLiteRateLimiter",
    "SQLiteReplayGuard",
    "AesGcmBlobCipher",
    "KeyEscrowAdapter",
    "StorageEncryptionError",
    "StorageKeyProvider",
    "LocalReadMetrics",
    "LocalServerConfigurationError",
    "AuthorizationRegistryAdapter",
    "PolicyEpochAdapter",
    "RateLimiterAdapter",
    "ReplayGuardAdapter",
    "ServerAuthorizationAdapters",
    "build_local_read_server",
    "HandoffError",
    "create_handoff_bundle",
    "verify_handoff",
    "ReviewPackageError",
    "build_review_package",
    "validate_review_package",
    "QueryRequest",
    "QueryResult",
    "SourceRecord",
]
