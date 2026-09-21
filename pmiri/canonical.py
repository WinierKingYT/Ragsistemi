"""Canonical serialization and fingerprint primitives.

All fingerprints in PMIRI are over UTF-8 JSON with sorted keys, compact
separators and no ambient locale-dependent formatting.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_json(value))


def is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_text(raw: bytes) -> str:
    """Decode only strict UTF-8 and normalize line endings to LF."""
    text = raw.decode("utf-8", errors="strict")
    return text.replace("\r\n", "\n").replace("\r", "\n")
