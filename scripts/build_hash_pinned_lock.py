"""Build a deterministic hash-pinned lock from an offline package mirror.

The repository's exact-version lock remains authoritative. This helper only
reads that lock and a deployment-supplied local mirror, computes SHA-256 for
every matching archive, and writes a new lock without contacting a package
index. Missing packages and output collisions are hard errors.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.verify_reproducibility import read_lock  # noqa: E402
from scripts.verify_supply_chain import ARCHIVE_SUFFIXES, SupplyChainError, _artifact_matches, verify_hash_pinned_lock, verify_mirror_artifacts  # noqa: E402


class HashLockBuildError(ValueError):
    """Raised when an offline mirror cannot produce a complete hash lock."""


def _archives(mirror_root: Path) -> tuple[Path, ...]:
    if mirror_root.is_symlink() or not mirror_root.is_dir():
        raise HashLockBuildError("mirror_directory_unavailable")
    try:
        return tuple(
            path
            for path in mirror_root.rglob("*")
            if path.is_file() and not path.is_symlink() and path.name.casefold().endswith(tuple(suffix.casefold() for suffix in ARCHIVE_SUFFIXES))
        )
    except OSError as exc:
        raise HashLockBuildError("mirror_read_failed") from exc


def build_hash_pinned_lock(mirror_root: str | Path, output_path: str | Path) -> dict[str, object]:
    """Create and verify a hash lock from *mirror_root* without network I/O."""

    mirror = Path(mirror_root).resolve()
    archives = _archives(mirror)
    locked = read_lock()
    lines: list[str] = []
    entries: dict[str, tuple[str, tuple[str, ...]]] = {}
    for name, version in sorted(locked.items()):
        candidates = sorted(path for path in archives if _artifact_matches(path, name, version))
        if not candidates:
            raise HashLockBuildError(f"mirror_artifact_missing:{name}=={version}")
        hashes = tuple(sorted({hashlib.sha256(path.read_bytes()).hexdigest() for path in candidates}))
        entries[name] = (version, hashes)
        lines.append(f"{name}=={version} " + " ".join(f"--hash=sha256:{digest}" for digest in hashes))

    destination = Path(output_path)
    if destination.exists():
        raise HashLockBuildError("hash_lock_output_exists")
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write("# Generated from the exact PMIRI lock and an offline deployment mirror.\n")
            stream.write("\n".join(lines) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise HashLockBuildError("hash_lock_output_exists") from exc
    except OSError as exc:
        raise HashLockBuildError("hash_lock_output_write_failed") from exc

    errors = list(verify_hash_pinned_lock(destination, base_lock=locked))
    errors.extend(verify_mirror_artifacts(mirror, entries=entries))
    if errors:
        raise HashLockBuildError("hash_lock_verification_failed:" + errors[0])
    return {"package_count": len(entries), "output": str(destination.resolve()), "mirror": str(mirror)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", required=True, help="offline package mirror directory")
    parser.add_argument("--output", required=True, help="new hash-pinned lock path")
    args = parser.parse_args(argv)
    try:
        result = build_hash_pinned_lock(args.artifact_dir, args.output)
    except (HashLockBuildError, SupplyChainError, OSError, ValueError, KeyError) as exc:
        print(json.dumps({"status": "HASH_LOCK_BUILD_BLOCKED", "error": str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps({"status": "HASH_LOCK_BUILT", **result}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
