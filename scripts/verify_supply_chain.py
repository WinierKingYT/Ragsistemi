"""Verify a deployment-supplied hash-pinned Python dependency lock.

``requirements.lock`` deliberately records exact versions only because this
repository does not select or attest a package mirror.  A deployment can
provide a second lock with one or more SHA-256 hashes per exact requirement.
This module verifies that the supplied lock has the same package/version
inventory as the repository lock and, optionally, that a local mirror
contains matching artefacts.

The checker is stdlib-only and never downloads packages or treats a public
index as a trusted source.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path
from typing import Iterable, Mapping

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.verify_reproducibility import canonical_name, read_lock  # noqa: E402


HASH_PATTERN = re.compile(r"^sha256:([0-9a-fA-F]{64})$")
ARCHIVE_SUFFIXES = (".whl", ".zip", ".tar.gz", ".tar.bz2", ".tar", ".tgz")


class SupplyChainError(ValueError):
    """Raised when a deployment lock or mirror is not verifiable."""


def _parse_hash_flag(token: str, package: str) -> str:
    if not token.startswith("--hash="):
        raise SupplyChainError(f"hash_lock_option_invalid:{package}")
    match = HASH_PATTERN.fullmatch(token[len("--hash=") :])
    if match is None:
        raise SupplyChainError(f"hash_invalid:{package}")
    return match.group(1).lower()


def read_hash_pinned_lock(path: Path) -> dict[str, tuple[str, tuple[str, ...]]]:
    """Read ``name==version --hash=sha256:...`` entries from *path*."""

    entries: dict[str, tuple[str, tuple[str, ...]]] = {}
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        tokens = line.split()
        if "==" not in tokens[0]:
            raise SupplyChainError(f"invalid_hash_lock_line:{line_number}")
        name, version = tokens[0].split("==", 1)
        if not name or not version or not re.fullmatch(r"[0-9][0-9A-Za-z.+-]*", version):
            raise SupplyChainError(f"invalid_hash_lock_line:{line_number}")
        if len(tokens) < 2:
            raise SupplyChainError(f"hash_missing:{name}")
        key = canonical_name(name)
        if key in entries:
            raise SupplyChainError(f"duplicate_hash_lock_package:{name}")
        hashes = tuple(dict.fromkeys(_parse_hash_flag(token, name) for token in tokens[1:]))
        if not hashes:
            raise SupplyChainError(f"hash_missing:{name}")
        entries[key] = (version, hashes)
    if not entries:
        raise SupplyChainError("hash_lock_is_empty")
    return entries


def verify_hash_pinned_lock(
    path: Path,
    *,
    base_lock: Mapping[str, str] | None = None,
) -> tuple[str, ...]:
    """Return deterministic errors for a deployment-supplied hash lock."""

    try:
        entries = read_hash_pinned_lock(path)
    except (OSError, SupplyChainError) as exc:
        return (str(exc),)
    expected = dict(base_lock or read_lock())
    errors: list[str] = []
    if set(entries) != set(expected):
        for name in sorted(set(expected) - set(entries)):
            errors.append(f"hash_lock_package_missing:{name}")
        for name in sorted(set(entries) - set(expected)):
            errors.append(f"hash_lock_package_unexpected:{name}")
    for name, version in expected.items():
        entry = entries.get(name)
        if entry is None:
            continue
        if entry[0] != version:
            errors.append(f"hash_lock_version_mismatch:{name}=={entry[0]};expected=={version}")
    return tuple(errors)


def _normalised_archive_identity(value: str) -> str:
    return re.sub(r"[-_.]+", "", value).lower()


def _iter_archives(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if path.is_file() and path.name.lower().endswith(ARCHIVE_SUFFIXES):
            yield path


def _artifact_matches(path: Path, name: str, version: str) -> bool:
    filename = path.name.casefold()
    package_names = {name.casefold(), name.casefold().replace("-", "_"), name.casefold().replace("-", ".")}
    suffixes = tuple(suffix.casefold() for suffix in ARCHIVE_SUFFIXES)
    for package_name in package_names:
        prefix = f"{package_name}-{version.casefold()}"
        if filename == prefix or any(filename == prefix + suffix for suffix in suffixes):
            return True
        if any(filename.startswith(prefix + separator) for separator in ("-", "_")):
            return True
    return False


def verify_mirror_artifacts(
    mirror_root: Path,
    *,
    entries: Mapping[str, tuple[str, tuple[str, ...]]],
) -> tuple[str, ...]:
    """Verify that every locked package has a hash-matching local artefact."""

    try:
        archives = tuple(_iter_archives(mirror_root))
    except OSError as exc:
        return (f"mirror_read_failed:{exc}",)
    errors: list[str] = []
    for name, (version, hashes) in sorted(entries.items()):
        candidates = [path for path in archives if _artifact_matches(path, name, version)]
        if not candidates:
            errors.append(f"mirror_artifact_missing:{name}=={version}")
            continue
        matched = False
        for path in candidates:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest in hashes:
                matched = True
                break
        if not matched:
            errors.append(f"mirror_artifact_hash_mismatch:{name}=={version}")
    return tuple(errors)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", required=True, help="deployment-supplied hash-pinned lock")
    parser.add_argument("--artifact-dir", help="optional local package mirror to verify")
    args = parser.parse_args(argv)
    lock_path = Path(args.lock)
    errors = list(verify_hash_pinned_lock(lock_path))
    if not errors and args.artifact_dir:
        try:
            entries = read_hash_pinned_lock(lock_path)
        except (OSError, SupplyChainError) as exc:
            errors.append(str(exc))
        else:
            errors.extend(verify_mirror_artifacts(Path(args.artifact_dir), entries=entries))
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(f"hash-pinned supply chain verified: {len(read_hash_pinned_lock(lock_path))} packages")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
