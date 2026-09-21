"""Verify PMIRI's declared dependency contract and optional environment.

The check is intentionally stdlib-only so it can run before PMIRI is
installed. ``--check-installed`` is the stronger CI gate: it detects a
missing package (including a dependency that the current test paths did not
exercise) or a version drift from ``requirements.lock``.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import re
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "requirements.lock"
PYPROJECT_PATH = ROOT / "pyproject.toml"
NAME_PATTERN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==([0-9][A-Za-z0-9.+-]*)$")
DEPENDENCY_PATTERN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)(.*)$")


class ReproducibilityError(ValueError):
    """Raised when the dependency contract is inconsistent."""


def canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def read_lock() -> dict[str, str]:
    locked: dict[str, str] = {}
    for line_number, raw_line in enumerate(LOCK_PATH.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = NAME_PATTERN.fullmatch(line)
        if match is None:
            raise ReproducibilityError(f"invalid_lock_line:{line_number}")
        name, version = match.groups()
        key = canonical_name(name)
        if key in locked:
            raise ReproducibilityError(f"duplicate_lock_package:{name}")
        locked[key] = version
    if not locked:
        raise ReproducibilityError("lock_is_empty")
    return locked


def read_project_dependencies() -> dict[str, str]:
    document = tomllib.loads(PYPROJECT_PATH.read_text(encoding="utf-8"))
    dependencies = list(document.get("project", {}).get("dependencies", []))
    dependencies.extend(document.get("build-system", {}).get("requires", []))
    if not isinstance(dependencies, list) or not dependencies:
        raise ReproducibilityError("project_dependencies_missing")
    parsed: dict[str, str] = {}
    for item in dependencies:
        if not isinstance(item, str):
            raise ReproducibilityError("project_dependency_invalid")
        match = DEPENDENCY_PATTERN.fullmatch(item.strip())
        if match is None:
            raise ReproducibilityError(f"project_dependency_invalid:{item}")
        name, specifier = match.groups()
        parsed[canonical_name(name)] = specifier
    return parsed


def version_tuple(value: str) -> tuple[int, ...]:
    match = re.match(r"^(\d+(?:\.\d+)*)", value)
    if match is None:
        raise ReproducibilityError(f"version_not_numeric:{value}")
    return tuple(int(part) for part in match.group(1).split("."))


def satisfies(version: str, specifier: str) -> bool:
    candidate = version_tuple(version)
    for operator, value in re.findall(r"(>=|<=|==|!=|>|<)\s*(\d+(?:\.\d+)*)", specifier):
        expected = version_tuple(value)
        if operator == ">=" and not candidate >= expected:
            return False
        if operator == "<=" and not candidate <= expected:
            return False
        if operator == "==" and not candidate == expected:
            return False
        if operator == "!=" and candidate == expected:
            return False
        if operator == ">" and not candidate > expected:
            return False
        if operator == "<" and not candidate < expected:
            return False
    return True


def verify_project_contract(locked: dict[str, str]) -> list[str]:
    dependencies = read_project_dependencies()
    errors: list[str] = []
    for name, specifier in dependencies.items():
        version = locked.get(name)
        if version is None:
            errors.append(f"direct_dependency_not_locked:{name}")
        elif not satisfies(version, specifier):
            errors.append(f"locked_version_outside_project_spec:{name}=={version}{specifier}")
    if not errors:
        print(f"project/build contract verified: {len(dependencies)} requirements, {len(locked)} locked packages")
    return errors


def verify_installed(locked: dict[str, str], *, announce: bool = True) -> list[str]:
    errors: list[str] = []
    for name, expected in sorted(locked.items()):
        try:
            actual = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            errors.append(f"package_missing:{name}=={expected}")
            continue
        if actual != expected:
            errors.append(f"package_version_drift:{name}=={actual};expected=={expected}")
    if not errors and announce:
        print(f"installed environment verified: {len(locked)} locked packages")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-installed", action="store_true")
    args = parser.parse_args(argv)
    try:
        locked = read_lock()
        errors = verify_project_contract(locked)
        if args.check_installed:
            errors.extend(verify_installed(locked))
    except (OSError, tomllib.TOMLDecodeError, ReproducibilityError) as exc:
        print(f"reproducibility verification failed: {exc}", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
