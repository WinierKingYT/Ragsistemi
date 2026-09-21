"""Structural checks for the documentation authority and D2 schema registry."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import sha256_bytes, sha256_json
from .schema import SchemaRegistry, SchemaValidationError


@dataclass(frozen=True)
class IntegrityReport:
    json_files: int
    schema_files: int
    parse_errors: tuple[str, ...]
    duplicate_schema_ids: tuple[str, ...]
    missing_registry_files: tuple[str, ...]
    id_mismatches: tuple[str, ...]
    unresolved_refs: tuple[str, ...]
    scenario_count: int
    required_r_fc_classes: int
    schema_backend: str

    @property
    def ok(self) -> bool:
        return not any(
            (
                self.parse_errors,
                self.duplicate_schema_ids,
                self.missing_registry_files,
                self.id_mismatches,
                self.unresolved_refs,
                self.schema_backend != "standards",
            )
        )

    def structured(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "json_files": self.json_files,
            "schema_files": self.schema_files,
            "parse_errors": list(self.parse_errors),
            "duplicate_schema_ids": list(self.duplicate_schema_ids),
            "missing_registry_files": list(self.missing_registry_files),
            "id_mismatches": list(self.id_mismatches),
            "unresolved_refs": list(self.unresolved_refs),
            "scenario_count": self.scenario_count,
            "required_r_fc_classes": self.required_r_fc_classes,
            "schema_backend": self.schema_backend,
        }


def _walk(value: Any):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key, child
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _pointer(document: Any, fragment: str) -> bool:
    if not fragment:
        return True
    if not fragment.startswith("#/"):
        return False
    current = document
    for raw_part in fragment[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return False
    return True


def validate_documentation_bundle(project_root: str | Path) -> IntegrityReport:
    root = Path(project_root).resolve() / "PMIRI_ALL_DOCUMENTATION_CHECKPOINT_17"
    json_paths = sorted(root.rglob("*.json"))
    parsed: dict[Path, Any] = {}
    parse_errors: list[str] = []
    for path in json_paths:
        try:
            parsed[path] = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            parse_errors.append(path.relative_to(root).as_posix())

    schemas = {path: value for path, value in parsed.items() if path.name.endswith(".schema.json")}
    by_id: dict[str, list[Path]] = {}
    for path, value in schemas.items():
        if isinstance(value, dict) and isinstance(value.get("$id"), str):
            by_id.setdefault(value["$id"], []).append(path)
    duplicate_ids = sorted(identifier for identifier, paths in by_id.items() if len(paths) != 1)

    registry_path = root / "GATE-D-R2" / "PMIRI_GD-R2_SCHEMA_RESOURCE_REGISTRY_v0.1.json"
    missing: list[str] = []
    mismatches: list[str] = []
    unresolved: list[str] = []
    registry: dict[str, Path] = {}
    registry_value = parsed.get(registry_path, {})
    for resource in registry_value.get("resources", []) if isinstance(registry_value, dict) else []:
        uri, filename = resource.get("uri"), resource.get("file")
        if not isinstance(uri, str) or not isinstance(filename, str):
            continue
        target = registry_path.parent / filename
        registry[uri] = target
        if not target.exists():
            missing.append(filename)
        elif parsed.get(target, {}).get("$id") != uri:
            mismatches.append(filename)

    for path, document in schemas.items():
        # GC-C1 schemas predate the D2 absolute-URI registry and legitimately
        # use same-document fragments. The registry rule applies to D2 only.
        if path.parent.name != "GATE-D-R2":
            continue
        for key, value in _walk(document):
            if key != "$ref" or not isinstance(value, str):
                continue
            if not value.startswith("pmiri://"):
                unresolved.append(f"{path.name}:{value}")
                continue
            base, _, fragment = value.partition("#")
            target = registry.get(base)
            if target is None or target not in parsed or not _pointer(parsed[target], "#" + fragment if fragment else ""):
                unresolved.append(f"{path.name}:{value}")

    matrix_path = root / "GATE-D-R2" / "PMIRI_GD-R2-05_ADVERSARIAL_SCENARIO_MATRIX.json"
    matrix = parsed.get(matrix_path, {})
    scenarios = matrix.get("scenarios", []) if isinstance(matrix, dict) else []
    coverage = matrix.get("coverage_requirements", []) if isinstance(matrix, dict) else []
    try:
        schema_backend = SchemaRegistry(project_root).backend
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, SchemaValidationError, ValueError):
        schema_backend = "UNAVAILABLE"
    return IntegrityReport(
        json_files=len(json_paths),
        schema_files=len(schemas),
        parse_errors=tuple(sorted(parse_errors)),
        duplicate_schema_ids=tuple(duplicate_ids),
        missing_registry_files=tuple(sorted(missing)),
        id_mismatches=tuple(sorted(mismatches)),
        unresolved_refs=tuple(sorted(unresolved)),
        scenario_count=len(scenarios),
        required_r_fc_classes=len(coverage),
        schema_backend=schema_backend,
    )


def authority_fingerprint(project_root: str | Path) -> str:
    """Fingerprint the current archive inventory, excluding generated output."""
    root = Path(project_root).resolve() / "PMIRI_ALL_DOCUMENTATION_CHECKPOINT_17"
    entries = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            entries.append({"path": path.relative_to(root).as_posix(), "sha256": sha256_bytes(path.read_bytes())})
    return sha256_json(entries)
