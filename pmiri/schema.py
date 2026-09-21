"""Schema registry with a standards-complete Draft 2020-12 backend.

The default backend uses the installed ``jsonschema`` implementation and a
custom PMIRI URI resolver.  The older dependency-free validator remains
available only with ``backend="subset"`` for constrained compatibility
environments; it is never selected silently for production validation.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


class SchemaValidationError(ValueError):
    pass


@dataclass(frozen=True)
class ValidationIssue:
    path: str
    message: str


class SchemaRegistry:
    def __init__(self, project_root: str | Path, *, backend: str = "standards"):
        if backend not in {"standards", "subset"}:
            raise ValueError("schema_backend_invalid")
        self.backend = backend
        self._standards_validator = None
        self._standards_registry = None
        self._format_checker = None
        if backend == "standards":
            try:
                from jsonschema import Draft202012Validator, FormatChecker
            except ImportError as exc:
                raise SchemaValidationError("standards_validator_unavailable") from exc
            self._standards_validator = Draft202012Validator
            self._format_checker = FormatChecker()
        self.root = Path(project_root).resolve() / "PMIRI_ALL_DOCUMENTATION_CHECKPOINT_17"
        self.directory = self.root / "GATE-D-R2"
        registry_path = self.directory / "PMIRI_GD-R2_SCHEMA_RESOURCE_REGISTRY_v0.1.json"
        self.registry = json.loads(registry_path.read_text(encoding="utf-8"))
        self.resources: dict[str, tuple[Path, dict[str, Any]]] = {}
        for item in self.registry.get("resources", []):
            uri, filename = item["uri"], item["file"]
            path = self.directory / filename
            document = json.loads(path.read_text(encoding="utf-8"))
            if document.get("$id") != uri:
                raise SchemaValidationError(f"schema_id_mismatch:{filename}")
            self.resources[uri] = (path, document)
        if backend == "standards":
            from referencing import Registry, Resource
            from referencing.jsonschema import DRAFT202012

            self._standards_registry = Registry().with_resources(
                (uri, Resource.from_contents(document, default_specification=DRAFT202012))
                for uri, (_, document) in self.resources.items()
            )

    def resolve(self, reference: str, current: dict[str, Any] | None = None) -> Any:
        if reference.startswith("#"):
            if current is None:
                raise SchemaValidationError("local_ref_without_schema")
            return _resolve_pointer(current, reference)
        if not reference.startswith("pmiri://"):
            raise SchemaValidationError(f"relative_ref_forbidden:{reference}")
        base, _, fragment = reference.partition("#")
        if base not in self.resources:
            raise SchemaValidationError(f"unknown_schema_ref:{base}")
        document = self.resources[base][1]
        return _resolve_pointer(document, "#" + fragment if fragment else "#")

    def validate(self, instance: Any, schema_ref: str) -> tuple[ValidationIssue, ...]:
        schema = self.resolve(schema_ref)
        if self.backend == "standards":
            validator = self._standards_validator(schema, registry=self._standards_registry, format_checker=self._format_checker)
            errors = sorted(validator.iter_errors(instance), key=lambda error: list(error.absolute_path))
            return tuple(ValidationIssue(_error_path(error.absolute_path), error.message) for error in errors)
        issues: list[ValidationIssue] = []
        self._validate(instance, schema, "$", issues, schema)
        return tuple(issues)

    def require_valid(self, instance: Any, schema_ref: str) -> None:
        issues = self.validate(instance, schema_ref)
        if issues:
            first = issues[0]
            raise SchemaValidationError(f"{first.path}:{first.message}")

    def _validate(self, value: Any, schema: Any, path: str, issues: list[ValidationIssue], document: dict[str, Any]) -> None:
        if not isinstance(schema, dict):
            issues.append(ValidationIssue(path, "schema_not_object"))
            return
        if "$ref" in schema:
            try:
                target = self.resolve(schema["$ref"], document)
            except SchemaValidationError as exc:
                issues.append(ValidationIssue(path, str(exc)))
                return
            self._validate(value, target, path, issues, target if isinstance(target, dict) else document)
            return
        if "not" in schema:
            inverse: list[ValidationIssue] = []
            self._validate(value, schema["not"], path, inverse, document)
            if not inverse:
                issues.append(ValidationIssue(path, "not_failed"))
        if "allOf" in schema:
            for part in schema["allOf"]:
                self._validate(value, part, path, issues, document)
        for keyword in ("anyOf", "oneOf"):
            if keyword in schema:
                branches = []
                for part in schema[keyword]:
                    branch_issues: list[ValidationIssue] = []
                    self._validate(value, part, path, branch_issues, document)
                    if not branch_issues:
                        branches.append(part)
                valid = len(branches) >= 1 if keyword == "anyOf" else len(branches) == 1
                if not valid:
                    issues.append(ValidationIssue(path, f"{keyword}_failed"))
        if "const" in schema and value != schema["const"]:
            issues.append(ValidationIssue(path, "const_mismatch"))
        if "enum" in schema and value not in schema["enum"]:
            issues.append(ValidationIssue(path, "enum_mismatch"))
        if "type" in schema:
            types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
            if not any(_type_matches(value, item) for item in types):
                issues.append(ValidationIssue(path, "type_mismatch"))
                return
        if "if" in schema:
            condition_issues: list[ValidationIssue] = []
            self._validate(value, schema["if"], path, condition_issues, document)
            branch = schema.get("then") if not condition_issues else schema.get("else")
            if branch is not None:
                self._validate(value, branch, path, issues, document)
        if isinstance(value, dict):
            for required in schema.get("required", []):
                if required not in value:
                    issues.append(ValidationIssue(path, f"required:{required}"))
            if "minProperties" in schema and len(value) < schema["minProperties"]:
                issues.append(ValidationIssue(path, "min_properties"))
            if "maxProperties" in schema and len(value) > schema["maxProperties"]:
                issues.append(ValidationIssue(path, "max_properties"))
            properties = schema.get("properties", {})
            for key, child in value.items():
                if key in properties:
                    self._validate(child, properties[key], f"{path}.{key}", issues, document)
                elif schema.get("additionalProperties") is False:
                    issues.append(ValidationIssue(path, f"additional_property:{key}"))
                elif isinstance(schema.get("additionalProperties"), dict):
                    self._validate(child, schema["additionalProperties"], f"{path}.{key}", issues, document)
            for dependent, required in schema.get("dependentRequired", {}).items():
                if dependent in value:
                    for field in required:
                        if field not in value:
                            issues.append(ValidationIssue(path, f"dependent_required:{dependent}:{field}"))
        elif isinstance(value, list):
            if "minItems" in schema and len(value) < schema["minItems"]:
                issues.append(ValidationIssue(path, "min_items"))
            if "maxItems" in schema and len(value) > schema["maxItems"]:
                issues.append(ValidationIssue(path, "max_items"))
            if schema.get("uniqueItems"):
                encoded = [json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")) for item in value]
                if len(encoded) != len(set(encoded)):
                    issues.append(ValidationIssue(path, "unique_items"))
            if "contains" in schema and not any(not self._branch_issues(item, schema["contains"], document) for item in value):
                issues.append(ValidationIssue(path, "contains_failed"))
            if "items" in schema:
                for index, child in enumerate(value):
                    self._validate(child, schema["items"], f"{path}[{index}]", issues, document)
        elif isinstance(value, str):
            if "minLength" in schema and len(value) < schema["minLength"]:
                issues.append(ValidationIssue(path, "min_length"))
            if "maxLength" in schema and len(value) > schema["maxLength"]:
                issues.append(ValidationIssue(path, "max_length"))
            if "pattern" in schema and not re.search(schema["pattern"], value):
                issues.append(ValidationIssue(path, "pattern_mismatch"))
            if schema.get("format") == "date-time":
                try:
                    timestamp = value[:-1] + "+00:00" if value.endswith("Z") else value
                    parsed = datetime.fromisoformat(timestamp)
                    if parsed.tzinfo is None:
                        raise ValueError
                except ValueError:
                    issues.append(ValidationIssue(path, "date_time_invalid"))
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if "minimum" in schema and value < schema["minimum"]:
                issues.append(ValidationIssue(path, "minimum"))
            if "maximum" in schema and value > schema["maximum"]:
                issues.append(ValidationIssue(path, "maximum"))
            if "exclusiveMinimum" in schema and value <= schema["exclusiveMinimum"]:
                issues.append(ValidationIssue(path, "exclusive_minimum"))
            if "exclusiveMaximum" in schema and value >= schema["exclusiveMaximum"]:
                issues.append(ValidationIssue(path, "exclusive_maximum"))

    def _branch_issues(self, value: Any, schema: Any, document: dict[str, Any]) -> tuple[ValidationIssue, ...]:
        issues: list[ValidationIssue] = []
        self._validate(value, schema, "$", issues, document)
        return tuple(issues)


def _type_matches(value: Any, type_name: str) -> bool:
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }.get(type_name, False)


def _error_path(path: Any) -> str:
    rendered = "$"
    for segment in path:
        if isinstance(segment, int):
            rendered += f"[{segment}]"
        elif isinstance(segment, str) and segment.isidentifier():
            rendered += "." + segment
        else:
            rendered += "[" + repr(segment) + "]"
    return rendered


def _resolve_pointer(document: Any, reference: str) -> Any:
    if reference in {"", "#"}:
        return document
    if not reference.startswith("#/"):
        raise SchemaValidationError(f"invalid_json_pointer:{reference}")
    current = document
    for raw in reference[2:].split("/"):
        key = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and key in current:
            current = current[key]
        elif isinstance(current, list) and key.isdigit() and int(key) < len(current):
            current = current[int(key)]
        else:
            raise SchemaValidationError(f"unresolved_json_pointer:{reference}")
    return current
