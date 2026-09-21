"""Documentary D2 matrix harness.

The harness validates every scenario and returns its declared expected outcome
with runtime status preserved as BLOCKED. It is intentionally not a substitute
for a clean-room provider/network replay.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .schema import SchemaRegistry


def validate_d2_matrix(project_root: str | Path) -> dict[str, Any]:
    registry = SchemaRegistry(project_root)
    matrix_path = registry.root / "GATE-D-R2" / "PMIRI_GD-R2-05_ADVERSARIAL_SCENARIO_MATRIX.json"
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    scenarios = matrix.get("scenarios", [])
    cases: list[dict[str, Any]] = []
    for scenario in scenarios:
        scenario_id = scenario.get("id")
        expected = scenario.get("expected")
        errors = []
        if not isinstance(scenario_id, str) or not scenario_id:
            errors.append("scenario_id_missing")
        if scenario.get("type") not in {"positive", "adversarial"}:
            errors.append("scenario_type_invalid")
        if not isinstance(scenario.get("area"), str) or not scenario.get("area"):
            errors.append("scenario_area_missing")
        try:
            registry.require_valid(expected, "pmiri://schema/gate-d-r2/expected-outcome/0.3")
        except ValueError as exc:
            errors.append(str(exc))
        if not isinstance(expected, dict) or expected.get("runtime_status") != "BLOCKED":
            errors.append("runtime_status_must_remain_blocked")
        cases.append({"scenario_id": scenario_id, "status": "DOCUMENTARY_VALIDATED" if not errors else "DOCUMENTARY_INVALID", "errors": errors, "expected": expected})
    classes = matrix.get("coverage_requirements", [])
    valid = len(cases) == 34 and len(classes) == 17 and all(case["status"] == "DOCUMENTARY_VALIDATED" for case in cases)
    return {"status": "D2_DOCUMENTARY_VALIDATED_RUNTIME_BLOCKED" if valid else "D2_DOCUMENTARY_INVALID", "runtime_execution": "NOT_PERFORMED", "scenario_count": len(cases), "coverage_class_count": len(classes), "cases": cases}
