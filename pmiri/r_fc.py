"""Truthful Gate-C R-FC inventory and attested candidate replay orchestration.

The default inventory is explicitly blocked. The candidate runner can execute
declared handlers only after per-case external attestation, exact fingerprints,
a digest-bound handler-module manifest and reviewer separation are supplied;
it records evidence but never assigns ``PASS``.
"""

from __future__ import annotations

import json
import inspect
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .attestation import load_attestation
from .canonical import canonical_json, is_sha256, sha256_bytes, sha256_json, utc_now
from .clean_room import IsolationObservation
from .controlled_replay import ReplaySessionResult, run_controlled_case
from .evidence import RF_CHECKS, create_evidence_record, validate_evidence_record
from .integrity import authority_fingerprint
from .preflight import validate_preflight_record_shape
from .replay import RUNNER_ID, RUNNER_VERSION


BLOCK_REASON = "clean_room_attestation_and_independent_review_absent"
CATALOG_PATH = Path("PMIRI_ALL_DOCUMENTATION_CHECKPOINT_17/GC-C1/PMIRI_GC-C1-02_REPLAY_FIXTURE_CATALOG.json")
REPLAY_FINGERPRINTS = (
    "runner_source",
    "runner_manifest",
    "authority_bundle",
    "evidence_schema",
    "fixture_catalog",
    "preflight_matrix",
    "preflight_record_schema",
)

CaseHandler = Callable[[Path, Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]]

HANDLER_MANIFEST_KIND = "PMIRI-GC-C1-R-FC-HANDLER-MANIFEST"
HANDLER_MANIFEST_VERSION = "0.1"


def _handler_source(handler: CaseHandler) -> tuple[str, Path, str]:
    module_id = getattr(handler, "__module__", None)
    qualified_name = getattr(handler, "__qualname__", None)
    if not isinstance(module_id, str) or not module_id:
        raise ValueError("handler_module_id_missing")
    if not isinstance(qualified_name, str) or not qualified_name:
        raise ValueError("handler_qualified_name_missing")
    try:
        source_name = inspect.getsourcefile(handler) or inspect.getfile(handler)
    except (OSError, TypeError) as exc:
        raise ValueError("handler_source_unavailable") from exc
    source_path = Path(source_name).resolve()
    if source_path.suffix.casefold() != ".py" or not source_path.is_file():
        raise ValueError("handler_source_not_python")
    return module_id, source_path, module_id + ":" + qualified_name


def _manifest_source_path(root: Path, source_path: Path) -> str:
    try:
        return source_path.relative_to(root).as_posix()
    except ValueError:
        return source_path.as_posix()


def create_handler_manifest(
    project_root: str | Path,
    *,
    case_handlers: Mapping[str, CaseHandler],
    case_ids: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Create a digest-bound manifest for one pinned handler module.

    The manifest binds every supplied case handler to one Python module and
    one source file. It does not authorize replay; the external attestation
    and independent review boundaries remain mandatory.
    """
    root = Path(project_root).resolve()
    selected = sorted(str(case_id) for case_id in (case_ids if case_ids is not None else case_handlers))
    if not selected or len(set(selected)) != len(selected):
        raise ValueError("handler_case_ids_invalid")
    if set(case_handlers) != set(selected):
        raise ValueError("handler_case_mapping_mismatch")
    descriptors = [_handler_source(case_handlers[case_id]) for case_id in selected]
    modules = {item[0] for item in descriptors}
    sources = {item[1] for item in descriptors}
    if len(modules) != 1:
        raise ValueError("handler_module_mismatch")
    if len(sources) != 1:
        raise ValueError("handler_source_file_mismatch")
    module_id = next(iter(modules))
    source_path = next(iter(sources))
    unsigned: dict[str, Any] = {
        "artifact_kind": HANDLER_MANIFEST_KIND,
        "version": HANDLER_MANIFEST_VERSION,
        "status": "READY_FOR_REPLAY",
        "module": {
            "module_id": module_id,
            "entrypoint": "HANDLERS",
            "source_path": _manifest_source_path(root, source_path),
            "source_fingerprint": sha256_bytes(source_path.read_bytes()),
        },
        "case_ids": selected,
        "handlers": {case_id: descriptors[index][2] for index, case_id in enumerate(selected)},
    }
    unsigned["handler_manifest_sha256"] = sha256_json(unsigned)
    return unsigned


def load_handler_manifest(path: str | Path) -> dict[str, Any]:
    """Load and verify a digest-bound handler manifest."""
    source = Path(path)
    try:
        manifest = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("handler_manifest_missing_or_invalid_json") from exc
    if not isinstance(manifest, dict):
        raise ValueError("handler_manifest_shape_invalid")
    required = {"artifact_kind", "version", "status", "module", "case_ids", "handlers", "handler_manifest_sha256"}
    if set(manifest) != required:
        raise ValueError("handler_manifest_fields_invalid")
    claimed = manifest.get("handler_manifest_sha256")
    unsigned = {key: value for key, value in manifest.items() if key != "handler_manifest_sha256"}
    if not is_sha256(claimed) or claimed != sha256_json(unsigned):
        raise ValueError("handler_manifest_digest_mismatch")
    if manifest.get("artifact_kind") != HANDLER_MANIFEST_KIND or manifest.get("version") != HANDLER_MANIFEST_VERSION:
        raise ValueError("handler_manifest_identity_invalid")
    if manifest.get("status") != "READY_FOR_REPLAY":
        raise ValueError("handler_manifest_not_ready")
    module = manifest.get("module")
    case_ids = manifest.get("case_ids")
    handlers = manifest.get("handlers")
    if not isinstance(module, dict) or set(module) != {"module_id", "entrypoint", "source_path", "source_fingerprint"}:
        raise ValueError("handler_manifest_module_invalid")
    if module.get("entrypoint") != "HANDLERS" or not isinstance(module.get("module_id"), str) or not module.get("module_id"):
        raise ValueError("handler_manifest_module_invalid")
    if not isinstance(module.get("source_path"), str) or not module.get("source_path") or not is_sha256(module.get("source_fingerprint")):
        raise ValueError("handler_manifest_source_invalid")
    if not isinstance(case_ids, list) or not case_ids or any(not isinstance(case_id, str) or not case_id for case_id in case_ids):
        raise ValueError("handler_manifest_cases_invalid")
    if len(set(case_ids)) != len(case_ids) or case_ids != sorted(case_ids):
        raise ValueError("handler_manifest_cases_not_canonical")
    if not isinstance(handlers, dict) or set(handlers) != set(case_ids) or any(not isinstance(value, str) or not value for value in handlers.values()):
        raise ValueError("handler_manifest_handlers_invalid")
    return manifest


def write_handler_manifest(manifest: Mapping[str, Any], path: str | Path) -> None:
    """Write a handler manifest after verifying its self-digest and shape."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Reuse the loader's strict checks without requiring a temporary file.
    claimed = manifest.get("handler_manifest_sha256")
    unsigned = {key: value for key, value in manifest.items() if key != "handler_manifest_sha256"}
    if not is_sha256(claimed) or claimed != sha256_json(unsigned):
        raise ValueError("handler_manifest_digest_mismatch")
    destination.write_text(json.dumps(dict(manifest), ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _validate_handler_contract(
    root: Path,
    *,
    manifest: Mapping[str, Any] | None,
    case_handlers: Mapping[str, CaseHandler] | None,
    selected_ids: Sequence[str],
) -> str | None:
    if manifest is None:
        return "handler_manifest_absent"
    try:
        required = {"artifact_kind", "version", "status", "module", "case_ids", "handlers", "handler_manifest_sha256"}
        if set(manifest) != required:
            return "handler_manifest_fields_invalid"
        claimed = manifest.get("handler_manifest_sha256")
        unsigned = {key: value for key, value in manifest.items() if key != "handler_manifest_sha256"}
        if not is_sha256(claimed) or claimed != sha256_json(unsigned):
            return "handler_manifest_digest_mismatch"
        module = manifest.get("module")
        manifest_ids = manifest.get("case_ids")
        symbols = manifest.get("handlers")
        if manifest.get("artifact_kind") != HANDLER_MANIFEST_KIND or manifest.get("version") != HANDLER_MANIFEST_VERSION or manifest.get("status") != "READY_FOR_REPLAY":
            return "handler_manifest_identity_invalid"
        if not isinstance(module, Mapping) or module.get("entrypoint") != "HANDLERS":
            return "handler_manifest_module_invalid"
        if not isinstance(manifest_ids, list) or manifest_ids != sorted(set(manifest_ids)) or not isinstance(symbols, Mapping) or set(symbols) != set(manifest_ids):
            return "handler_manifest_cases_invalid"
        if not set(selected_ids).issubset(set(manifest_ids)):
            return "handler_manifest_case_missing"
        handlers = case_handlers or {}
        if any(case_id not in handlers for case_id in selected_ids):
            return "case_handler_missing"
        if any(case_id not in manifest_ids for case_id in handlers):
            return "handler_case_not_declared"
        module_id = module.get("module_id")
        declared_source = module.get("source_path")
        declared_fingerprint = module.get("source_fingerprint")
        if not isinstance(module_id, str) or not module_id or not isinstance(declared_source, str) or not declared_source or not is_sha256(declared_fingerprint):
            return "handler_manifest_source_invalid"
        descriptors = {case_id: _handler_source(handlers[case_id]) for case_id in handlers}
        if any(not callable(handlers[case_id]) for case_id in handlers):
            return "case_handler_not_callable"
        if any(descriptor[0] != module_id for descriptor in descriptors.values()):
            return "handler_module_mismatch"
        source_paths = {descriptor[1] for descriptor in descriptors.values()}
        if len(source_paths) != 1:
            return "handler_source_file_mismatch"
        source_path = next(iter(source_paths))
        declared_path = Path(declared_source)
        if not declared_path.is_absolute():
            declared_path = root / declared_path
        if declared_path.resolve() != source_path:
            return "handler_source_path_mismatch"
        if sha256_bytes(source_path.read_bytes()) != declared_fingerprint:
            return "handler_source_fingerprint_mismatch"
        for case_id, descriptor in descriptors.items():
            if symbols.get(case_id) != descriptor[2]:
                return "handler_symbol_mismatch:" + case_id
    except (OSError, TypeError, ValueError):
        return "handler_manifest_validation_error"
    return None


def _load_catalog(root: Path) -> dict[str, Any]:
    source = root / CATALOG_PATH
    try:
        catalog = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("r_fc_fixture_catalog_invalid") from exc
    if not isinstance(catalog, dict) or not isinstance(catalog.get("fixtures"), list):
        raise ValueError("r_fc_fixture_catalog_shape_invalid")
    fixtures = catalog["fixtures"]
    if len(fixtures) != 17:
        raise ValueError("r_fc_fixture_catalog_count_invalid")
    checks: set[str] = set()
    case_ids: set[str] = set()
    for fixture in fixtures:
        if not isinstance(fixture, dict) or fixture.get("check_id") not in RF_CHECKS or fixture.get("check_id") in checks:
            raise ValueError("r_fc_fixture_invalid")
        checks.add(str(fixture["check_id"]))
        declared_cases = fixture.get("cases")
        if not isinstance(declared_cases, list) or not declared_cases:
            raise ValueError("r_fc_fixture_cases_invalid")
        for declared_case in declared_cases:
            if not isinstance(declared_case, dict) or not isinstance(declared_case.get("case_id"), str) or declared_case["case_id"] in case_ids:
                raise ValueError("r_fc_case_invalid")
            oracle = declared_case.get("oracle")
            if not isinstance(oracle, dict) or not isinstance(oracle.get("expected_dispositions"), list) or not oracle["expected_dispositions"]:
                raise ValueError("r_fc_case_oracle_invalid")
            case_ids.add(declared_case["case_id"])
    if checks != RF_CHECKS or len(case_ids) != 34:
        raise ValueError("r_fc_fixture_coverage_invalid")
    return catalog


def _expected(case: Mapping[str, Any]) -> tuple[list[str], list[str]]:
    oracle = case.get("oracle", {})
    return list(oracle.get("expected_dispositions", [])), list(oracle.get("forbidden_dispositions", []))


def _blocked_case_evidence(
    *,
    check_id: str,
    case: Mapping[str, Any],
    reason: str,
    authority_fp: str,
) -> tuple[dict[str, Any], list[str]]:
    case_id = str(case["case_id"])
    expected, forbidden = _expected(case)
    input_fingerprint = sha256_json({"fixture_id": case_id, "case": dict(case), "reason": reason})
    record = create_evidence_record(
        check_id=check_id,
        fixture_id=case_id,
        input_fingerprint=input_fingerprint,
        expected_dispositions=expected,
        forbidden_dispositions=forbidden,
        actual={"disposition": "BLOCKED", "notes": reason},
        invariants=[str(case.get("invariant", ""))] if case.get("invariant") else None,
        authority_refs=["authority://gc-c1-evidence-matrix", "sha256://" + authority_fp],
        action_trace=[
            {
                "step": 1,
                "operation": "controlled_replay_gate",
                "input_ref": "fixture://" + case_id,
                "state_change_or_fault": reason,
            }
        ],
        lineage={
            "authorization_lineage_ref": "lineage://not-executed/" + case_id.lower(),
            "evidence_refs": ["evidence://not-executed/" + case_id.lower()],
            "citation_refs": [],
            "boundary_refs": ["boundary://gc-c1-clean-room"],
        },
        replay={
            "runner_id": "runner://" + RUNNER_ID,
            "runner_version": "runner-version://" + RUNNER_VERSION,
            "command_or_workflow_ref": "workflow://r-fc-not-executed/" + case_id,
            "environment_fingerprint": sha256_json({"environment": "UNVERIFIED", "case_id": case_id}),
        },
        review={
            "primary_reviewer": "reviewer://not-supplied",
            "independent_reviewer": "reviewer://not-supplied",
            "review_result": "blocked",
            "review_evidence_ref": "review://not-supplied",
        },
        status="BLOCKED",
    )
    structured = record.structured()
    return structured, list(validate_evidence_record(structured))


def _case_attestation(
    *,
    case_id: str,
    attestation_paths: Mapping[str, str | Path] | None,
    fingerprints: Mapping[str, object],
) -> tuple[dict[str, Any] | None, Mapping[str, IsolationObservation] | None, str | None]:
    if not attestation_paths or case_id not in attestation_paths:
        return None, None, "clean_room_attestation_absent"
    try:
        record, observations = load_attestation(attestation_paths[case_id])
    except (OSError, ValueError, TypeError, KeyError) as exc:
        return None, None, "attestation_invalid:" + type(exc).__name__ + ":" + str(exc)
    if record.get("status") != "VERIFIED" or record.get("outcome") != "READY_FOR_REPLAY":
        return None, None, "attestation_not_verified"
    if record.get("case", {}).get("case_id") != case_id:
        return None, None, "attestation_case_mismatch"
    attested = record.get("fingerprints", {})
    for name in REPLAY_FINGERPRINTS[:-1]:
        if attested.get(name) != fingerprints.get(name):
            return None, None, "attestation_fingerprint_mismatch:" + name
    return record, observations, None


def _case_preflight(
    *,
    fixture_id: str,
    case_id: str,
    preflight_paths: Mapping[str, str | Path] | None,
    fingerprints: Mapping[str, object],
) -> str | None:
    if not preflight_paths or case_id not in preflight_paths:
        return "preflight_record_absent"
    try:
        record = json.loads(Path(preflight_paths[case_id]).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return "preflight_record_invalid:" + type(exc).__name__ + ":" + str(exc)
    errors = validate_preflight_record_shape(record) if isinstance(record, Mapping) else ("record_must_be_object",)
    if errors:
        return "preflight_record_schema_invalid:" + ",".join(errors[:3])
    if record.get("overall_result") != "READY_FOR_REPLAY":
        return "preflight_not_ready"
    if record.get("selected_fixture_id") != fixture_id or record.get("selected_case_id") != case_id:
        return "preflight_case_binding_mismatch"
    if any(item.get("result") != "READY" for item in record.get("checks", [])):
        return "preflight_contains_non_ready_check"
    if record.get("runner", {}).get("source_fingerprint") != fingerprints.get("runner_source"):
        return "preflight_runner_source_fingerprint_mismatch"
    input_bindings = {
        "authority_bundle_fingerprint": "authority_bundle",
        "schema_fingerprint": "evidence_schema",
        "catalog_fingerprint": "fixture_catalog",
        "matrix_fingerprint": "preflight_matrix",
    }
    if any(record.get("inputs", {}).get(record_key) != fingerprints.get(fingerprint_key) for record_key, fingerprint_key in input_bindings.items()):
        return "preflight_input_fingerprint_mismatch"
    return None


def _lineage(output: Mapping[str, Any] | None, case_id: str) -> dict[str, Any]:
    raw = output.get("lineage", {}) if isinstance(output, Mapping) else {}
    raw = raw if isinstance(raw, Mapping) else {}
    return {
        "authorization_lineage_ref": str(raw.get("authorization_lineage_ref", "lineage://r-fc/" + case_id.lower())),
        "evidence_refs": [str(value) for value in raw.get("evidence_refs", [])] if isinstance(raw.get("evidence_refs", []), list) else [],
        "citation_refs": [str(value) for value in raw.get("citation_refs", [])] if isinstance(raw.get("citation_refs", []), list) else [],
        "boundary_refs": [str(value) for value in raw.get("boundary_refs", ["boundary://gc-c1-clean-room"])] if isinstance(raw.get("boundary_refs", ["boundary://gc-c1-clean-room"]), list) else ["boundary://gc-c1-clean-room"],
    }


def _trace(case: Mapping[str, Any], case_id: str, final_state: str) -> list[dict[str, Any]]:
    trace: list[dict[str, Any]] = []
    step = 1
    for operation, values in (("declared_setup", case.get("setup", [])), ("declared_action", case.get("actions", []))):
        for value in values if isinstance(values, list) else []:
            trace.append({"step": step, "operation": operation, "input_ref": "fixture://" + case_id, "state_change_or_fault": str(value)})
            step += 1
    trace.append({"step": step, "operation": "controlled_replay", "input_ref": "fixture://" + case_id, "state_change_or_fault": final_state})
    return trace


def run_r_fc_candidate(
    project_root: str | Path,
    *,
    identity: Mapping[str, object],
    fingerprints: Mapping[str, object],
    attestation_paths: Mapping[str, str | Path] | None,
    preflight_paths: Mapping[str, str | Path] | None,
    case_handlers: Mapping[str, CaseHandler] | None,
    handler_manifest: Mapping[str, Any] | None = None,
    operator_ref: str | None,
    independent_reviewer_ref: str | None,
    case_ids: Sequence[str] | None = None,
    persist_dir: str | Path | None = None,
    output_path: str | Path | None = None,
) -> dict[str, Any]:
    """Execute declared R-FC cases only under externally attested prerequisites.

    A handler is the implementation under test and receives only a fresh case
    root, the declared fixture and one declared positive/adversarial case. The
    runner records the observed result and oracle comparison, but never assigns
    ``PASS``; independent review must make that decision outside this process.
    """
    root = Path(project_root).resolve()
    catalog = _load_catalog(root)
    authority_fp = authority_fingerprint(root)
    all_cases = {
        str(declared_case["case_id"]): (str(fixture["check_id"]), fixture, declared_case)
        for fixture in catalog["fixtures"]
        for declared_case in fixture["cases"]
    }
    selected_ids = list(case_ids) if case_ids is not None else sorted(all_cases)
    if len(set(selected_ids)) != len(selected_ids) or any(case_id not in all_cases for case_id in selected_ids):
        raise ValueError("r_fc_case_selection_invalid")
    fingerprints_ok = all(is_sha256(fingerprints.get(name)) for name in REPLAY_FINGERPRINTS)
    reviewer_separated = bool(operator_ref and independent_reviewer_ref and operator_ref != independent_reviewer_ref)
    handler_contract_reason = _validate_handler_contract(
        root,
        manifest=handler_manifest,
        case_handlers=case_handlers,
        selected_ids=selected_ids,
    )
    cases: list[dict[str, Any]] = []
    for case_id in selected_ids:
        check_id, fixture, declared_case = all_cases[case_id]
        reason: str | None = None
        handler = case_handlers.get(case_id) if case_handlers else None
        if not fingerprints_ok:
            reason = "required_fingerprint_missing"
        elif not reviewer_separated:
            reason = "operator_independent_reviewer_separation_missing"
        elif not callable(handler):
            reason = "case_handler_missing"
        if reason is None:
            reason = _case_preflight(
                fixture_id=str(fixture["fixture_id"]),
                case_id=case_id,
                preflight_paths=preflight_paths,
                fingerprints=fingerprints,
            )
        attestation_record: dict[str, Any] | None = None
        isolation: Mapping[str, IsolationObservation] | None = None
        if reason is None:
            attestation_record, isolation, reason = _case_attestation(
                case_id=case_id,
                attestation_paths=attestation_paths,
                fingerprints=fingerprints,
            )
        if reason is None and handler_contract_reason is not None:
            reason = handler_contract_reason
        if reason is not None or handler is None or isolation is None or attestation_record is None:
            evidence, schema_errors = _blocked_case_evidence(check_id=check_id, case=declared_case, reason=reason or "replay_prerequisite_missing", authority_fp=authority_fp)
            cases.append({
                "case_id": case_id,
                "check_id": check_id,
                "case_type": declared_case.get("case_type"),
                "status": "BLOCKED",
                "executed": False,
                "block_reason": reason or "replay_prerequisite_missing",
                "oracle": dict(declared_case.get("oracle", {})),
                "oracle_match": None,
                "evidence": evidence,
                "schema_errors": schema_errors,
            })
            continue
        case_persist = Path(persist_dir).resolve() / case_id if persist_dir is not None else None
        session: ReplaySessionResult = run_controlled_case(
            case_id=case_id,
            identity=identity,
            isolation=isolation,
            fingerprints=fingerprints,
            inputs={"fixture.json": canonical_json({"fixture": fixture, "case": declared_case}) + b"\n"},
            case=lambda case_root, handler=handler, fixture=fixture, declared_case=declared_case: handler(case_root, fixture, declared_case),
            persist_dir=case_persist,
        )
        replay_output = session.replay.output if isinstance(session.replay.output, Mapping) else None
        disposition = session.replay.disposition
        expected, forbidden = _expected(declared_case)
        oracle_match = session.status == "RECORDED" and disposition in expected and disposition not in forbidden
        output_fingerprint = session.output_fingerprint or sha256_json(session.structured())
        evidence = create_evidence_record(
            check_id=check_id,
            fixture_id=case_id,
            input_fingerprint=sha256_json({"fixture": fixture, "case": declared_case}),
            expected_dispositions=expected,
            forbidden_dispositions=forbidden,
            actual={
                "disposition": disposition,
                "output_artifact_ref": "artifact://r-fc/" + case_id + "/outputs/result.json",
                "output_fingerprint": output_fingerprint,
                "handler_manifest_fingerprint": handler_manifest.get("handler_manifest_sha256") if isinstance(handler_manifest, Mapping) else None,
                "notes": session.reason,
            },
            invariants=[str(value) for value in [fixture.get("invariant")] if value],
            authority_refs=["authority://gc-c1-evidence-matrix", "sha256://" + authority_fp],
            action_trace=_trace(declared_case, case_id, session.reason),
            lineage=_lineage(replay_output, case_id),
            replay={
                "executed": session.status == "RECORDED",
                "runner_id": "runner://" + RUNNER_ID,
                "runner_version": "runner-version://" + RUNNER_VERSION,
                "command_or_workflow_ref": "workflow://r-fc-controlled-replay/" + case_id,
                "environment_fingerprint": sha256_json({"attestation": attestation_record, "case_id": case_id, "handler_manifest": handler_manifest.get("handler_manifest_sha256") if isinstance(handler_manifest, Mapping) else None}),
            },
            review={
                "primary_reviewer": operator_ref,
                "independent_reviewer": independent_reviewer_ref,
                "review_result": "blocked",
                "review_evidence_ref": "review://pending/" + case_id,
            },
            status="UNVERIFIED" if session.status == "RECORDED" and oracle_match else ("FAIL" if session.status == "RECORDED" else "BLOCKED"),
        )
        cases.append({
            "case_id": case_id,
            "check_id": check_id,
            "case_type": declared_case.get("case_type"),
            "status": "RECORDED" if session.status == "RECORDED" else session.status,
            "executed": session.status == "RECORDED",
            "oracle": dict(declared_case.get("oracle", {})),
            "oracle_match": oracle_match,
            "replay": session.structured(),
            "evidence": evidence.structured(),
            "schema_errors": list(validate_evidence_record(evidence.structured())),
        })
    executed = sum(case["executed"] is True for case in cases)
    blocked = sum(case["status"] == "BLOCKED" for case in cases)
    matched = sum(case["oracle_match"] is True for case in cases)
    all_schema_valid = all(not case["schema_errors"] for case in cases)
    report = {
        "artifact_kind": "PMIRI-GC-C1-R-FC-CANDIDATE-REPORT",
        "status": "R_FC_REPLAY_BLOCKED" if executed == 0 else ("R_FC_REPLAY_PARTIAL" if blocked else "R_FC_REPLAY_RECORDED"),
        "catalog_id": catalog.get("catalog_id"),
        "catalog_version": catalog.get("catalog_version"),
        "catalog_status": catalog.get("status"),
        "implementation_authorization": catalog.get("scope", {}).get("implementation_authorization"),
        "runtime_execution": "CONTROLLED_CANDIDATE" if executed else "NOT_PERFORMED",
        "r_fc_pass": "NONE",
        "authority_execution_authorized": False,
        "replay_prerequisites": "READY_FOR_REPLAY" if executed or (selected_ids and not blocked) else "BLOCKED",
        "preflight": "READY_FOR_REPLAY" if executed else "NOT_SUPPLIED",
        "clean_room_attestation": "VERIFIED_EXTERNAL_PER_CASE" if executed else "NOT_SUPPLIED",
        "independent_review": "PENDING" if executed else ("NOT_SUPPLIED" if not reviewer_separated else "PENDING"),
        "operator_ref": operator_ref if reviewer_separated else None,
        "independent_reviewer_ref": independent_reviewer_ref if reviewer_separated else None,
        "handler_contract": "READY" if handler_contract_reason is None else handler_contract_reason,
        "handler_manifest_fingerprint": handler_manifest.get("handler_manifest_sha256") if isinstance(handler_manifest, Mapping) else None,
        "external_provider_access": "NOT_PERFORMED",
        "external_connector_access": "NOT_PERFORMED",
        "external_network_access": "NOT_PERFORMED",
        "authority_fingerprint": authority_fp,
        "selected_case_count": len(selected_ids),
        "executed_case_count": executed,
        "blocked_case_count": blocked,
        "oracle_match_count": matched,
        "schema_valid": all_schema_valid,
        "captured_at": utc_now(),
        "cases": cases,
    }
    report["report_fingerprint"] = sha256_json(report)
    if output_path is not None:
        destination = Path(output_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return report


def run_r_fc_blocked_candidate(project_root: str | Path, output_path: str | Path | None = None) -> dict[str, Any]:
    """Emit explicit blocked records without invoking the R-FC callables."""
    root = Path(project_root).resolve()
    authority_fp = authority_fingerprint(root)
    cases: list[dict[str, Any]] = []
    for check_id in sorted(RF_CHECKS):
        input_fingerprint = sha256_json({"check_id": check_id, "status": "BLOCKED", "reason": BLOCK_REASON})
        record = create_evidence_record(
            check_id=check_id,
            fixture_id="fixture://" + check_id,
            input_fingerprint=input_fingerprint,
            expected_dispositions=["REPLAY_REQUIRED"],
            forbidden_dispositions=["PASS"],
            actual={"disposition": "BLOCKED", "notes": BLOCK_REASON},
            authority_refs=["authority://gc-c1-evidence-matrix", "sha256://" + authority_fp],
            action_trace=[
                {
                    "step": 1,
                    "operation": "controlled_replay_gate",
                    "input_ref": "fixture://" + check_id,
                    "state_change_or_fault": BLOCK_REASON,
                }
            ],
            lineage={
                "authorization_lineage_ref": "lineage://" + check_id.lower(),
                "evidence_refs": ["evidence://not-executed/" + check_id.lower()],
                "citation_refs": [],
                "boundary_refs": ["boundary://gc-c1-clean-room"],
            },
            replay={
                "runner_id": "runner://pmiri-gc-c1-replay",
                "runner_version": "runner-version://0.1.0",
                "command_or_workflow_ref": "workflow://r-fc-not-executed",
                "environment_fingerprint": sha256_json({"environment": "UNVERIFIED"}),
            },
            review={
                "primary_reviewer": "reviewer://not-supplied",
                "independent_reviewer": "reviewer://not-supplied",
                "review_result": "blocked",
                "review_evidence_ref": "review://not-supplied",
            },
            status="BLOCKED",
        )
        structured = record.structured()
        errors = validate_evidence_record(structured)
        cases.append(
            {
                "check_id": check_id,
                "status": "BLOCKED" if not errors else "INVALID",
                "block_reason": BLOCK_REASON,
                "evidence": structured,
                "schema_errors": list(errors),
                "executed": False,
            }
        )
    valid = len(cases) == 17 and all(case["status"] == "BLOCKED" and case["executed"] is False for case in cases)
    report = {
        "artifact_kind": "PMIRI-GC-C1-R-FC-BLOCKED-CANDIDATE-REPORT",
        "status": "R_FC_REPLAY_BLOCKED" if valid else "R_FC_CANDIDATE_INVALID",
        "runtime_execution": "NOT_PERFORMED",
        "r_fc_pass": "NONE",
        "executed_case_count": 0,
        "blocked_case_count": sum(case["status"] == "BLOCKED" for case in cases),
        "authority_execution_authorized": False,
        "clean_room_attestation": "NOT_SUPPLIED",
        "independent_review": "NOT_SUPPLIED",
        "authority_fingerprint": authority_fp,
        "cases": cases,
        "report_fingerprint": sha256_json(cases),
    }
    if output_path is not None:
        destination = Path(output_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return report


__all__ = [
    "CaseHandler",
    "HANDLER_MANIFEST_KIND",
    "HANDLER_MANIFEST_VERSION",
    "create_handler_manifest",
    "load_handler_manifest",
    "run_r_fc_blocked_candidate",
    "run_r_fc_candidate",
    "write_handler_manifest",
]
