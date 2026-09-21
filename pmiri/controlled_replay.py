"""Case-scoped GC-C1 replay session wrapper.

The wrapper provides fresh temporary case roots, input/output separation and
artifact sealing around the pinned replay boundary.  It is not an OS sandbox:
network, credential and filesystem capabilities remain ``BLOCKED`` unless the
caller supplies an externally observed attestation that proves them.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from .canonical import canonical_json, is_sha256, sha256_bytes, sha256_json, utc_now
from .clean_room import IsolationObservation
from .replay import ReplayResult, run_case
from .sealing import seal_directory, verify_seal


@dataclass(frozen=True)
class ReplaySessionResult:
    case_id: str
    status: str
    reason: str
    replay: ReplayResult
    artifact_manifest_fingerprint: str | None = None
    output_fingerprint: str | None = None
    persisted_dir: str | None = None

    def structured(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "status": self.status,
            "reason": self.reason,
            "replay": {
                "status": self.replay.status,
                "disposition": self.replay.disposition,
                "reason": self.replay.reason,
                "output": dict(self.replay.output) if self.replay.output is not None else None,
            },
            "artifact_manifest_fingerprint": self.artifact_manifest_fingerprint,
            "output_fingerprint": self.output_fingerprint,
            "persisted_dir": self.persisted_dir,
        }


def _safe_relative(value: str) -> Path:
    candidate = Path(value)
    if not value or candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        raise ValueError("case_path_invalid")
    return candidate


def _blocked(case_id: str, reason: str) -> ReplaySessionResult:
    return ReplaySessionResult(case_id, "BLOCKED", reason, ReplayResult(case_id, "BLOCKED", "BLOCKED", reason))


def _prepare_persist_dir(value: str | Path | None) -> Path | None:
    if value is None:
        return None
    destination = Path(value).resolve()
    if destination.exists() and any(destination.iterdir()):
        raise ValueError("persist_dir_must_be_new_or_empty")
    destination.mkdir(parents=True, exist_ok=True)
    return destination


def _persist_case(root: Path, destination: Path, manifest_path: Path) -> None:
    """Copy the sealed case inventory while excluding the seal destination."""
    for source in sorted(root.rglob("*")):
        if not source.is_file() or manifest_path.parent in source.parents:
            continue
        relative = source.relative_to(root)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    target_manifest = destination / "sealed" / "artifact-manifest.json"
    target_manifest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(manifest_path, target_manifest)


def run_controlled_case(
    *,
    case_id: str,
    identity: Mapping[str, object],
    isolation: Mapping[str, IsolationObservation] | None,
    fingerprints: Mapping[str, object],
    inputs: Mapping[str, bytes],
    case: Callable[[Path], Mapping[str, object]],
    temp_parent: str | Path | None = None,
    persist_dir: str | Path | None = None,
) -> ReplaySessionResult:
    """Run a pure case in a fresh root only after replay prerequisites pass."""
    required = ("runner_source", "runner_manifest", "authority_bundle", "evidence_schema", "fixture_catalog", "preflight_matrix", "preflight_record_schema")
    if any(not is_sha256(fingerprints.get(name)) for name in required):
        return _blocked(case_id, "required_fingerprint_missing")
    if isolation is None:
        return _blocked(case_id, "clean_room_attestation_absent")
    try:
        persist_destination = _prepare_persist_dir(persist_dir)
    except (OSError, ValueError) as exc:
        return _blocked(case_id, type(exc).__name__ + ":" + str(exc))
    with tempfile.TemporaryDirectory(prefix="pmiri-case-", dir=str(Path(temp_parent).resolve()) if temp_parent else None) as temp:
        root = Path(temp).resolve()
        input_root = root / "inputs"
        output_root = root / "outputs"
        input_root.mkdir()
        output_root.mkdir()
        try:
            for relative, content in sorted(inputs.items()):
                path = input_root / _safe_relative(relative)
                path.parent.mkdir(parents=True, exist_ok=True)
                if not isinstance(content, bytes):
                    raise ValueError("case_input_must_be_bytes")
                path.write_bytes(content)
                os.chmod(path, 0o444)
        except (OSError, TypeError, ValueError) as exc:
            return _blocked(case_id, type(exc).__name__ + ":" + str(exc))

        def invoke() -> Mapping[str, object]:
            result = case(root)
            if not isinstance(result, Mapping):
                raise ValueError("case_output_must_be_mapping")
            return dict(result)

        replay = run_case(case_id=case_id, identity=identity, isolation=isolation, fingerprints=fingerprints, case=invoke)
        if replay.status != "RECORDED" or replay.output is None:
            return ReplaySessionResult(case_id, replay.status, replay.reason, replay)
        output_bytes = canonical_json(dict(replay.output)) + b"\n"
        output_path = output_root / "result.json"
        output_path.write_bytes(output_bytes)
        output_fingerprint = sha256_bytes(output_bytes)
        sealed = seal_directory(root, case_id=case_id, output_dir=root / "sealed")
        valid, seal_reason = verify_seal(sealed["manifest_path"], root=root)
        if not valid:
            return ReplaySessionResult(case_id, "VALIDATION_ERROR", "seal_" + seal_reason, replay, None, output_fingerprint)
        persisted = None
        if persist_destination is not None:
            try:
                _persist_case(root, persist_destination, Path(sealed["manifest_path"]))
                persisted_valid, persisted_reason = verify_seal(
                    persist_destination / "sealed" / "artifact-manifest.json",
                    root=persist_destination,
                )
                if not persisted_valid:
                    return ReplaySessionResult(
                        case_id,
                        "VALIDATION_ERROR",
                        "persisted_seal_" + persisted_reason,
                        replay,
                        sealed["bundle_sha256"],
                        output_fingerprint,
                    )
                persisted = str(persist_destination)
            except (OSError, ValueError, shutil.Error) as exc:
                return ReplaySessionResult(
                    case_id,
                    "VALIDATION_ERROR",
                    "persist_failed:" + type(exc).__name__ + ":" + str(exc),
                    replay,
                    sealed["bundle_sha256"],
                    output_fingerprint,
                )
        seal_reason = "case_completed_and_integrity_sealed" if sealed.get("completeness") == "COMPLETE" else "case_completed_and_integrity_sealed_incomplete"
        return ReplaySessionResult(case_id, "RECORDED", seal_reason, replay, sealed["bundle_sha256"], output_fingerprint, persisted)


__all__ = ["ReplaySessionResult", "run_controlled_case"]
