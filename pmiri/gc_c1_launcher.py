"""Local GC-C1 launcher adapter with fail-closed subprocess handoff.

The authority archive leaves the OS isolation mechanism to a controlled
environment.  This adapter implements the part that can be verified locally:
exact input hashing, fresh case-root creation, allowlisted input materializing,
scrubbed process environment, Windows Job Object limits, bounded wall time,
and teardown inspection.  It will not start a runner without a digest-valid
``VERIFIED`` attestation supplied by the controlled environment.

The adapter is an execution boundary, not an independent attestor.  A local
caller cannot turn its own observation into independent clean-room evidence by
calling this module.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Mapping, Sequence

from .attestation import LAUNCHER_ID, LAUNCHER_VERSION, load_attestation
from .canonical import canonical_json, is_sha256, sha256_bytes, sha256_json, utc_now
from .replay import RUNNER_ID, RUNNER_VERSION, verify_identity
from .sealing import seal_directory, verify_seal


REQUIRED_FINGERPRINTS = (
    "runner_source",
    "runner_manifest",
    "authority_bundle",
    "evidence_schema",
    "fixture_catalog",
    "preflight_matrix",
    "profile",
)


@dataclass(frozen=True)
class ResourceProfile:
    """Hard limits applied by the local process supervisor."""

    wall_time_seconds: int = 30
    cpu_time_seconds: int = 10
    memory_bytes: int = 256 * 1024 * 1024
    max_processes: int = 1

    def validate(self) -> None:
        if not 1 <= self.wall_time_seconds <= 3600:
            raise ValueError("wall_time_limit_invalid")
        if not 1 <= self.cpu_time_seconds <= self.wall_time_seconds:
            raise ValueError("cpu_time_limit_invalid")
        if not 16 * 1024 * 1024 <= self.memory_bytes <= 4 * 1024 * 1024 * 1024:
            raise ValueError("memory_limit_invalid")
        if self.max_processes != 1:
            raise ValueError("process_limit_must_be_one")

    def as_dict(self) -> dict[str, int]:
        return asdict(self)


@dataclass(frozen=True)
class LaunchResult:
    case_id: str
    status: str
    reason: str
    started: bool
    returncode: int | None
    root_fingerprint: str | None
    stdout_fingerprint: str | None
    stderr_fingerprint: str | None
    artifact_bundle_fingerprint: str | None
    persisted_dir: str | None
    job_limits_enforced: bool
    teardown_verified: bool
    evidence_ref: str | None = None

    def structured(self) -> dict[str, Any]:
        return asdict(self)


def _safe_relative(value: str) -> Path:
    candidate = Path(value)
    if not value or candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        raise ValueError("case_path_invalid")
    return candidate


def _safe_persist_dir(value: str | Path | None, case_root: Path | None = None) -> Path | None:
    if value is None:
        return None
    destination = Path(value).expanduser().resolve()
    if case_root is not None and (destination == case_root or case_root in destination.parents):
        raise ValueError("persist_dir_inside_case_root")
    if destination.exists() and any(destination.iterdir()):
        raise ValueError("persist_dir_must_be_new_or_empty")
    return destination


def _minimal_environment(work_root: Path) -> dict[str, str]:
    """Return a deterministic environment with no inherited user/cache paths."""
    temp_root = work_root / "tmp"
    profile_root = work_root / "profile"
    temp_root.mkdir()
    profile_root.mkdir()
    path = os.environ.get("PATH", "")
    env: dict[str, str] = {
        "PATH": path,
        "PYTHONHASHSEED": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "TEMP": str(temp_root),
        "TMP": str(temp_root),
        "HOME": str(profile_root),
        "USERPROFILE": str(profile_root),
        "APPDATA": str(profile_root / "AppData"),
        "LOCALAPPDATA": str(profile_root / "LocalAppData"),
        "PIP_CACHE_DIR": str(temp_root / "pip-cache"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "NO_PROXY": "*",
        "HTTP_PROXY": "",
        "HTTPS_PROXY": "",
        "ALL_PROXY": "",
    }
    for name in ("SystemRoot", "WINDIR", "PATHEXT"):
        if os.environ.get(name):
            env[name] = os.environ[name]
    return env


def _resolve_venv_python_command(
    argv: Sequence[str], env: Mapping[str, str]
) -> tuple[list[str], dict[str, str], str]:
    """Avoid the Windows venv redirector spawning a second Job Object process.

    Windows virtual environments commonly expose ``Scripts/python.exe`` as a
    small redirector which starts the base interpreter.  With the strict
    ``ActiveProcessLimit == 1`` policy that bootstrap child is correctly
    rejected.  When the command is an explicit venv Python executable, invoke
    the recorded base interpreter directly and expose only that venv's
    ``site-packages`` through a scrubbed ``PYTHONPATH``.  Any malformed or
    ambiguous venv metadata leaves the requested command unchanged so the
    launcher remains fail-closed rather than guessing.
    """
    requested = list(argv)
    resolved_env = dict(env)
    if os.name != "nt" or not requested:
        return requested, resolved_env, "NONE"
    executable = Path(requested[0]).expanduser()
    if not executable.is_absolute() or executable.name.casefold() not in {"python.exe", "pythonw.exe"}:
        return requested, resolved_env, "NONE"
    try:
        executable = executable.resolve()
        if executable.parent.name.casefold() != "scripts":
            return requested, resolved_env, "NONE"
        venv_root = executable.parent.parent
        config_path = venv_root / "pyvenv.cfg"
        site_packages = venv_root / "Lib" / "site-packages"
        if not config_path.is_file() or not site_packages.is_dir():
            return requested, resolved_env, "NONE"
        config: dict[str, str] = {}
        for line in config_path.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator:
                config[key.strip().casefold()] = value.strip()
        base_value = config.get("executable")
        if not base_value and config.get("home"):
            # uv-managed venvs omit ``executable`` but retain the base
            # interpreter directory in the standard ``home`` key.
            base_value = str(Path(config["home"]) / executable.name)
        if not base_value:
            return requested, resolved_env, "NONE"
        base_executable = Path(base_value).expanduser()
        if not base_executable.is_absolute():
            base_executable = (venv_root / base_executable).resolve()
        else:
            base_executable = base_executable.resolve()
        if not base_executable.is_file() or base_executable == executable:
            return requested, resolved_env, "NONE"
    except (OSError, UnicodeError, ValueError):
        return requested, resolved_env, "NONE"
    resolved_env["PYTHONPATH"] = str(site_packages)
    return [str(base_executable), *requested[1:]], resolved_env, "WINDOWS_VENV_BASE_INTERPRETER"


class _WindowsJob:
    """Small ctypes-only Windows Job Object wrapper.

    Job Objects provide process-memory, CPU-time, process-count and
    kill-on-close enforcement without introducing a third-party dependency.
    """

    def __init__(self, profile: ResourceProfile) -> None:
        import ctypes
        from ctypes import wintypes

        self._ctypes = ctypes
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._handle = self._kernel32.CreateJobObjectW(None, None)
        if not self._handle:
            raise OSError(ctypes.get_last_error(), "CreateJobObjectW")

        class Basic(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class IoCounters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount", "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class Extended(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", Basic),
                ("IoInfo", IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        JOB_OBJECT_LIMIT_WORKINGSET = 0x00000001
        JOB_OBJECT_LIMIT_PROCESS_TIME = 0x00000002
        JOB_OBJECT_LIMIT_JOB_TIME = 0x00000004
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
        JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
        info = Extended()
        info.BasicLimitInformation.PerJobUserTimeLimit = profile.cpu_time_seconds * 10_000_000
        info.BasicLimitInformation.ActiveProcessLimit = profile.max_processes
        info.BasicLimitInformation.LimitFlags = (
            JOB_OBJECT_LIMIT_JOB_TIME
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        )
        info.ProcessMemoryLimit = profile.memory_bytes
        ok = self._kernel32.SetInformationJobObject(self._handle, 9, ctypes.byref(info), ctypes.sizeof(info))
        if not ok:
            self.close()
            raise OSError(ctypes.get_last_error(), "SetInformationJobObject")

    def assign(self, process_handle: int) -> None:
        if not self._kernel32.AssignProcessToJobObject(self._handle, process_handle):
            raise OSError(self._ctypes.get_last_error(), "AssignProcessToJobObject")

    def terminate(self, exit_code: int = 1) -> None:
        self._kernel32.TerminateJobObject(self._handle, exit_code)

    def close(self) -> None:
        if getattr(self, "_handle", None):
            self._kernel32.CloseHandle(self._handle)
            self._handle = None


def _open_job(profile: ResourceProfile):
    if os.name == "nt":
        return _WindowsJob(profile)
    try:
        import resource  # type: ignore
    except ImportError as exc:  # pragma: no cover - platform dependent
        raise RuntimeError("resource_limits_unavailable") from exc
    return None


def _fingerprint_inputs(
    fingerprints: Mapping[str, str],
    fingerprint_paths: Mapping[str, str | Path],
    profile: ResourceProfile,
) -> tuple[dict[str, str], dict[str, bytes]]:
    if set(fingerprints) != set(REQUIRED_FINGERPRINTS):
        raise ValueError("fingerprint_set_invalid")
    if set(fingerprint_paths) != set(REQUIRED_FINGERPRINTS) - {"profile"}:
        raise ValueError("fingerprint_path_set_invalid")
    if any(not is_sha256(value) for value in fingerprints.values()):
        raise ValueError("fingerprint_invalid")
    materialized: dict[str, bytes] = {}
    for name, value in fingerprint_paths.items():
        source = Path(value).resolve()
        content = source.read_bytes()
        actual = sha256_bytes(content)
        if actual != fingerprints[name]:
            raise ValueError("fingerprint_mismatch:" + name)
        materialized[name] = content
    profile_fingerprint = sha256_json(profile.as_dict())
    if fingerprints["profile"] != profile_fingerprint:
        raise ValueError("profile_fingerprint_mismatch")
    return dict(fingerprints), materialized


def _inventory(root: Path) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            content = path.read_bytes()
            items.append({"path": relative, "byte_length": len(content), "sha256": sha256_bytes(content)})
    return items


def _persist_artifacts(destination: Path, artifacts: Mapping[str, bytes | str]) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for name, content in artifacts.items():
        path = destination / _safe_relative(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, str):
            path.write_text(content, encoding="utf-8")
        else:
            path.write_bytes(content)


def _blocked(case_id: str, reason: str) -> LaunchResult:
    return LaunchResult(case_id, "BLOCKED", reason, False, None, None, None, None, None, None, False, False)


def launch_pinned_runner(
    *,
    case_id: str,
    identity: Mapping[str, object],
    attestation_path: str | Path,
    fingerprints: Mapping[str, str],
    fingerprint_paths: Mapping[str, str | Path],
    argv: Sequence[str],
    inputs: Mapping[str, bytes],
    profile: ResourceProfile | None = None,
    persist_dir: str | Path | None = None,
    temp_parent: str | Path | None = None,
) -> LaunchResult:
    """Run one pinned command after verified attestation and local hardening.

    ``attestation_path`` must be an externally produced, digest-valid
    ``VERIFIED`` artifact.  The command is never invoked through a shell.
    """
    if not case_id or not argv or any(not isinstance(item, str) or not item for item in argv):
        return _blocked(case_id, "runner_command_invalid")
    try:
        verify_identity(identity)
        record, _ = load_attestation(attestation_path)
        if record.get("status") != "VERIFIED" or record.get("outcome") != "READY_FOR_REPLAY":
            return _blocked(case_id, "attestation_not_verified")
        if record.get("launcher") != {"launcher_id": LAUNCHER_ID, "launcher_version": LAUNCHER_VERSION}:
            return _blocked(case_id, "launcher_identity_invalid")
        if record.get("case", {}).get("case_id") != case_id:
            return _blocked(case_id, "attestation_case_mismatch")
        profile = profile or ResourceProfile()
        profile.validate()
        expected, materialized = _fingerprint_inputs(fingerprints, fingerprint_paths, profile)
        if record.get("fingerprints") != dict(sorted(expected.items())):
            return _blocked(case_id, "attestation_fingerprint_mismatch")
        if identity.get("runner_id") != RUNNER_ID or identity.get("runner_version") != RUNNER_VERSION:
            return _blocked(case_id, "runner_identity_mismatch")
        persist_destination = _safe_persist_dir(persist_dir) if persist_dir is not None else None
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        return _blocked(case_id, type(exc).__name__ + ":" + str(exc))

    parent = Path(temp_parent).resolve() if temp_parent else None
    try:
        with tempfile.TemporaryDirectory(prefix="pmiri-gc-c1-", dir=str(parent) if parent else None) as temp:
            root = Path(temp).resolve()
            if persist_destination is not None and (persist_destination == root or root in persist_destination.parents):
                return _blocked(case_id, "persist_dir_inside_case_root")
            inputs_root = root / "inputs"
            work_root = root / "work"
            outputs_root = root / "outputs"
            attestation_root = root / "attestation"
            teardown_root = root / "teardown"
            for directory in (inputs_root, work_root, outputs_root, attestation_root, teardown_root):
                directory.mkdir()
            attestation_bytes = Path(attestation_path).read_bytes()
            attestation_copy = attestation_root / "attestation.json"
            attestation_copy.write_bytes(attestation_bytes)
            os.chmod(attestation_copy, 0o444)
            for relative, content in sorted(inputs.items()):
                path = inputs_root / _safe_relative(relative)
                if not isinstance(content, bytes):
                    return _blocked(case_id, "case_input_must_be_bytes")
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
                os.chmod(path, 0o444)
            provenance_root = inputs_root / "provenance"
            provenance_root.mkdir()
            for name, content in sorted(materialized.items()):
                path = provenance_root / (name + ".bin")
                path.write_bytes(content)
                os.chmod(path, 0o444)
            profile_bytes = canonical_json(profile.as_dict()) + b"\n"
            profile_path = provenance_root / "profile.json"
            profile_path.write_bytes(profile_bytes)
            os.chmod(profile_path, 0o444)
            root_fingerprint = sha256_json({"case_id": case_id, "inputs": _inventory(inputs_root), "profile": profile.as_dict()})
            env = _minimal_environment(work_root)
            effective_argv, env, interpreter_resolution = _resolve_venv_python_command(argv, env)
            stdout_path = outputs_root / "stdout.bin"
            stderr_path = outputs_root / "stderr.bin"
            job = None
            process: subprocess.Popen[bytes] | None = None
            started = False
            returncode: int | None = None
            job_limits_enforced = False
            reason = "runner_not_started"
            try:
                job = _open_job(profile)
                if os.name != "nt":  # pragma: no cover - current supported host is Windows
                    raise RuntimeError("posix_launcher_not_implemented")
                with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                    process = subprocess.Popen(
                        effective_argv,
                        cwd=str(work_root),
                        env=env,
                        stdin=subprocess.DEVNULL,
                        stdout=stdout,
                        stderr=stderr,
                        shell=False,
                        close_fds=True,
                    )
                    job.assign(process._handle)  # type: ignore[attr-defined]
                    job_limits_enforced = True
                    started = True
                    deadline = time.monotonic() + profile.wall_time_seconds
                    while process.poll() is None and time.monotonic() < deadline:
                        time.sleep(0.02)
                    if process.poll() is None:
                        job.terminate(124)
                        process.wait(timeout=5)
                        reason = "wall_time_limit_exceeded"
                    else:
                        returncode = process.returncode
                        reason = "runner_completed" if returncode == 0 else "runner_exit_nonzero"
                    returncode = process.returncode
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                if process is not None and process.poll() is None:
                    try:
                        if job is not None:
                            job.terminate(1)
                        else:
                            process.kill()
                        process.wait(timeout=5)
                    except (OSError, subprocess.SubprocessError):
                        pass
                reason = type(exc).__name__ + ":" + str(exc)
                if not started:
                    return _blocked(case_id, "runner_launch_failed:" + reason)
            finally:
                if job is not None:
                    job.close()
            teardown_verified = process is not None and process.poll() is not None
            if not teardown_verified:
                return LaunchResult(case_id, "ISOLATION_VIOLATION", "teardown_unverified", started, returncode, root_fingerprint, None, None, None, job_limits_enforced, False)
            stdout_bytes = stdout_path.read_bytes() if stdout_path.exists() else b""
            stderr_bytes = stderr_path.read_bytes() if stderr_path.exists() else b""
            launch_record = {
                "artifact_kind": "PMIRI-GC-C1-LOCAL-LAUNCH-RECORD",
                "version": "0.1",
                "case_id": case_id,
                "launcher": {"launcher_id": LAUNCHER_ID, "launcher_version": LAUNCHER_VERSION},
                "runner": {"runner_id": RUNNER_ID, "runner_version": RUNNER_VERSION},
                "attestation_ref": str(Path(attestation_path).resolve()),
                "attestation_status": "VERIFIED",
                "argv": list(argv),
                "effective_argv": effective_argv,
                "interpreter_resolution": interpreter_resolution,
                "root_policy": "FRESH_CASE_ROOT",
                "root_fingerprint": root_fingerprint,
                "resource_profile": profile.as_dict(),
                "resource_limits_enforced": job_limits_enforced,
                "network_enforcement": "REQUIRES_EXTERNAL_ATTESTATION",
                "filesystem_enforcement": "CASE_ROOT_AND_READ_ONLY_INPUTS",
                "returncode": returncode,
                "stdout_fingerprint": sha256_bytes(stdout_bytes),
                "stderr_fingerprint": sha256_bytes(stderr_bytes),
                "teardown": {"result": "VERIFIED", "process_exited": True},
                "captured_at": utc_now(),
            }
            launch_record["record_sha256"] = sha256_json({key: value for key, value in launch_record.items() if key != "record_sha256"})
            launch_record_path = attestation_root / "launch-record.json"
            launch_record_path.write_bytes(canonical_json(launch_record) + b"\n")
            sealed = seal_directory(root, case_id=case_id, output_dir=root / "sealed")
            seal_valid, seal_reason = verify_seal(sealed["manifest_path"], root=root)
            if not seal_valid:
                return LaunchResult(case_id, "VALIDATION_ERROR", "seal_" + seal_reason, started, returncode, root_fingerprint, None, None, None, None, None, job_limits_enforced, teardown_verified)
            persisted = None
            if persist_destination is not None:
                artifacts = {
                    "launch-record.json": launch_record_path.read_bytes(),
                    "stdout.bin": stdout_bytes,
                    "stderr.bin": stderr_bytes,
                    "input-manifest.json": json.dumps(_inventory(inputs_root), ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                    "attestation/attestation.json": attestation_bytes,
                    "sealed/artifact-manifest.json": Path(sealed["manifest_path"]).read_bytes(),
                }
                _persist_artifacts(persist_destination, artifacts)
                persisted = str(persist_destination)
            status = "RECORDED" if returncode == 0 else "FAIL"
            return LaunchResult(case_id, status, reason, started, returncode, root_fingerprint, sha256_bytes(stdout_bytes), sha256_bytes(stderr_bytes), sealed["bundle_sha256"], persisted, job_limits_enforced, True, "evidence://local-launch/" + case_id)
    except (OSError, ValueError, TypeError) as exc:
        return _blocked(case_id, type(exc).__name__ + ":" + str(exc))


__all__ = ["LAUNCHER_ID", "LAUNCHER_VERSION", "LaunchResult", "REQUIRED_FINGERPRINTS", "ResourceProfile", "launch_pinned_runner"]
