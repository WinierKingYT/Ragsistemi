"""Verify supplied deployment evidence through readiness and final acceptance.

This command is a read-only closure gate. It does not observe a VM, contact an
identity provider, execute a connector, or manufacture evidence. It evaluates
the local candidate together with externally supplied signed evidence and
returns success only when both readiness and final acceptance are ready.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pmiri.canonical import utc_now  # noqa: E402
from pmiri.deployment_evidence import (  # noqa: E402
    DeploymentEvidenceError,
    verify_final_acceptance_evidence,
)
from pmiri.readiness import (  # noqa: E402
    load_profile,
    run_deployment_readiness,
    validate_readiness_report,
)


class ClosureVerificationError(ValueError):
    """Raised when the closure verification inputs cannot be evaluated."""


def _in_project(root: Path, value: str | Path, error_code: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = root / path
    if path.is_symlink():
        raise ClosureVerificationError(error_code + "_symlink")
    path = path.resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ClosureVerificationError(error_code + "_outside_project") from exc
    if not path.is_file():
        raise ClosureVerificationError(error_code + "_unavailable")
    return path


def _external_file(value: str | Path | None, error_code: str) -> Path | None:
    if value is None:
        return None
    path = Path(value)
    if path.is_symlink():
        raise ClosureVerificationError(error_code + "_symlink")
    path = path.resolve()
    if not path.is_file():
        raise ClosureVerificationError(error_code + "_unavailable")
    return path


def _blocked_checks(report: dict[str, Any]) -> list[str]:
    return [
        str(item.get("check_id"))
        for item in report.get("checks", [])
        if isinstance(item, dict) and item.get("result") == "BLOCKED"
    ]


def verify_deployment_closure(
    project_root: str | Path,
    profile_path: str | Path,
    *,
    external_evidence_path: str | Path | None = None,
    external_public_key_path: str | Path | None = None,
    final_evidence_path: str | Path | None = None,
    final_public_key_path: str | Path | None = None,
    captured_at: str | None = None,
) -> dict[str, Any]:
    """Evaluate the supplied signed evidence without writing candidate state."""

    root = Path(project_root).resolve()
    if not root.is_dir():
        raise ClosureVerificationError("project_root_unavailable")
    profile_file = _in_project(root, profile_path, "profile")
    profile = load_profile(profile_file)
    external_evidence = _external_file(external_evidence_path, "external_evidence")
    external_public_key = _external_file(external_public_key_path, "external_public_key")
    final_evidence = _external_file(final_evidence_path, "final_evidence")
    final_public_key = _external_file(final_public_key_path, "final_public_key")

    readiness = run_deployment_readiness(
        root,
        profile=profile,
        captured_at=captured_at or utc_now(),
        external_evidence_path=external_evidence,
        external_public_key_path=external_public_key,
    ).structured()
    readiness_errors = list(validate_readiness_report(readiness))
    readiness_ready = not readiness_errors and readiness.get("overall_result") == "DEPLOYMENT_READY"
    final_result: dict[str, Any] = {"result": "BLOCKED"}

    if readiness_errors:
        final_result["reason"] = "readiness_report_invalid:" + readiness_errors[0]
    elif not readiness_ready:
        final_result["reason"] = "readiness_not_ready"
    elif final_evidence is None or final_public_key is None:
        final_result["reason"] = "final_evidence_and_public_key_required"
    else:
        try:
            verified = verify_final_acceptance_evidence(
                final_evidence,
                trusted_public_key=final_public_key.read_bytes(),
                profile_id=profile["profile_id"],
                profile_fingerprint=readiness["profile_fingerprint"],
                authority_fingerprint=readiness["authority_fingerprint"],
                readiness_report_fingerprint=readiness["report_fingerprint"],
            )
        except (DeploymentEvidenceError, OSError, ValueError, TypeError) as exc:
            final_result["reason"] = type(exc).__name__ + ":" + str(exc)
        else:
            final_result = {
                "result": "FINAL_ACCEPTANCE_READY",
                "evidence_fingerprint": verified.evidence_fingerprint,
                "reviewer_id": verified.reviewer_id,
            }

    closure_ready = readiness_ready and final_result["result"] == "FINAL_ACCEPTANCE_READY"
    return {
        "status": "DEPLOYMENT_CLOSURE_READY" if closure_ready else "DEPLOYMENT_CLOSURE_BLOCKED",
        "project_root": str(root),
        "profile_id": profile["profile_id"],
        "readiness": {
            "result": readiness.get("overall_result"),
            "report_fingerprint": readiness.get("report_fingerprint"),
            "blocked_checks": _blocked_checks(readiness),
            "validation_errors": readiness_errors,
        },
        "final_acceptance": final_result,
        "external_execution": "NOT_PERFORMED_BY_THIS_TOOL",
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", default=".")
    parser.add_argument("--profile", default="deployment-profile.example.json")
    parser.add_argument("--external-evidence")
    parser.add_argument("--external-public-key")
    parser.add_argument("--final-evidence")
    parser.add_argument("--final-public-key")
    parser.add_argument("--captured-at")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = verify_deployment_closure(
            args.project_root,
            args.profile,
            external_evidence_path=args.external_evidence,
            external_public_key_path=args.external_public_key,
            final_evidence_path=args.final_evidence,
            final_public_key_path=args.final_public_key,
            captured_at=args.captured_at,
        )
    except (ClosureVerificationError, OSError, ValueError, TypeError, KeyError) as exc:
        print(json.dumps({"status": "DEPLOYMENT_CLOSURE_BLOCKED", "error": str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "DEPLOYMENT_CLOSURE_READY" else 1


if __name__ == "__main__":
    raise SystemExit(main())
