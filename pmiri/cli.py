"""Command-line entry point for the local PMIRI slice."""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path

from .network import NetworkBoundary
from .integrity import authority_fingerprint, validate_documentation_bundle
from .acceptance import run_s0_acceptance
from .attestation import load_attestation
from .canonical import sha256_json
from .d2 import validate_d2_matrix
from .d2_runtime import run_d2_runtime_candidate, run_gate_d_smoke
from .gc_c1_launcher import ResourceProfile, launch_pinned_runner
from .models import QueryRequest
from .preflight import run_preflight, write_preflight
from .readiness import default_profile, load_profile, run_deployment_readiness, write_readiness
from .r_fc import create_handler_manifest, load_handler_manifest, run_r_fc_blocked_candidate, run_r_fc_candidate, write_handler_manifest
from .r_fc_handlers import run_local_r_fc_candidate
from .runtime import LocalEvidenceRuntime
from .sealing import seal_directory
from .store import LocalStore, SQLiteStore
from .control_plane import SQLiteAuthenticationRegistry, SQLitePolicyEpoch, SQLiteRateLimiter, SQLiteReplayGuard
from .deployment_smoke import run_local_deployment_smoke, write_deployment_smoke
from .http_api import DEFAULT_MAX_REQUEST_BYTES
from .server import LocalServerConfigurationError, build_local_read_server
from .deployment_server import DeploymentConfigurationError, ReadinessContractError, build_deployment_server
from .handoff import create_handoff_bundle
from .review_package import build_review_package, validate_review_package, write_review_package
from .final_acceptance import build_final_acceptance_report, write_final_acceptance_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="PMIRI local-first evidence runtime")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="initialize a local store")
    init.add_argument("store")
    init.add_argument("--backend", choices=("json", "sqlite"), default="json")

    add = sub.add_parser("add", help="register one UTF-8 local text/Markdown file")
    add.add_argument("store")
    add.add_argument("project")
    add.add_argument("path")
    add.add_argument("--backend", choices=("json", "sqlite"), default="json")

    add_dir = sub.add_parser("add-dir", help="register explicit UTF-8 Markdown/text files under one directory")
    add_dir.add_argument("store")
    add_dir.add_argument("project")
    add_dir.add_argument("directory")
    add_dir.add_argument("--backend", choices=("json", "sqlite"), default="json")

    query = sub.add_parser("query", help="run a project-bounded local query")
    query.add_argument("store")
    query.add_argument("project")
    query.add_argument("text")
    query.add_argument("--request-id", default="cli-request")
    query.add_argument("--max-results", type=int, default=20)
    query.add_argument("--context-bound", type=int, default=4000)
    query.add_argument("--json", action="store_true", dest="as_json")
    query.add_argument("--backend", choices=("json", "sqlite"), default="json")

    migrate = sub.add_parser("migrate-json-to-sqlite", help="migrate a JSON/blob store, including history, into SQLite")
    migrate.add_argument("source_store")
    migrate.add_argument("target_store")
    migrate.add_argument("--dry-run", action="store_true", help="inspect source and target without writing")

    backup = sub.add_parser("backup-sqlite", help="create and verify a consistent SQLite backup")
    backup.add_argument("source_store")
    backup.add_argument("backup_store")

    restore = sub.add_parser("restore-sqlite", help="restore a SQLite backup into a new, non-existing destination")
    restore.add_argument("backup_store")
    restore.add_argument("restore_store")

    control_plane = sub.add_parser("init-control-plane", help="initialize the shared local authorization control plane")
    control_plane.add_argument("path", help="SQLite control-plane database path")
    control_plane.add_argument("--initial-policy-epoch", type=int, default=0)

    readiness = sub.add_parser("readiness", help="write a fail-closed deployment-readiness report")
    readiness.add_argument("root", nargs="?", default=".")
    readiness.add_argument("--profile", help="closed JSON deployment profile; defaults to the safe local candidate")
    readiness.add_argument("--external-evidence", help="deployment-supplied signed EXT-01..EXT-06 evidence JSON")
    readiness.add_argument("--external-public-key", help="trusted Ed25519 public key for the external evidence")
    readiness.add_argument("--output", default="artifacts/deployment-readiness-report.json")

    deployment_smoke = sub.add_parser("deployment-smoke", help="run the local ingest/recovery/query/readiness smoke scenario")
    deployment_smoke.add_argument("root", nargs="?", default=".")
    deployment_smoke.add_argument("--fixture-root")
    deployment_smoke.add_argument("--output", default="artifacts/deployment-smoke-report.json")

    serve = sub.add_parser("serve-local", help="serve authenticated reads on the IPv4 loopback interface")
    serve.add_argument("store", nargs="?", help="initialized SQLite store root; defaults to the profile storage root")
    serve.add_argument("--control-plane", default=None, help="SQLite control-plane path; defaults to the profile control-plane path")
    serve.add_argument("--profile", help="closed deployment profile; API settings provide safe defaults")
    serve.add_argument("--audit", default=None)
    serve.add_argument("--port", type=int, default=None)
    serve.add_argument("--max-request-bytes", type=int, default=None)

    deployment_serve = sub.add_parser(
        "serve-deployment",
        help="serve authenticated reads with explicitly supplied deployment adapters",
    )
    deployment_serve.add_argument("--profile", required=True, help="closed JSON deployment profile")
    deployment_serve.add_argument("--adapter-module", required=True, help="trusted module exposing build_authorization_adapters(config)")
    deployment_serve.add_argument("--adapter-dir", help="directory containing the trusted adapter module")
    deployment_serve.add_argument("--adapter-config", help="JSON object of deployment-owned references")
    deployment_serve.add_argument("--adapter-sha256", help="expected SHA-256 of the loaded adapter module")
    deployment_serve.add_argument("--port", type=int, default=None)
    deployment_serve.add_argument("--max-request-bytes", type=int, default=None)

    handoff = sub.add_parser("handoff", help="materialize and verify a clean-room review handoff bundle")
    handoff.add_argument("root", nargs="?", default=".")
    handoff.add_argument("--output", default="artifacts/handoff")
    handoff.add_argument("--fixture-id", default="GC-C1-FC01")
    handoff.add_argument("--case-id", default="GC-C1-FC01-P")

    review_package = sub.add_parser("review-package", help="materialize a bounded external-review checklist from candidate reports")
    review_package.add_argument("root", nargs="?", default=".")
    review_package.add_argument("--output", default="artifacts/review-package.json")

    final_acceptance = sub.add_parser("final-acceptance", help="evaluate the fail-closed final acceptance gate")
    final_acceptance.add_argument("root", nargs="?", default=".")
    final_acceptance.add_argument("--readiness", default="artifacts/deployment-readiness-report.json")
    final_acceptance.add_argument("--evidence", dest="final_evidence", help="deployment-supplied signed final-acceptance evidence JSON")
    final_acceptance.add_argument("--public-key", dest="final_public_key", help="trusted Ed25519 public key for final-acceptance evidence")
    final_acceptance.add_argument("--output", default="artifacts/final-acceptance-gate.json")

    preflight = sub.add_parser("preflight", help="write a truthful GC-C1 preflight record")
    preflight.add_argument("root", nargs="?", default=".")
    preflight.add_argument("--output", default="artifacts/preflight-record.json")
    preflight.add_argument("--identity-file", help="JSON file containing the exact pinned runner identity")
    preflight.add_argument("--attestation", help="verified external isolation-attestation JSON")
    preflight.add_argument("--operator")
    preflight.add_argument("--independent-reviewer")
    preflight.add_argument("--fixture-id")
    preflight.add_argument("--case-id")

    seal = sub.add_parser("seal", help="seal case-scoped artifacts")
    seal.add_argument("root")
    seal.add_argument("case_id")
    seal.add_argument("--output-dir")

    url = sub.add_parser("evaluate-url", help="evaluate a URL at the deny-by-default boundary")
    url.add_argument("operation")
    url.add_argument("url")

    integrity = sub.add_parser("integrity", help="check the documentation JSON/schema registry")
    integrity.add_argument("root", nargs="?", default=".")

    acceptance = sub.add_parser("acceptance", help="run the 12-case V1-S0 acceptance harness")
    acceptance.add_argument("root", nargs="?", default=".")
    acceptance.add_argument("--output", default="artifacts/s0-acceptance-report.json")

    d2 = sub.add_parser("d2-matrix", help="validate the D2 matrix without executing runtime cases")
    d2.add_argument("root", nargs="?", default=".")
    d2.add_argument("--output", default="artifacts/d2-matrix-report.json")

    smoke = sub.add_parser("gate-d-smoke", help="run deterministic local Gate-D enforcement smoke cases")
    smoke.add_argument("root", nargs="?", default=".")
    smoke.add_argument("--output", default="artifacts/gate-d-runtime-smoke-report.json")

    d2_runtime = sub.add_parser("d2-runtime", help="run the 34-case local synthetic D2 candidate harness")
    d2_runtime.add_argument("root", nargs="?", default=".")
    d2_runtime.add_argument("--output", default="artifacts/d2-runtime-candidate-report.json")

    rfc = sub.add_parser("rfc-status", help="write explicit blocked evidence records for all 17 R-FC obligations")
    rfc.add_argument("root", nargs="?", default=".")
    rfc.add_argument("--output", default="artifacts/r-fc-blocked-candidate-report.json")

    rfc_local = sub.add_parser("rfc-local", help="run the PMIRI-backed local synthetic handlers for all 34 R-FC cases")
    rfc_local.add_argument("root", nargs="?", default=".")
    rfc_local.add_argument("--case-id", action="append", dest="case_ids", help="run one local case; may be repeated, defaults to all 34")
    rfc_local.add_argument("--output", default="artifacts/r-fc-local-handler-candidate-report.json")

    rfc_run = sub.add_parser("rfc-run", help="run declared R-FC cases behind external per-case attestations")
    rfc_run.add_argument("root", nargs="?", default=".")
    rfc_run.add_argument("--identity-file", required=True)
    rfc_run.add_argument("--fingerprints-file", required=True, help="JSON object containing the seven replay SHA-256 fingerprints")
    rfc_run.add_argument("--attestation-dir", required=True, help="directory containing one VERIFIED attestation JSON per case_id")
    rfc_run.add_argument("--preflight-dir", required=True, help="directory containing one READY_FOR_REPLAY preflight JSON per case_id")
    rfc_run.add_argument("--handler-module", required=True, help="importable pinned handler module exposing HANDLERS={case_id: callable}")
    rfc_run.add_argument("--handler-manifest", required=True, help="digest-bound handler manifest for the imported module")
    rfc_run.add_argument("--operator", required=True)
    rfc_run.add_argument("--independent-reviewer", required=True)
    rfc_run.add_argument("--case-id", action="append", dest="case_ids", help="run one case; may be repeated, defaults to all 34")
    rfc_run.add_argument("--persist-dir", help="directory where sealed per-case candidate artifacts are retained")
    rfc_run.add_argument("--output", default="artifacts/r-fc-candidate-report.json")

    rfc_manifest = sub.add_parser("rfc-handler-manifest", help="create a digest-bound manifest for an R-FC HANDLERS module")
    rfc_manifest.add_argument("root", nargs="?", default=".")
    rfc_manifest.add_argument("--handler-module", required=True, help="importable module exposing HANDLERS={case_id: callable}")
    rfc_manifest.add_argument("--case-id", action="append", dest="case_ids", help="include one handler; may be repeated, defaults to all module handlers")
    rfc_manifest.add_argument("--output", default="artifacts/r-fc-handler-manifest.json")

    launch = sub.add_parser("gc-c1-launch", help="launch one pinned runner command behind a verified GC-C1 attestation")
    launch.add_argument("case_id")
    launch.add_argument("--identity-file", required=True)
    launch.add_argument("--attestation", required=True)
    launch.add_argument("--fingerprints-file", required=True, help="JSON object containing the seven attested SHA-256 fingerprints")
    launch.add_argument("--fingerprint-files-file", required=True, help="JSON object mapping six fingerprint names to source files")
    launch.add_argument("--input", action="append", default=[], metavar="RELATIVE=FILE", help="read-only case input; may be repeated")
    launch.add_argument("--persist-dir", required=True)
    launch.add_argument("--temp-parent")
    launch.add_argument("--wall-time-seconds", type=int, default=30)
    launch.add_argument("--cpu-time-seconds", type=int, default=10)
    launch.add_argument("--memory-bytes", type=int, default=256 * 1024 * 1024)
    launch.add_argument("runner_args", nargs=argparse.REMAINDER, help="runner argv after --")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    def make_store(path: str, backend: str):
        return SQLiteStore(path) if backend == "sqlite" else LocalStore(path)

    if args.command == "init":
        make_store(args.store, args.backend).initialize()
        print(json.dumps({"status": "INITIALIZED", "store": str(Path(args.store).resolve())}))
        return 0
    if args.command == "add":
        record = make_store(args.store, args.backend).register_file(args.project, args.path)
        print(json.dumps(record.public_dict(), ensure_ascii=False, sort_keys=True, indent=2))
        return 0
    if args.command == "add-dir":
        records = make_store(args.store, args.backend).ingest_directory(args.project, args.directory)
        print(json.dumps({"count": len(records), "sources": [record.public_dict() for record in records]}, ensure_ascii=False, sort_keys=True, indent=2))
        return 0
    if args.command == "query":
        result = LocalEvidenceRuntime(make_store(args.store, args.backend), context_bound=args.context_bound).query(
            QueryRequest(args.request_id, args.project, args.text, max_results=args.max_results)
        )
        print(json.dumps(result.structured(), ensure_ascii=False, sort_keys=True, indent=2) if args.as_json else result.render())
        return 0
    if args.command == "migrate-json-to-sqlite":
        target = SQLiteStore(args.target_store)
        report = target.migration_plan(args.source_store) if args.dry_run else target.migrate_from_local_store(args.source_store)
        print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
        return 0 if report["status"] in {"MIGRATED", "MIGRATION_DRY_RUN"} else 1
    if args.command == "backup-sqlite":
        report = SQLiteStore(args.source_store).backup_to(args.backup_store)
        print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
        return 0 if report["status"] == "BACKUP_VERIFIED" else 1
    if args.command == "restore-sqlite":
        report = SQLiteStore(args.backup_store).restore_from_backup(args.restore_store)
        print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
        return 0 if report["status"] == "RESTORE_VERIFIED" and report["source_fingerprint"] == report["restored_fingerprint"] else 1
    if args.command == "init-control-plane":
        SQLiteAuthenticationRegistry(args.path).initialize()
        SQLiteReplayGuard(args.path).initialize()
        SQLiteRateLimiter(args.path).initialize()
        epoch = SQLitePolicyEpoch(args.path, initial_epoch=args.initial_policy_epoch)
        epoch.initialize()
        print(json.dumps({"status": "INITIALIZED", "path": str(Path(args.path).resolve()), "policy_epoch": epoch.get()}, ensure_ascii=False))
        return 0
    if args.command == "readiness":
        profile = load_profile(args.profile) if args.profile else None
        report = run_deployment_readiness(
            args.root,
            profile=profile,
            external_evidence_path=args.external_evidence,
            external_public_key_path=args.external_public_key,
        )
        write_readiness(report, args.output)
        structured = report.structured()
        blocked = [item["check_id"] for item in structured["checks"] if item["result"] == "BLOCKED"]
        print(json.dumps({"status": structured["overall_result"], "output": str(Path(args.output).resolve()), "blocked_checks": blocked}, ensure_ascii=False))
        return 0 if structured["overall_result"] == "DEPLOYMENT_READY" else 1
    if args.command == "deployment-smoke":
        report = run_local_deployment_smoke(args.root, fixture_root=args.fixture_root)
        write_deployment_smoke(report, args.output)
        print(json.dumps({"status": report["status"], "output": str(Path(args.output).resolve()), "sources": report["source_count"], "readiness_status": report["readiness_status"], "external_access": report["external_access"]}, ensure_ascii=False))
        return 0
    if args.command == "serve-local":
        profile = load_profile(args.profile) if args.profile else default_profile()
        api_profile = profile["api"]
        profile_root = Path(args.profile).resolve().parent if args.profile else Path.cwd().resolve()
        if args.store is None:
            if profile["storage"].get("backend") != "sqlite" or not profile["storage"].get("root"):
                raise LocalServerConfigurationError("serve_profile_storage_unconfigured")
            storage_root = Path(profile["storage"]["root"])
            if not storage_root.is_absolute():
                storage_root = profile_root / storage_root
        else:
            storage_root = Path(args.store)
        if args.control_plane is None:
            if profile["control_plane"].get("backend") != "sqlite-local" or not profile["control_plane"].get("path"):
                raise LocalServerConfigurationError("serve_profile_control_plane_unconfigured")
            control_plane_path = Path(profile["control_plane"]["path"])
            if not control_plane_path.is_absolute():
                control_plane_path = profile_root / control_plane_path
        else:
            control_plane_path = Path(args.control_plane)
        audit_path = args.audit if args.audit is not None else api_profile["audit_path"]
        if args.audit is None and not Path(audit_path).is_absolute():
            audit_path = str(profile_root / audit_path)
        server = build_local_read_server(
            storage_root,
            control_plane_path,
            port=args.port if args.port is not None else api_profile["port"],
            audit_path=audit_path,
            max_request_bytes=args.max_request_bytes if args.max_request_bytes is not None else api_profile["max_request_bytes"],
        )
        print(
            json.dumps(
                {
                    "status": "SERVING_LOOPBACK_ONLY",
                    "host": "127.0.0.1",
                    "port": server.server_port,
                    "audit": str(Path(audit_path).resolve()),
                    "profile_id": profile["profile_id"],
                    "profile_fingerprint": sha256_json(profile),
                    "storage": str(storage_root.resolve()),
                    "control_plane": str(control_plane_path.resolve()),
                },
                ensure_ascii=False,
            ),
            flush=True,
        )
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            return 0
        finally:
            server.server_close()
        return 0
    if args.command == "serve-deployment":
        server = None
        try:
            server, startup = build_deployment_server(
                args.profile,
                adapter_module=args.adapter_module,
                adapter_dir=args.adapter_dir,
                adapter_config=args.adapter_config,
                adapter_sha256=args.adapter_sha256,
                port=args.port,
                max_request_bytes=args.max_request_bytes,
            )
        except (DeploymentConfigurationError, ReadinessContractError) as exc:
            print(json.dumps({"status": "DEPLOYMENT_BLOCKED", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
            return 2
        print(json.dumps(startup, ensure_ascii=False), flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            return 0
        finally:
            server.server_close()
        return 0
    if args.command == "handoff":
        report = create_handoff_bundle(
            args.root,
            args.output,
            selected_fixture_id=args.fixture_id,
            selected_case_id=args.case_id,
        )
        print(json.dumps({"status": report["status"], "manifest": report["manifest_path"], "payload_count": report["payload_count"], "external_execution": report["external_execution"]}, ensure_ascii=False))
        return 0
    if args.command == "review-package":
        package = build_review_package(args.root)
        write_review_package(package, args.output)
        errors = validate_review_package(package, project_root=args.root)
        print(json.dumps({"status": package["status"], "output": str(Path(args.output).resolve()), "errors": list(errors), "promotion_result": package["promotion_result"]}, ensure_ascii=False))
        return 0 if not errors else 1
    if args.command == "final-acceptance":
        report = build_final_acceptance_report(
            args.root,
            readiness_path=args.readiness,
            evidence_path=args.final_evidence,
            public_key_path=args.final_public_key,
        )
        write_final_acceptance_report(report, args.output)
        blocked = [item["check_id"] for item in report["checks"] if item["result"] == "BLOCKED"]
        print(json.dumps({"status": report["overall_result"], "output": str(Path(args.output).resolve()), "blocked_checks": blocked, "external_evidence_status": report["external_evidence_status"]}, ensure_ascii=False))
        return 0 if report["overall_result"] == "FINAL_ACCEPTANCE_READY" else 1
    if args.command == "preflight":
        identity = None
        isolation = None
        if args.identity_file:
            identity = json.loads(Path(args.identity_file).read_text(encoding="utf-8"))
        if args.attestation:
            _, isolation = load_attestation(args.attestation)
        record = run_preflight(
            args.root,
            identity=identity,
            isolation=isolation,
            operator=args.operator,
            independent_reviewer=args.independent_reviewer,
            selected_fixture_id=args.fixture_id,
            selected_case_id=args.case_id,
        )
        write_preflight(record, args.output)
        print(json.dumps({"overall_result": record.overall_result, "output": str(Path(args.output).resolve())}))
        return 0
    if args.command == "seal":
        print(json.dumps(seal_directory(args.root, case_id=args.case_id, output_dir=args.output_dir), ensure_ascii=False, indent=2))
        return 0
    if args.command == "evaluate-url":
        print(json.dumps(NetworkBoundary().evaluate(args.operation, args.url).public_dict(), ensure_ascii=False, indent=2))
        return 0
    if args.command == "integrity":
        report = validate_documentation_bundle(args.root)
        print(json.dumps({**report.structured(), "authority_fingerprint": authority_fingerprint(args.root)}, ensure_ascii=False, indent=2))
        return 0 if report.ok else 1
    if args.command == "acceptance":
        report = run_s0_acceptance(args.root, args.output)
        print(json.dumps({"status": report["status"], "output": str(Path(args.output).resolve()), "cases": len(report["cases"])}, ensure_ascii=False))
        return 0 if report["status"] == "S0_ACCEPTANCE_CANDIDATE" else 1
    if args.command == "d2-matrix":
        report = validate_d2_matrix(args.root)
        destination = Path(args.output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"status": report["status"], "output": str(destination.resolve()), "scenarios": report["scenario_count"]}, ensure_ascii=False))
        return 0 if report["status"] == "D2_DOCUMENTARY_VALIDATED_RUNTIME_BLOCKED" else 1
    if args.command == "gate-d-smoke":
        report = run_gate_d_smoke(args.root, args.output)
        print(json.dumps({"status": report["status"], "output": str(Path(args.output).resolve()), "provider_calls": report["provider_calls"]}, ensure_ascii=False))
        return 0 if report["status"] == "RUNTIME_SMOKE_CANDIDATE" else 1
    if args.command == "d2-runtime":
        report = run_d2_runtime_candidate(args.root, args.output)
        print(json.dumps({"status": report["status"], "output": str(Path(args.output).resolve()), "scenarios": report["scenario_count"], "all_oracles_match": report["all_oracles_match"]}, ensure_ascii=False))
        return 0 if report["status"] == "D2_RUNTIME_CANDIDATE" and report["all_oracles_match"] else 1
    if args.command == "rfc-status":
        report = run_r_fc_blocked_candidate(args.root, args.output)
        print(json.dumps({"status": report["status"], "output": str(Path(args.output).resolve()), "blocked_cases": report["blocked_case_count"], "r_fc_pass": report["r_fc_pass"]}, ensure_ascii=False))
        return 0 if report["status"] == "R_FC_REPLAY_BLOCKED" else 1
    if args.command == "rfc-local":
        report = run_local_r_fc_candidate(args.root, case_ids=args.case_ids, output_path=args.output)
        print(json.dumps({"status": report["status"], "output": str(Path(args.output).resolve()), "executed_cases": report["executed_case_count"], "oracle_matches": report["oracle_match_count"], "all_oracles_match": report["all_oracles_match"], "r_fc_pass": report["r_fc_pass"]}, ensure_ascii=False))
        return 0 if report["status"] == "LOCAL_SYNTHETIC_ONLY" and report["all_oracles_match"] and report["r_fc_pass"] == "NONE" else 1
    if args.command == "rfc-handler-manifest":
        module = importlib.import_module(args.handler_module)
        handlers = getattr(module, "HANDLERS", {})
        if not isinstance(handlers, dict):
            raise SystemExit("handler module HANDLERS must be a dict")
        selected_case_ids = list(args.case_ids or sorted(handlers))
        try:
            selected_handlers = {case_id: handlers[case_id] for case_id in selected_case_ids}
            manifest = create_handler_manifest(args.root, case_handlers=selected_handlers, case_ids=selected_case_ids)
            write_handler_manifest(manifest, args.output)
        except (KeyError, ValueError) as exc:
            raise SystemExit(str(exc)) from exc
        print(json.dumps({"status": manifest["status"], "output": str(Path(args.output).resolve()), "case_count": len(manifest["case_ids"]), "handler_manifest_fingerprint": manifest["handler_manifest_sha256"]}, ensure_ascii=False))
        return 0
    if args.command == "rfc-run":
        identity = json.loads(Path(args.identity_file).read_text(encoding="utf-8"))
        fingerprints = json.loads(Path(args.fingerprints_file).read_text(encoding="utf-8"))
        selected_case_ids = list(args.case_ids or [])
        if selected_case_ids:
            attestation_case_ids = selected_case_ids
        else:
            attestation_case_ids = [f"GC-C1-FC{index:02d}-{case_type}" for index in range(1, 18) for case_type in ("P", "A")]
        attestation_paths = {
            case_id: Path(args.attestation_dir) / (case_id + ".json")
            for case_id in attestation_case_ids
        }
        preflight_paths = {
            case_id: Path(args.preflight_dir) / (case_id + ".json")
            for case_id in attestation_case_ids
        }
        handlers = {}
        if args.handler_module:
            module = importlib.import_module(args.handler_module)
            handlers = getattr(module, "HANDLERS", {})
            if not isinstance(handlers, dict):
                raise SystemExit("handler module HANDLERS must be a dict")
        try:
            handler_manifest = load_handler_manifest(args.handler_manifest)
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        report = run_r_fc_candidate(
            args.root,
            identity=identity,
            fingerprints=fingerprints,
            attestation_paths=attestation_paths,
            preflight_paths=preflight_paths,
            case_handlers=handlers,
            handler_manifest=handler_manifest,
            operator_ref=args.operator,
            independent_reviewer_ref=args.independent_reviewer,
            case_ids=selected_case_ids or None,
            persist_dir=args.persist_dir,
            output_path=args.output,
        )
        print(json.dumps({"status": report["status"], "output": str(Path(args.output).resolve()), "executed_cases": report["executed_case_count"], "blocked_cases": report["blocked_case_count"], "r_fc_pass": report["r_fc_pass"]}, ensure_ascii=False))
        return 0 if report["status"] == "R_FC_REPLAY_RECORDED" and report["r_fc_pass"] == "NONE" else 1
    if args.command == "gc-c1-launch":
        runner_args = list(args.runner_args)
        if runner_args and runner_args[0] == "--":
            runner_args = runner_args[1:]
        identity = json.loads(Path(args.identity_file).read_text(encoding="utf-8"))
        fingerprints = json.loads(Path(args.fingerprints_file).read_text(encoding="utf-8"))
        fingerprint_files = json.loads(Path(args.fingerprint_files_file).read_text(encoding="utf-8"))
        inputs: dict[str, bytes] = {}
        for spec in args.input:
            relative, separator, source = spec.partition("=")
            if not separator or not relative or not source:
                raise SystemExit("--input must use RELATIVE=FILE")
            inputs[relative] = Path(source).read_bytes()
        result = launch_pinned_runner(
            case_id=args.case_id,
            identity=identity,
            attestation_path=args.attestation,
            fingerprints=fingerprints,
            fingerprint_paths=fingerprint_files,
            argv=runner_args,
            inputs=inputs,
            profile=ResourceProfile(args.wall_time_seconds, args.cpu_time_seconds, args.memory_bytes),
            persist_dir=args.persist_dir,
            temp_parent=args.temp_parent,
        )
        print(json.dumps(result.structured(), ensure_ascii=False, sort_keys=True, indent=2))
        return 0 if result.status == "RECORDED" else 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
