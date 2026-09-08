from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from .audit_capture import capture_audits, capture_graph_audits
from .collector import capture_controls
from .defaults import resource_path
from .manifest import load_manifest
from .models import CaptureResult
from .monkey365 import import_rule_map, load_failed_findings, load_rule_map
from .powershell_audit import REGISTRY as AUDITS
from .powershell_dependencies import ensure_modules
from .powershell_graph import REGISTRY as GRAPH_AUDITS
from .source_evidence import capture_source_findings


def selected_controls(args, controls):
    mapping = load_rule_map(args.rule_map)
    findings = load_failed_findings(args.monkey365, mapping)
    for finding in findings:
        if finding.control_id:
            if finding.benchmark_version != "7.0.0":
                raise ValueError("Bundled routes require CIS v7.0.0; HTML uses a different version")
            mapping[finding.rule_id] = finding.control_id
    rules = {finding.rule_id for finding in findings}
    mapped = {mapping[rule] for rule in rules if rule in mapping}
    if args.controls:
        requested = {value.strip() for value in args.controls.split(",") if value.strip()}
        unknown = requested - controls.keys() - set(mapping.values())
        if unknown:
            raise ValueError("Unknown control IDs: " + ", ".join(sorted(unknown)))
        mapped &= requested
    chosen = [controls[cis] for cis in sorted(mapped) if cis in controls and controls[cis].enabled]
    return rules, mapping, mapped, chosen, findings


def main() -> int:
    try:
        return _main()
    except (OSError, ValueError) as error:
        print(f"Error: {error}")
        return 1


def _main() -> int:
    parser = argparse.ArgumentParser(prog="monkey365-evidence")
    sub = parser.add_subparsers(dest="command", required=True)
    importer = sub.add_parser("import-ruleset", help="Build ID mappings from a Monkey365 ruleset")
    importer.add_argument("--ruleset", type=Path, required=True)
    importer.add_argument("--findings", type=Path, required=True)
    importer.add_argument("--output", type=Path, required=True)
    validate = sub.add_parser("validate")
    validate.add_argument("--manifest", type=Path, default=resource_path("controls.v7.json"))
    for name in ("plan", "capture"):
        command = sub.add_parser(name)
        command.add_argument("--manifest", type=Path, default=resource_path("controls.v7.json"))
        command.add_argument("--monkey365", type=Path, required=True)
        command.add_argument("--rule-map", type=Path, default=resource_path("monkey365-map.json"))
        command.add_argument("--controls")
        command.add_argument("--powershell", action="store_true",
                             help="Use bundled read-only PowerShell audits where available")
    capture = sub.choices["capture"]
    capture.add_argument("--output", type=Path, default=Path("evidence"))
    capture.add_argument("--profile", type=Path, default=Path("browser-profile"))
    capture.add_argument("--storage-state", type=Path,
                         help="Use saved Playwright login state in an isolated browser")
    capture.add_argument("--tenant-organization",
                         help="Exchange Online organization for PowerShell authentication")
    capture.add_argument("--expected-tenant-id",
                         help="Abort PowerShell audits if the connected tenant differs")
    capture.add_argument("--graph-client-id",
                         help="Use an existing authorised Graph application with its default scopes")
    capture.add_argument("--live-graph", action="store_true",
                         help="Recheck Graph controls live instead of using their Monkey365 export records")
    capture.add_argument("--test-run", action="store_true",
                         help="Label results as route tests rather than source-tenant evidence")
    capture.add_argument("--non-interactive", action="store_true",
                         help="Use an existing signed-in profile without a terminal prompt")

    args = parser.parse_args()
    if args.command == "import-ruleset":
        mapping = import_rule_map(args.ruleset, args.findings)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(mapping, indent=2, sort_keys=True), encoding="utf-8")
        print(f"Wrote {len(mapping)} rule/event aliases for {len(set(mapping.values()))} controls")
        return 0
    hosts, controls = load_manifest(args.manifest)
    if args.command == "validate":
        print(f"Valid manifest: {len(controls)} controls, {len(hosts)} allowed hosts")
        return 0
    rules, mapping, mapped, chosen, findings = selected_controls(args, controls)
    audit_ids = sorted(mapped & AUDITS.keys()) if args.powershell else []
    live_graph = getattr(args, "live_graph", False)
    graph_controls = sorted(mapped & GRAPH_AUDITS.keys()) if args.powershell else []
    graph_ids = graph_controls if live_graph else []
    source_graph_ids = graph_controls if not live_graph else []
    if getattr(args, "graph_client_id", None) and not live_graph:
        raise ValueError("--graph-client-id requires --live-graph")
    powershell_ids = set(audit_ids) | set(graph_controls)
    chosen = [control for control in chosen if control.cis not in powershell_ids]
    unmapped_rules = sorted(rules - mapping.keys())
    missing_routes = sorted(mapped - controls.keys() - powershell_ids)
    disabled = sorted(cis for cis in mapped & controls.keys()
                      if not controls[cis].enabled and cis not in powershell_ids)
    print(f"Failed rules: {len(rules)}; browser routes: {len(chosen)}; "
          f"PowerShell audits: {len(powershell_ids)}")
    if unmapped_rules:
        print("Unmapped Monkey365 rules: " + ", ".join(unmapped_rules))
    if missing_routes:
        print("Mapped controls without routes: " + ", ".join(missing_routes))
    if disabled:
        print("Disabled routes: " + ", ".join(disabled))
    for control in chosen:
        print(f"  CIS {control.cis} - {control.title}")
    for cis in sorted(powershell_ids):
        label = "PowerShell Command/Output" if cis not in source_graph_ids else "Monkey365 export evidence"
        print(f"  CIS {cis} - {label}")
    if args.command == "plan":
        return 2 if unmapped_rules or missing_routes or disabled else 0
    if powershell_ids:
        ensure_modules(exchange=bool(audit_ids), graph=bool(graph_ids),
                       interactive=not args.non_interactive)
    run_dir = args.output / datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
    run_dir.mkdir(parents=True, exist_ok=False)
    results = [CaptureResult(cis, "skipped", detail="Route is disabled") for cis in disabled]
    results.extend(CaptureResult(cis, "skipped", detail="No route configured")
                   for cis in missing_routes)
    report = {
        "schema_version": 1,
        "purpose": "route_test" if args.test_run else "evidence",
        "expected_tenant_id": args.expected_tenant_id,
        "input": str(args.monkey365.resolve()),
        "manifest": str(args.manifest.resolve()),
        "manifest_sha256": hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
        "rule_map_sha256": hashlib.sha256(args.rule_map.read_bytes()).hexdigest(),
        "failed_findings": [
            {"rule_id": finding.rule_id, "cis": mapping.get(finding.rule_id),
             "source": str(finding.source.resolve()), "record_index": finding.record_index,
             "selected": mapping.get(finding.rule_id) in mapped}
            for finding in findings
        ],
        "source_sha256": {str(source.resolve()): hashlib.sha256(source.read_bytes()).hexdigest()
                          for source in sorted({finding.source for finding in findings})},
        "created_at": datetime.now(UTC).isoformat(),
        "unmapped_rules": unmapped_rules,
        "missing_routes": missing_routes,
        "disabled_routes": disabled,
        "powershell_controls": sorted(powershell_ids),
        "graph_controls": graph_controls,
        "graph_evidence_source": "live_graph" if live_graph else "monkey365_export",
    }
    destination = run_dir / "run-manifest.json"
    def checkpoint(status="running"):
        report["status"] = status
        report["results"] = [
            {**asdict(result), "path": str(result.path) if result.path else None}
            for result in results
        ]
        temporary = destination.with_suffix(".tmp")
        temporary.write_text(json.dumps(report, indent=2), encoding="utf-8")
        temporary.replace(destination)

    def completed(result):
        results.append(result)
        checkpoint()

    checkpoint()
    interrupted = False
    phases = [
        ([control.cis for control in chosen], lambda: capture_controls(
            chosen, run_dir, args.profile, hosts, interactive=not args.non_interactive,
            on_result=completed, storage_state=args.storage_state)),
        (audit_ids, lambda: capture_audits(
            audit_ids, run_dir, tenantorganization=args.tenant_organization,
            expected_tenant_id=args.expected_tenant_id, on_result=completed)),
        (source_graph_ids, lambda: capture_source_findings(
            source_graph_ids,
            {mapping[finding.rule_id]: finding for finding in findings
             if mapping.get(finding.rule_id) in source_graph_ids},
            run_dir, on_result=completed)),
        (graph_ids, lambda: capture_graph_audits(
            graph_ids, run_dir, expected_tenant_id=args.expected_tenant_id,
            client_id=args.graph_client_id, on_result=completed)),
    ]
    try:
        for phase_ids, run_phase in phases:
            if not phase_ids:
                continue
            try:
                run_phase()
            except Exception as error:  # noqa: BLE001 - keep independent collectors running
                done = {result.cis for result in results}
                for cis in phase_ids:
                    if cis not in done:
                        completed(CaptureResult(cis, "failed", detail=str(error)))
    except KeyboardInterrupt:
        interrupted = True
        done = {result.cis for result in results}
        results.extend(CaptureResult(cis, "skipped", detail="Capture was interrupted")
                       for cis in [control.cis for control in chosen] + sorted(powershell_ids)
                       if cis not in done)
    incomplete = bool(unmapped_rules) or any(
        result.status not in {"captured", "needs_review"} for result in results)
    verified_files = {result.cis for result in results
                       if result.path is not None and result.path.is_file()
                       and result.status in {"captured", "needs_review"}}
    incomplete = incomplete or bool(mapped - verified_files)
    review_required = any(result.status == "needs_review" for result in results)
    report["capture_complete"] = not interrupted and not incomplete
    report["review_required"] = review_required
    checkpoint("interrupted" if interrupted else "incomplete" if incomplete
               else "review_required" if review_required else "complete")
    print(f"Evidence files: {sum(result.path is not None for result in results)}; "
          f"review items: {sum(result.status == 'needs_review' for result in results)}; "
          f"failed or skipped: {sum(result.status in {'failed', 'skipped'} for result in results)}")
    print(f"Wrote {destination}")
    return 130 if interrupted else 2 if incomplete or review_required else 0


if __name__ == "__main__":
    raise SystemExit(main())

