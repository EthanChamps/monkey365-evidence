from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from .collector import capture_controls
from .manifest import load_manifest
from .monkey365 import failed_rule_ids, load_rule_map


def selected_controls(args, controls):
    rules = failed_rule_ids(args.monkey365)
    mapping = load_rule_map(args.rule_map)
    mapped = {mapping[rule] for rule in rules if rule in mapping}
    if args.controls:
        mapped &= set(args.controls.split(","))
    chosen = [controls[cis] for cis in sorted(mapped) if cis in controls and controls[cis].enabled]
    return rules, mapping, mapped, chosen


def main() -> None:
    parser = argparse.ArgumentParser(prog="monkey365-evidence")
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate")
    validate.add_argument("--manifest", type=Path, required=True)
    for name in ("plan", "capture"):
        command = sub.add_parser(name)
        command.add_argument("--manifest", type=Path, required=True)
        command.add_argument("--monkey365", type=Path, required=True)
        command.add_argument("--rule-map", type=Path, default=Path("monkey365-map.json"))
        command.add_argument("--controls")
    capture = sub.choices["capture"]
    capture.add_argument("--output", type=Path, default=Path("evidence"))
    capture.add_argument("--profile", type=Path, default=Path("browser-profile"))

    args = parser.parse_args()
    hosts, controls = load_manifest(args.manifest)
    if args.command == "validate":
        print(f"Valid manifest: {len(controls)} controls, {len(hosts)} allowed hosts")
        return
    rules, mapping, mapped, chosen = selected_controls(args, controls)
    unmapped_rules = sorted(rules - mapping.keys())
    missing_routes = sorted(mapped - controls.keys())
    print(f"Failed rules: {len(rules)}; capture-ready controls: {len(chosen)}")
    if unmapped_rules:
        print("Unmapped Monkey365 rules: " + ", ".join(unmapped_rules))
    if missing_routes:
        print("Mapped controls without routes: " + ", ".join(missing_routes))
    for control in chosen:
        print(f"  CIS {control.cis} - {control.title}")
    if args.command == "plan":
        return
    results = capture_controls(chosen, args.output, args.profile, hosts) if chosen else []
    report = {
        "results": [{**asdict(result), "path": str(result.path) if result.path else None} for result in results],
        "unmapped_rules": unmapped_rules,
        "missing_routes": missing_routes,
    }
    Path("run-manifest.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("Wrote run-manifest.json")


if __name__ == "__main__":
    main()

