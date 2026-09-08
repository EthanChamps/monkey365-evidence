"""Write actual PowerShell command and output evidence as UTF-8 text."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterable
from dataclasses import asdict
from pathlib import Path

from .audit_evaluation import evaluate_audit
from .defender_attachments import evaluate_attachment_filtering
from .defender_limits import evaluate_limits
from .defender_policy_evaluation import evaluate_defender
from .graph_evaluation import evaluate_graph
from .models import CaptureResult, evidence_filename
from .powershell_audit import AuditResult, run_audits
from .powershell_graph import REGISTRY as GRAPH_AUDITS
from .powershell_graph import run_audits as run_graph_audits
from .powershell_teams import REGISTRY as TEAMS_AUDITS
from .powershell_teams import run_audits as run_teams_audits
from .teams_evaluation import evaluate_teams


def render_audit_results(
    audits: Iterable[AuditResult],
    output_dir: Path,
    *,
    on_result: Callable[[CaptureResult], None],
    titles: dict[str, str] | None = None,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for audit in audits:
        if audit.status != "collected" or audit.data is None or not audit.output.strip():
            on_result(CaptureResult(audit.cis, "failed",
                                    detail=audit.error or "No audit output collected"))
            continue
        title = (titles or {}).get(audit.cis, "Audit evidence")
        destination = output_dir / evidence_filename(audit.cis, title, "txt")
        try:
            if audit.cis in GRAPH_AUDITS:
                evaluation = evaluate_graph(audit.cis, audit.data)
            elif audit.cis in TEAMS_AUDITS:
                evaluation = evaluate_teams(audit.cis, audit.data)
            elif audit.cis == "2.1.15":
                evaluation = evaluate_limits(audit.data)
            elif audit.cis in {"2.1.1", "2.1.7"}:
                evaluation = evaluate_defender(audit.cis, audit.data)
            elif audit.cis == "2.1.11" and isinstance(audit.data, dict):
                evaluation = evaluate_attachment_filtering(
                    audit.data.get("Policies"), audit.data.get("Rules"))
            else:
                evaluation = evaluate_audit(audit.cis, audit.data)
            output = json.dumps(audit.data, indent=2, ensure_ascii=False)
            with destination.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(f"CIS {audit.cis} — PowerShell audit\n\n"
                             f"Command\n-------\n{audit.command}\n\n"
                             f"Output\n------\n{output}\n")
            on_result(CaptureResult(
                audit.cis, "captured" if evaluation.status == "failure" else "needs_review",
                destination, evaluation.detail, highlighted=False,
                sha256=hashlib.sha256(destination.read_bytes()).hexdigest(),
            ))
        except Exception as error:  # noqa: BLE001 - preserve other audit results
            on_result(CaptureResult(audit.cis, "failed", detail=str(error)))


def capture_audits(
    control_ids: list[str],
    output_dir: Path,
    *,
    tenantorganization: str | None,
    on_result: Callable[[CaptureResult], None],
    expected_tenant_id: str | None = None,
    titles: dict[str, str] | None = None,
) -> None:
    audits = run_audits(control_ids, output_dir, tenantorganization=tenantorganization,
                       expected_tenant_id=expected_tenant_id)
    raw_path = output_dir / "powershell-results.local.json"
    with raw_path.open("x", encoding="utf-8") as stream:
        json.dump([asdict(audit) for audit in audits], stream, indent=2, ensure_ascii=False)
    render_audit_results(audits, output_dir, on_result=on_result, titles=titles)


def capture_graph_audits(
    control_ids: list[str], output_dir: Path, *,
    expected_tenant_id: str | None, client_id: str | None,
    on_result: Callable[[CaptureResult], None],
    titles: dict[str, str] | None = None,
) -> None:
    audits = run_graph_audits(control_ids, output_dir,
                             expected_tenant_id=expected_tenant_id, client_id=client_id)
    with (output_dir / "graph-results.local.json").open("x", encoding="utf-8") as stream:
        json.dump([asdict(audit) for audit in audits], stream, indent=2, ensure_ascii=False)
    render_audit_results(audits, output_dir, on_result=on_result, titles=titles)


def capture_teams_audits(
    control_ids: list[str], output_dir: Path, *, expected_tenant_id: str | None,
    on_result: Callable[[CaptureResult], None], titles: dict[str, str] | None = None,
) -> None:
    audits = run_teams_audits(control_ids, output_dir, expected_tenant_id=expected_tenant_id)
    with (output_dir / "teams-results.local.json").open("x", encoding="utf-8") as stream:
        json.dump([asdict(audit) for audit in audits], stream, indent=2, ensure_ascii=False)
    render_audit_results(audits, output_dir, on_result=on_result, titles=titles)
