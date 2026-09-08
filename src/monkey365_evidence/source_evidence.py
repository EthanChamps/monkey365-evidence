"""Write evidence from an existing Monkey365 finding without a second API query."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path

from .models import CaptureResult
from .monkey365 import FailedFinding


def capture_source_findings(
    control_ids: list[str], findings: dict[str, FailedFinding], output_dir: Path, *,
    on_result: Callable[[CaptureResult], None],
) -> None:
    """Create local text evidence from the failed records already in the Monkey365 export."""
    output_dir.mkdir(parents=True, exist_ok=True)
    for cis in control_ids:
        finding = findings.get(cis)
        if finding is None:
            on_result(CaptureResult(cis, "failed", detail="No matching Monkey365 finding record"))
            continue
        destination = output_dir / f"{cis} Monkey365.txt"
        try:
            data = {
                "rule_id": finding.rule_id,
                "source": str(finding.source),
                "record_index": finding.record_index,
                "finding": finding.record,
            }
            with destination.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(f"CIS {cis} — Monkey365 export evidence\n\n"
                             "Source\n------\n"
                             "Existing Monkey365 failed-finding record; not revalidated live.\n\n"
                             "Output\n------\n"
                             f"{json.dumps(data, indent=2, ensure_ascii=False)}\n")
            on_result(CaptureResult(
                cis, "captured", destination,
                detail="Evidence copied from the Monkey365 export; not revalidated live",
                highlighted=False, sha256=hashlib.sha256(destination.read_bytes()).hexdigest(),
            ))
        except Exception as error:  # noqa: BLE001 - preserve other evidence records
            on_result(CaptureResult(cis, "failed", detail=str(error)))
