import json
from pathlib import Path

import pytest

from monkey365_evidence.checkpoint import write_checkpoint


def test_recreates_directory_removed_during_sign_in(tmp_path):
    destination = tmp_path / "run" / "run-manifest.json"
    write_checkpoint(destination, {"status": "running"})
    destination.unlink()
    destination.parent.rmdir()
    write_checkpoint(destination, {"status": "complete", "results": []})
    assert json.loads(destination.read_text()) == {"status": "complete", "results": []}
    assert list(destination.parent.glob("*.tmp")) == []


def test_retries_if_temporary_file_disappears_before_replace(tmp_path, monkeypatch):
    original = Path.replace
    calls = []

    def replace(source, target):
        calls.append(source)
        if len(calls) == 1:
            source.unlink()
        return original(source, target)

    monkeypatch.setattr(Path, "replace", replace)
    destination = tmp_path / "run-manifest.json"
    write_checkpoint(destination, {"status": "running"})
    assert len(calls) == 2
    assert calls[0] != calls[1]
    assert json.loads(destination.read_text())["status"] == "running"


def test_persistent_error_preserves_previous_report(tmp_path, monkeypatch):
    destination = tmp_path / "run-manifest.json"
    write_checkpoint(destination, {"status": "running"})

    def denied(source, target):
        raise PermissionError("simulated locked destination")

    monkeypatch.setattr(Path, "replace", denied)
    with pytest.raises(PermissionError):
        write_checkpoint(destination, {"status": "complete"})
    assert json.loads(destination.read_text())["status"] == "running"
    assert list(tmp_path.glob("*.tmp")) == []


def test_checkpoint_failure_does_not_hide_capture_errors(tmp_path, monkeypatch, capsys):
    from monkey365_evidence import cli
    from monkey365_evidence.models import CaptureResult

    findings = tmp_path / "findings.json"
    mapping = tmp_path / "mapping.json"
    findings.write_text(json.dumps([
        {"ruleId": "manual-1", "statusCode": "fail"},
        {"ruleId": "manual-2", "statusCode": "fail"},
    ]))
    mapping.write_text(json.dumps({"manual-1": "7.2.4", "manual-2": "7.2.9"}))
    monkeypatch.setattr("sys.argv", [
        "monkey365-evidence", "capture", "--monkey365", str(findings),
        "--rule-map", str(mapping), "--output", str(tmp_path / "evidence"),
        "--sharepoint-admin-url", "https://example-admin.sharepoint.com/",
        "--non-interactive",
    ])
    calls = []

    def save(destination, report):
        calls.append(report["status"])
        if len(calls) == 2:
            raise FileNotFoundError("simulated checkpoint disappearance")
        write_checkpoint(destination, report)

    def capture(controls, *args, on_result, **kwargs):
        for control in controls:
            on_result(CaptureResult(control.cis, "failed", detail="original capture error"))

    monkeypatch.setattr(cli, "write_checkpoint", save)
    monkeypatch.setattr(cli, "capture_controls", capture)
    assert cli.main() == 2
    log = capsys.readouterr().out
    assert log.index("original capture error") < log.index("Cannot save run manifest")
    assert "CIS 7.2.9: failed: original capture error" in log
    manifest = next((tmp_path / "evidence").glob("*/run-manifest.json"))
    report = json.loads(manifest.read_text())
    assert report["capture_complete"] is False
    assert len(report["results"]) == 2
