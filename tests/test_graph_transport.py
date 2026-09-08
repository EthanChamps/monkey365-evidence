"""Execute the generated collector with synthetic data in real PowerShell hosts."""

import json
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from monkey365_evidence import powershell_graph


@pytest.mark.parametrize("host", ["powershell.exe", "pwsh"])
@pytest.mark.parametrize("payload", [[], [{"Id": "one", "Values": []}],
                                     [{"Id": "one"}, {"Id": "two"}]])
def test_generated_graph_transport(host, payload, tmp_path, monkeypatch):
    executable = shutil.which(host)
    if executable is None:
        pytest.skip(f"{host} is unavailable")
    encoded = json.dumps(payload).replace("'", "''")
    synthetic = "(ConvertFrom-Json -InputObject '{\"items\":" + encoded + "}').items"
    spec = replace(powershell_graph.REGISTRY["1.2.1"], script=synthetic)
    monkeypatch.setitem(powershell_graph.REGISTRY, "1.2.1", spec)

    def local_runner(argv, **kwargs):
        script_path = Path(argv[argv.index("-File") + 1])
        script = script_path.read_text(encoding="utf-8")
        # Execute the actual generated collection/transport, without tenant access.
        body = script[script.index("$records = @()") :]
        script_path.write_text("$ErrorActionPreference='Stop'\n" + body, encoding="utf-8")
        check = kwargs.pop("check", False)
        return subprocess.run(argv, check=check, **kwargs)

    result = powershell_graph.run_audits(
        ["1.2.1"], tmp_path, pwsh=executable, runner=local_runner
    )[0]
    assert result.status == "collected", result.error
    assert result.data == payload
    assert json.loads(result.output) == payload
