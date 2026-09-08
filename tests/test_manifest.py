import json

import pytest

from monkey365_evidence.manifest import load_manifest


def test_rejects_mutating_action(tmp_path):
    path = tmp_path / "controls.json"
    path.write_text(json.dumps({
        "allowed_hosts": ["entra.microsoft.com"],
        "controls": [{
            "cis": "1.0", "title": "Example", "start_url": "https://entra.microsoft.com/",
            "steps": [{"action": "fill", "selector": "input", "value": "secret"}]
        }]
    }))
    with pytest.raises(ValueError, match="unsupported action"):
        load_manifest(path)


def test_rejects_unapproved_host(tmp_path):
    path = tmp_path / "controls.json"
    path.write_text(json.dumps({
        "allowed_hosts": ["entra.microsoft.com"],
        "controls": [{"cis": "1.0", "title": "Example", "start_url": "https://example.com/"}]
    }))
    with pytest.raises(ValueError, match="not allowed"):
        load_manifest(path)

