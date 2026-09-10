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


def test_allows_a_strict_tenant_sharepoint_host_pattern(tmp_path):
    path = tmp_path / "controls.json"
    path.write_text(json.dumps({
        "allowed_hosts": ["admin.microsoft.com"],
        "allowed_host_patterns": ["[a-z0-9-]+-admin\\.sharepoint\\.com"],
        "controls": [{
            "cis": "7.2.1", "title": "Example", "start_url": "https://admin.microsoft.com/sharepoint",
            "expected_url_pattern": "https://[a-z0-9-]+-admin\\.sharepoint\\.com/.+",
            "ready_selector": "main",
        }],
    }))
    hosts, controls = load_manifest(path)
    assert "7.2.1" in controls
    assert any(host.startswith("re:") for host in hosts)


def test_rejects_both_exact_and_pattern_urls(tmp_path):
    path = tmp_path / "controls.json"
    path.write_text(json.dumps({
        "allowed_hosts": ["entra.microsoft.com"],
        "controls": [{
            "cis": "1.0", "title": "Example", "start_url": "https://entra.microsoft.com/",
            "expected_url": "https://entra.microsoft.com/", "expected_url_pattern": "https://entra.microsoft.com/.+",
            "ready_selector": "main",
        }],
    }))
    with pytest.raises(ValueError, match="expected_url or expected_url_pattern"):
        load_manifest(path)
