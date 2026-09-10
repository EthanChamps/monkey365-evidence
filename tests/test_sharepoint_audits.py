from __future__ import annotations

import json
from pathlib import Path

import pytest

from monkey365_evidence.cli import sharepoint_browser_controls, sharepoint_fallback_ids
from monkey365_evidence.manifest import load_manifest
from monkey365_evidence.powershell_sharepoint import REGISTRY, run_audits, validate_admin_url
from monkey365_evidence.sharepoint_evaluation import evaluate_sharepoint


def test_registry_covers_all_sharepoint_tenant_controls():
    assert set(REGISTRY) == {
        "7.2.1", "7.2.2", "7.2.3", "7.2.4", "7.2.5", "7.2.6",
        "7.2.7", "7.2.8", "7.2.9", "7.2.10", "7.2.11", "7.3.1", "7.3.2",
    }
    assert all("Set-SPO" not in spec.script for spec in REGISTRY.values())


def test_ui_routes_cover_every_v7_sharepoint_control_with_a_documented_ui_check():
    root = Path(__file__).parents[1]
    hosts, controls = load_manifest(root / "controls.v7.json")
    assert set(controls) & {
        "7.2.1", "7.2.3", "7.2.4", "7.2.5", "7.2.6", "7.2.7", "7.2.8",
        "7.2.9", "7.2.10", "7.2.11",
    } == {
        "7.2.1", "7.2.3", "7.2.4", "7.2.5", "7.2.6", "7.2.7", "7.2.8",
        "7.2.9", "7.2.10", "7.2.11",
    }
    assert "7.2.2" not in controls and "7.3.1" not in controls
    assert any(host.startswith("re:[a-z0-9-]+-admin") for host in hosts)
    assert all(controls[cis].expected_url_pattern for cis in controls if cis.startswith("7."))


def test_powershell_is_only_used_for_sharepoint_controls_without_ui_routes():
    root = Path(__file__).parents[1]
    _, controls = load_manifest(root / "controls.v7.json")
    selected = {"7.2.2", "7.2.3", "7.2.4", "7.3.1"}
    assert sharepoint_fallback_ids(selected, controls, True) == ["7.2.2", "7.3.1"]
    assert sharepoint_fallback_ids(selected, controls, False) == []


def test_sharepoint_browser_routes_use_the_supplied_tenant_admin_url():
    root = Path(__file__).parents[1]
    _, controls = load_manifest(root / "controls.v7.json")
    bound = sharepoint_browser_controls(
        [controls["7.2.4"]], "https://example-admin.sharepoint.com/"
    )
    assert bound[0].start_url == (
        "https://example-admin.sharepoint.com/_layouts/15/online/AdminHome.aspx?modern=true#/home"
    )


def test_admin_url_is_strictly_validated():
    validate_admin_url("https://example-admin.sharepoint.com")
    with pytest.raises(ValueError):
        validate_admin_url("https://sharepoint.com.evil.example")


@pytest.mark.parametrize(
    ("cis", "data"),
    [
        ("7.2.1", {"LegacyAuthProtocolsEnabled": True}),
        ("7.2.2", {"EnableAzureADB2BIntegration": False}),
        ("7.2.3", {"SharingCapability": "ExternalUserAndGuestSharing"}),
        ("7.2.4", {"OneDriveSharingCapability": "ExternalUserSharingOnly"}),
        ("7.2.5", {"PreventExternalUsersFromResharing": False}),
        ("7.2.6", {"SharingCapability": "ExternalUserSharingOnly", "SharingDomainRestrictionMode": "None"}),
        ("7.2.7", {"DefaultSharingLinkType": "AnonymousAccess"}),
        ("7.2.8", {"SharingCapability": "ExternalUserSharingOnly", "WhoCanShareAuthenticatedGuestAllowList": []}),
        ("7.2.9", {"ExternalUserExpirationRequired": True, "ExternalUserExpireInDays": 60}),
        ("7.2.10", {"EmailAttestationRequired": True, "EmailAttestationReAuthDays": 30}),
        ("7.2.11", {"DefaultLinkPermission": "Edit"}),
        ("7.3.1", {"DisallowInfectedFileDownload": False}),
    ],
)
def test_each_noncompliant_setting_is_a_failure(cis, data):
    assert evaluate_sharepoint(cis, data).status == "failure"


def test_organization_specific_allow_lists_require_review():
    result = evaluate_sharepoint("7.2.6", {
        "SharingCapability": "ExternalUserSharingOnly",
        "SharingDomainRestrictionMode": "AllowList",
        "SharingAllowedDomainList": "example.org",
    })
    assert result.status == "unknown"


def test_runner_uses_safe_argv_and_preserves_single_record(tmp_path: Path):
    seen = {}

    def fake_runner(argv, **kwargs):
        seen["argv"] = argv
        script = Path(argv[argv.index("-File") + 1]).read_text(encoding="utf-8")
        seen["script"] = script
        result_path = next(
            line.split("-LiteralPath '", 1)[1].split("'", 1)[0]
            for line in script.splitlines() if "Set-Content -LiteralPath" in line
        )
        Path(result_path).write_text(json.dumps({
            "cis": "7.2.1", "command": "Get-SPOTenant",
            "output": '{"LegacyAuthProtocolsEnabled":true}',
            "data": {"LegacyAuthProtocolsEnabled": True},
            "status": "collected", "error": None,
        }), encoding="utf-8")
        return type("Done", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    result = run_audits(
        ["7.2.1"], tmp_path, sharepoint_admin_url="https://example-admin.sharepoint.com",
        runner=fake_runner,
    )
    assert result[0].status == "collected"
    assert seen["argv"][-2:] == ["-SharePointAdminUrl", "https://example-admin.sharepoint.com"]
    assert "Import-Module Microsoft.Online.SharePoint.PowerShell -UseWindowsPowerShell" in seen["script"]
