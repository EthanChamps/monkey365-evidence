from monkey365_evidence.audit_evaluation import evaluate_audit
from monkey365_evidence.powershell_audit import REGISTRY, _script

NEW_CONTROLS = {
    "1.2.2", "2.1.2", "2.1.4", "2.1.5", "2.1.8", "2.1.9", "2.1.10",
    "2.1.13", "2.2.1", "2.4.1", "2.4.2", "2.4.4", "3.1.1", "3.2.1",
    "3.2.2", "3.2.3", "3.3.1",
}


def test_registry_contains_read_only_expansion():
    assert NEW_CONTROLS <= REGISTRY.keys()
    assert all("Set-" not in REGISTRY[cis].script for cis in NEW_CONTROLS)


def test_purview_controls_open_compliance_session():
    script = _script([REGISTRY["3.2.1"]], "result.json", None)
    assert "Connect-IPPSSession" in script


def test_shared_mailbox_enabled_account_is_failure():
    result = evaluate_audit("1.2.2", [{
        "UserPrincipalName": "shared@example.test", "AccountDisabled": False,
    }])
    assert result.status == "failure"


def test_direct_defender_settings_are_evaluated():
    assert evaluate_audit("2.1.13", [{"EnableSafeList": True}]).status == "failure"
    assert evaluate_audit("2.1.5", [{
        "EnableATPForSPOTeamsODB": True,
        "EnableSafeDocs": True,
        "AllowSafeDocsOpen": False,
    }]).status == "no_failure"


def test_invalid_dkim_domain_is_failure():
    result = evaluate_audit("2.1.9", [{
        "Domain": "example.test", "Enabled": False, "Status": "Not Configured",
    }])
    assert result.status == "failure"
