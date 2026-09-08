from monkey365_evidence.graph_evaluation import evaluate_graph
from monkey365_evidence.powershell_graph import REGISTRY


def test_expanded_graph_registry_is_read_only():
    expected = {"1.1.1", "1.1.2", "1.1.3", "5.1.5.2", "5.1.5.4", "5.1.5.6"}
    assert expected <= REGISTRY.keys()
    assert all("Set-Mg" not in REGISTRY[cis].script for cis in expected)


def test_synced_privileged_user_is_a_failure():
    result = evaluate_graph("1.1.1", [{
        "Id": "1", "UserPrincipalName": "admin@example.test",
        "OnPremisesSyncEnabled": True, "Role": "Global Administrator",
    }])
    assert result.status == "failure"


def test_global_admin_count_bounds_are_enforced():
    assert evaluate_graph("1.1.3", [{"Id": "1"}]).status == "failure"
    assert evaluate_graph("1.1.3", [{"Id": "1"}, {"Id": "2"}]).status == "no_failure"


def test_admin_consent_request_must_be_enabled():
    assert evaluate_graph("5.1.5.2", [{"IsEnabled": False}]).status == "failure"


def test_application_credential_over_180_days_is_a_failure():
    result = evaluate_graph("5.1.5.4", [{
        "Id": "1", "DisplayName": "Example",
        "PasswordCredentials": [{
            "StartDateTime": "2026-01-01T00:00:00Z",
            "EndDateTime": "2026-08-01T00:00:00Z",
        }],
    }])
    assert result.status == "failure"
