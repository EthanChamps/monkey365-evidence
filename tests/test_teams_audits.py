from monkey365_evidence.powershell_teams import REGISTRY, _script
from monkey365_evidence.teams_evaluation import evaluate_teams


def test_all_benchmark_global_teams_controls_are_registered():
    assert len(REGISTRY) == 15
    assert {"8.1.1", "8.1.2", "8.2.1", "8.2.2", "8.2.3", "8.2.4"} <= REGISTRY.keys()
    assert {f"8.5.{number}" for number in range(1, 10)} <= REGISTRY.keys()


def test_generated_script_is_read_only_and_checks_tenant():
    text = _script([REGISTRY["8.1.2"]], "result.json")
    assert "Connect-MicrosoftTeams" in text
    assert "Get-CsTenant" in text
    assert "Set-Cs" not in text
    assert "Remove-Cs" not in text


def test_direct_boolean_teams_controls():
    for cis, key in {
        "8.1.2": "AllowEmailIntoChannel",
        "8.5.1": "AllowAnonymousUsersToJoinMeeting",
        "8.5.9": "AllowCloudRecording",
    }.items():
        assert evaluate_teams(cis, {key: False}).status == "no_failure"
        assert evaluate_teams(cis, {key: True}).status == "failure"
        assert evaluate_teams(cis, {key: None}).status == "unknown"


def test_consumer_access_accepts_either_disabled_layer():
    data = {"EnableTeamsConsumerAccess": True, "AllowTeamsConsumer": False}
    assert evaluate_teams("8.2.2", data).status == "no_failure"
    data = {"EnableTeamsConsumerAccess": True, "AllowTeamsConsumer": True}
    assert evaluate_teams("8.2.2", data).status == "failure"


def test_accepted_meeting_policy_values():
    assert evaluate_teams("8.5.3", {"AutoAdmittedUsers": "OrganizerOnly"}).status == (
        "no_failure"
    )
    assert evaluate_teams("8.5.3", {"AutoAdmittedUsers": "Everyone"}).status == "failure"
    assert evaluate_teams(
        "8.5.5", {"MeetingChatEnabledType": "EnabledExceptAnonymous"}
    ).status == "no_failure"
