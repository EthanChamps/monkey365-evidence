from monkey365_evidence.fabric_evaluation import evaluate_fabric
from monkey365_evidence.powershell_fabric import REGISTRY, SETTINGS, _script


def record(enabled, *, groups=None, properties=None):
    setting = {"enabled": enabled}
    if groups is not None:
        setting["enabledSecurityGroups"] = groups
    if properties is not None:
        setting["properties"] = properties
    return {"found": True, "setting": setting}


def test_all_fabric_controls_are_registered():
    assert len(REGISTRY) == len(SETTINGS) == 12


def test_fabric_script_uses_one_read_only_request():
    text = _script(["9.1.5", "9.1.9"], "result.json")
    assert text.count("Invoke-RestMethod -Method Get") == 1
    assert "api.fabric.microsoft.com/v1/admin/tenantsettings" in text
    assert "-Method Post" not in text
    assert "-Method Patch" not in text


def test_disabled_or_scoped_controls():
    assert evaluate_fabric("9.1.1", record(False)).status == "no_failure"
    assert evaluate_fabric("9.1.1", record(True, groups=[{"id": "group"}])).status == ("no_failure")
    assert evaluate_fabric("9.1.1", record(True)).status == "failure"


def test_direct_fabric_booleans():
    assert evaluate_fabric("9.1.5", record(False)).status == "no_failure"
    assert evaluate_fabric("9.1.5", record(True)).status == "failure"
    assert evaluate_fabric("9.1.9", record(True)).status == "no_failure"
    assert evaluate_fabric("9.1.9", record(False)).status == "failure"


def test_publish_to_web_requires_existing_codes_and_scope():
    good = record(True, groups=[{"id": "group"}], properties={"createP2w": False})
    assert evaluate_fabric("9.1.4", good).status == "no_failure"
    assert (
        evaluate_fabric(
            "9.1.4", record(True, groups=[{"id": "group"}], properties={"createP2w": True})
        ).status
        == "failure"
    )
    assert evaluate_fabric("9.1.4", record(True, properties={"createP2w": False})).status == (
        "failure"
    )


def test_missing_setting_is_unknown():
    assert evaluate_fabric("9.1.9", {"found": False, "setting": None}).status == "unknown"
