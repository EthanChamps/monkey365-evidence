import json

from monkey365_evidence.models import Control
from monkey365_evidence.monkey365 import failed_rule_ids, load_rule_map


def test_extracts_failed_rules_only(tmp_path):
    path = tmp_path / "results.json"
    path.write_text(json.dumps([
        {"statusCode": "fail", "findingInfo": {"ruleId": "entra_1"}},
        {"statusCode": "pass", "findingInfo": {"ruleId": "entra_2"}},
    ]))
    assert failed_rule_ids(path) == {"entra_1"}


def test_extracts_current_monkey365_unmapped_and_metadata_ids(tmp_path):
    path = tmp_path / "results.json"
    path.write_text(json.dumps([{
        "statusCode": "fail",
        "unmapped": {"ruleId": "entraid_1141"},
        "metadata": {"eventCode": "reduced_licence_footprint"},
    }]))
    assert failed_rule_ids(path) == {"entraid_1141"}


def test_evidence_filename_is_sanitized():
    control = Control("0.0.0", "Example: setting/value?", "https://entra.microsoft.com", ())
    assert control.filename == "0.0.0 Example_ setting_value_.png"


def test_rule_map_accepts_windows_utf8_bom(tmp_path):
    path = tmp_path / "map.json"
    path.write_bytes(b"\xef\xbb\xbf{\"manual-7.2.4\": \"7.2.4\"}")
    assert load_rule_map(path) == {"manual-7.2.4": "7.2.4"}
