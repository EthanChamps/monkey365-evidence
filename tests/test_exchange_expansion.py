from monkey365_evidence.audit_evaluation import evaluate_audit
from monkey365_evidence.powershell_audit import REGISTRY


def test_exchange_expansion_is_registered():
    assert {"6.1.1", "6.1.3", "6.2.3", "6.5.5"} <= REGISTRY.keys()


def test_boolean_exchange_controls_fail_closed():
    cases = {
        "6.1.1": ("AuditDisabled", False),
        "6.2.3": ("Enabled", True),
        "6.5.5": ("RejectDirectSend", True),
    }
    for cis, (key, expected) in cases.items():
        assert evaluate_audit(cis, {key: expected}).status == "no_failure"
        assert evaluate_audit(cis, {key: not expected}).status == "failure"
        assert evaluate_audit(cis, {key: None}).status == "unknown"


def test_mailbox_audit_bypass_requires_an_empty_list():
    assert evaluate_audit("6.1.3", {"BypassedMailboxes": []}).status == "no_failure"
    result = evaluate_audit(
        "6.1.3",
        {"BypassedMailboxes": [{"Identity": "example", "AuditBypassEnabled": True}]},
    )
    assert result.status == "failure"
    assert evaluate_audit("6.1.3", {"BypassedMailboxes": None}).status == "unknown"
