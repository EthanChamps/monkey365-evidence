"""Conservative evaluation of linked Defender policy and rule evidence."""

from __future__ import annotations

from typing import Any

from .audit_evaluation import Evaluation

_SAFE = {
    "EnableSafeLinksForEmail": True,
    "EnableSafeLinksForTeams": True,
    "EnableSafeLinksForOffice": True,
    "TrackClicks": True,
    "AllowClickThrough": False,
    "ScanUrls": True,
    "EnableForInternalSenders": True,
    "DeliverMessageAfterScan": True,
    "DisableUrlRewrite": False,
}
_PHISH = {
    "Enabled": True,
    "PhishThresholdLevel": 3,
    "EnableTargetedUserProtection": True,
    "EnableOrganizationDomainsProtection": True,
    "EnableMailboxIntelligence": True,
    "EnableMailboxIntelligenceProtection": True,
    "EnableSpoofIntelligence": True,
    "TargetedUserProtectionAction": "Quarantine",
    "TargetedDomainProtectionAction": "Quarantine",
    "MailboxIntelligenceProtectionAction": "Quarantine",
    "EnableFirstContactSafetyTips": True,
    "EnableSimilarUsersSafetyTips": True,
    "EnableSimilarDomainsSafetyTips": True,
    "EnableUnusualCharactersSafetyTips": True,
    "HonorDmarcPolicy": True,
}
_EXCLUSIONS = ("ExceptIfSentTo", "ExceptIfSentToMemberOf", "ExceptIfRecipientDomainIs")


def _items(value: Any) -> list[dict[str, Any]]:
    return value if isinstance(value, list) else [value] if isinstance(value, dict) else []


def _has(value: Any) -> bool:
    return value is not None and value != "" and value != []


def _same(actual: Any, expected: Any) -> bool:
    return type(actual) is type(expected) and actual == expected


def _coverage_proven(rule: dict[str, Any], majority: bool) -> bool:
    if rule.get("OrganizationCoverage") is True:
        return True
    percent = rule.get("CoveragePercent")
    return type(percent) in (int, float) and percent >= (50 if majority else 100)


def evaluate_defender(control_id: str, data: dict[str, Any]) -> Evaluation:
    """Evaluate linked policy/rule data; unproven coverage remains unknown."""
    if not isinstance(data, dict):
        return Evaluation("unknown", detail="Structured policy data is missing")
    policies, rules = _items(data.get("Policies")), _items(data.get("Rules"))
    expected, majority, link_key = (
        (_SAFE, False, "SafeLinksPolicy")
        if control_id == "2.1.1"
        else (_PHISH, True, "AntiPhishPolicy")
        if control_id == "2.1.7"
        else (None, False, "")
    )
    if expected is None:
        raise ValueError(f"Unsupported Defender evaluation control: {control_id}")
    for policy in policies:
        ids = {x for x in (policy.get("Identity"), policy.get("Name")) if x}
        linked = [r for r in rules if r.get(link_key) and r.get(link_key) in ids]
        enabled = [r for r in linked if str(r.get("State", "")).lower() == "enabled"]
        if not enabled or not any(_coverage_proven(r, majority) for r in enabled):
            continue
        if any(_has(r.get(k)) for r in enabled for k in _EXCLUSIONS):
            return Evaluation(
                "unknown", detail="Linked rule has exclusions requiring coverage review"
            )
        if control_id == "2.1.7":
            targets = policy.get("TargetedUsersToProtect")
            if not _has(targets) or len(_items(targets)) > 350:
                continue
        matches = all(
            (
                _same(policy.get(k), v)
                if k != "PhishThresholdLevel"
                else type(policy.get(k)) is int and policy.get(k) >= v
            )
            for k, v in expected.items()
        )
        return Evaluation(
            "no_failure" if matches else "failure",
            detail="Linked settings and effective coverage are proven"
            if matches
            else "Linked policy settings do not meet requirements",
        )
    return Evaluation(
        "unknown", detail="Policy settings checked; effective organization coverage is not proven"
    )
