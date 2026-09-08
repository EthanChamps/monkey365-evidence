"""Evaluate SharePoint Online tenant settings for CIS 7 controls."""

from __future__ import annotations

from typing import Any

from .audit_evaluation import Evaluation


def _record(data: Any) -> dict[str, Any] | None:
    if isinstance(data, dict):
        return data
    if isinstance(data, list) and len(data) == 1 and isinstance(data[0], dict):
        return data[0]
    return None


def _bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.casefold() in {"true", "false"}:
        return value.casefold() == "true"
    return None


def _failure(detail: str, *terms: str) -> Evaluation:
    return Evaluation("failure", detail=detail, highlight_terms=terms)


def evaluate_sharepoint(cis: str, data: Any) -> Evaluation:
    item = _record(data)
    if item is None:
        return Evaluation("unknown", detail="SharePoint returned an unexpected result shape")

    boolean_rules = {
        "7.2.1": ("LegacyAuthProtocolsEnabled", False),
        "7.2.2": ("EnableAzureADB2BIntegration", True),
        "7.2.5": ("PreventExternalUsersFromResharing", True),
        "7.3.1": ("DisallowInfectedFileDownload", True),
    }
    if cis in boolean_rules:
        key, expected = boolean_rules[cis]
        actual = _bool(item.get(key))
        if actual is None:
            return Evaluation("unknown", detail=f"{key} was missing or not boolean")
        if actual != expected:
            return _failure(f"{key} must be {str(expected).lower()}", key, str(actual))
        return Evaluation("no_failure", detail=f"{key} matches the CIS setting")

    allowed = {
        "7.2.3": (
            "SharingCapability",
            {"ExternalUserSharingOnly", "ExistingExternalUserSharingOnly", "Disabled"},
        ),
        "7.2.4": ("OneDriveSharingCapability", {"Disabled"}),
        "7.2.7": ("DefaultSharingLinkType", {"Direct", "Internal"}),
        "7.2.11": ("DefaultLinkPermission", {"View"}),
    }
    if cis in allowed:
        key, expected = allowed[cis]
        value = item.get(key)
        if not isinstance(value, str):
            return Evaluation("unknown", detail=f"{key} was missing or not text")
        if value not in expected:
            return _failure(f"{key} is {value}; expected {', '.join(sorted(expected))}", key, value)
        return Evaluation("no_failure", detail=f"{key} matches the CIS setting")

    if cis == "7.2.6":
        sharing = item.get("SharingCapability")
        if sharing == "Disabled":
            return Evaluation("no_failure", detail="External sharing is disabled")
        mode, domains = (
            item.get("SharingDomainRestrictionMode"),
            item.get("SharingAllowedDomainList"),
        )
        if mode != "AllowList" or not domains:
            return _failure(
                "External sharing is not disabled or restricted to a domain allow list",
                "SharingCapability",
                str(sharing),
                "SharingDomainRestrictionMode",
                str(mode),
            )
        return Evaluation(
            "unknown", detail="A domain allow list exists; confirm its domains are approved"
        )

    if cis == "7.2.8":
        if item.get("SharingCapability") == "Disabled":
            return Evaluation("no_failure", detail="External sharing is disabled")
        groups = item.get("WhoCanShareAuthenticatedGuestAllowList")
        if not groups:
            return _failure(
                "External sharing is not restricted to a security group",
                "WhoCanShareAuthenticatedGuestAllowList",
            )
        return Evaluation(
            "unknown",
            detail="A sharing group is configured; confirm it is the approved security group",
        )

    if cis in {"7.2.9", "7.2.10"}:
        enabled_key, days_key = (
            ("ExternalUserExpirationRequired", "ExternalUserExpireInDays")
            if cis == "7.2.9"
            else ("EmailAttestationRequired", "EmailAttestationReAuthDays")
        )
        enabled = _bool(item.get(enabled_key))
        days = item.get(days_key)
        try:
            days = int(days)
        except (TypeError, ValueError):
            return Evaluation("unknown", detail=f"{days_key} was missing or not numeric")
        valid_days = days == 30 if cis == "7.2.9" else 0 < days <= 15
        if enabled is not True or not valid_days:
            expectation = "30" if cis == "7.2.9" else "15 or fewer"
            return _failure(
                f"{enabled_key} must be true and {days_key} must be {expectation}",
                enabled_key,
                str(enabled),
                days_key,
                str(days),
            )
        return Evaluation("no_failure", detail="Guest expiration setting matches CIS")

    return Evaluation("unknown", detail=f"No SharePoint evaluator exists for CIS {cis}")
    if cis == "7.3.2":
        return Evaluation(
            "unknown",
            detail="This recommendation was removed from CIS v7; current SharePoint unmanaged-device settings were collected for compatibility",
        )
