"""Evaluate fixed Microsoft Teams Global-policy audit results."""

from __future__ import annotations

import json
from typing import Any

from .audit_evaluation import Evaluation


def _find(data: Any, key: str) -> list[Any]:
    values = []
    if isinstance(data, dict):
        for name, value in data.items():
            if isinstance(name, str) and name.casefold() == key.casefold():
                values.append(value)
            values.extend(_find(value, key))
    elif isinstance(data, list):
        for value in data:
            values.extend(_find(value, key))
    return values


def _single(data: Any, key: str) -> Any:
    values = _find(data, key)
    return values[0] if len(values) == 1 else None


def evaluate_teams(cis: str, data: Any) -> Evaluation:
    if cis == "8.4.1":
        return Evaluation("unknown", detail="App permission policies were collected; confirm org-wide app defaults in the Teams admin center")
    if cis == "8.6.1":
        enabled = _single(data, "AllowSecurityEndUserReporting")
        if type(enabled) is not bool:
            return Evaluation("unknown", detail="AllowSecurityEndUserReporting is missing or malformed")
        if enabled is False:
            return Evaluation("failure", ('"AllowSecurityEndUserReporting": false',), "Security concern reporting is disabled in Teams")
        return Evaluation("unknown", detail="Teams reporting is enabled; confirm the Defender reporting mailbox settings")
    if cis == "8.1.1":
        return Evaluation(
            "unknown",
            detail="Enabled cloud storage providers require comparison with the organization's approved list",
        )
    boolean_false = {
        "8.1.2": "AllowEmailIntoChannel",
        "8.5.1": "AllowAnonymousUsersToJoinMeeting",
        "8.5.2": "AllowAnonymousUsersToStartMeeting",
        "8.5.4": "AllowPSTNUsersToBypassLobby",
        "8.5.7": "AllowExternalParticipantGiveRequestControl",
        "8.5.8": "AllowExternalNonTrustedMeetingChat",
        "8.5.9": "AllowCloudRecording",
    }
    if cis in boolean_false:
        key = boolean_false[cis]
        value = _single(data, key)
        if type(value) is not bool:
            return Evaluation("unknown", detail=f"{key} is missing, null, or not a boolean")
        if value:
            return Evaluation("failure", (f'"{key}": true',), f"{key} must be false")
        return Evaluation("no_failure", detail=f"{key} is false")
    if cis in {"8.2.2", "8.2.3"}:
        keys = (
            ("EnableTeamsConsumerAccess", "AllowTeamsConsumer")
            if cis == "8.2.2"
            else ("EnableTeamsConsumerInbound", "AllowTeamsConsumerInbound")
        )
        values = [_single(data, key) for key in keys]
        if any(type(value) is not bool for value in values):
            return Evaluation("unknown", detail="Consumer access settings are incomplete")
        if any(value is False for value in values):
            return Evaluation(
                "no_failure", detail="Consumer access is disabled by policy or organization setting"
            )
        return Evaluation(
            "failure", tuple(f'"{key}": true' for key in keys), "Consumer Teams access is enabled"
        )
    if cis == "8.2.1":
        enabled = _single(data, "EnableFederationAccess")
        org_enabled = _single(data, "AllowFederatedUsers")
        domains = _single(data, "AllowedDomains")
        if enabled is False or org_enabled is False:
            return Evaluation("no_failure", detail="External federation is disabled")
        if type(enabled) is not bool or type(org_enabled) is not bool:
            return Evaluation("unknown", detail="External federation settings are incomplete")
        if domains:
            return Evaluation(
                "unknown",
                detail="External domains are restricted; allow/block entries require review",
            )
        return Evaluation(
            "failure",
            ('"EnableFederationAccess": true', '"AllowFederatedUsers": true'),
            "External federation is enabled without a visible domain restriction",
        )
    expected_strings = {
        "8.2.4": ("ExternalAccessWithTrialTenants", {"Blocked"}),
        "8.5.3": (
            "AutoAdmittedUsers",
            {"InvitedUsers", "EveryoneInCompanyExcludingGuests", "OrganizerOnly"},
        ),
        "8.5.5": ("MeetingChatEnabledType", {"Disabled", "EnabledExceptAnonymous"}),
        "8.5.6": ("DesignatedPresenterRoleMode", {"OrganizerOnlyUserOverride"}),
    }
    if cis in expected_strings:
        key, accepted = expected_strings[cis]
        value = _single(data, key)
        if not isinstance(value, str):
            return Evaluation("unknown", detail=f"{key} is missing, null, or not text")
        if value not in accepted:
            return Evaluation("failure", (json.dumps(value),), f"{key} is not an accepted value")
        return Evaluation("no_failure", detail=f"{key} is set to an accepted value")
    return Evaluation("unknown", detail=f"No Teams evaluator is defined for CIS control {cis}")
