"""Strict, read-only evaluation of selected Exchange Online audit results."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Evaluation:
    status: str
    highlight_terms: tuple[str, ...] = ()
    detail: str = ""


_ROLES = ("My Custom Apps", "My Marketplace Apps", "My ReadWriteMailbox Apps")


def _term(key: str, value: Any) -> str:
    return f'{json.dumps(key, ensure_ascii=False)}: {json.dumps(value, ensure_ascii=False)}'


def _values(data: Any, key: str) -> list[Any]:
    return [value for _, value in _entries(data, key)]


def _entries(data: Any, key: str) -> list[tuple[str, Any]]:
    found: list[tuple[str, Any]] = []
    if isinstance(data, dict):
        for name, value in data.items():
            if isinstance(name, str) and name.casefold() == key.casefold():
                found.append((name, value))
            found.extend(_entries(value, key))
    elif isinstance(data, list):
        for value in data:
            found.extend(_entries(value, key))
    return found


def _one_bool(data: Any, key: str) -> tuple[bool | None, str | None]:
    entries = _entries(data, key)
    if len(entries) != 1 or type(entries[0][1]) is not bool:
        return None, None
    actual_key, value = entries[0]
    return value, _term(actual_key, value)


def _failure(terms: list[str], detail: str) -> Evaluation:
    return Evaluation("failure", tuple(terms), detail)


def _records(data: Any, keys: tuple[str, ...]) -> list[dict[str, Any]] | None:
    keyset = {key.casefold() for key in keys}
    if isinstance(data, dict):
        if any(isinstance(name, str) and name.casefold() in keyset for name in data):
            return [data]
        for value in data.values():
            nested = _records(value, keys)
            if nested is not None:
                return nested
        return None
    if isinstance(data, list) and data and all(isinstance(item, dict) for item in data):
        return data
    return None


def _record_entry(record: dict[str, Any], key: str) -> tuple[str, Any] | None:
    entries = [(name, value) for name, value in record.items()
               if isinstance(name, str) and name.casefold() == key.casefold()]
    return entries[0] if len(entries) == 1 else None


def evaluate_audit(cis: str, data: Any) -> Evaluation:
    """Evaluate the six bounded EXO controls; all other controls are unknown."""
    if cis == "1.3.6":
        value, term = _one_bool(data, "CustomerLockBoxEnabled")
        if value is None:
            return Evaluation("unknown", detail="CustomerLockBoxEnabled is missing, null, or not a boolean")
        return _failure([term], "CustomerLockBoxEnabled must be true") if not value else Evaluation("no_failure", detail="CustomerLockBoxEnabled is true")

    if cis == "1.3.9":
        default, dterm = _one_bool(data, "BookingsMailboxCreationEnabled")
        org, oterm = _one_bool(data, "BookingsEnabled")
        if default is False or org is False:
            return Evaluation("no_failure", detail="Bookings is disabled by an accepted policy or organization setting")
        if default is True and org is True:
            return _failure([dterm, oterm], "Both the default OWA policy and organization Bookings setting are enabled")
        return Evaluation("unknown", detail="Bookings alternative is incomplete or contains missing/null/non-boolean data")

    if cis == "6.3.1":
        roles = _values(data, "AssignedRoles")
        if len(roles) != 1 or roles[0] is None or not isinstance(roles[0], list) or any(not isinstance(role, str) for role in roles[0]):
            return Evaluation("unknown", detail="AssignedRoles is missing, null, or not a list of strings")
        offending = [role for role in roles[0] if role in _ROLES]
        return _failure([json.dumps(role, ensure_ascii=False) for role in offending], "Default role assignment includes a prohibited personal app role") if offending else Evaluation("no_failure", detail="Default role assignment excludes prohibited personal app roles")

    if cis == "6.3.2":
        a, at = _one_bool(data, "PersonalAccountsEnabled")
        c, ct = _one_bool(data, "PersonalAccountCalendarsEnabled")
        if a is True or c is True:
            terms = [term for value, term in ((a, at), (c, ct)) if value is True]
            return _failure(terms, "A personal account setting is enabled; both settings must be disabled")
        if a is False and c is False:
            return Evaluation("no_failure", detail="Personal accounts and personal calendars are disabled")
        return Evaluation("unknown", detail="Personal account settings are incomplete or contain missing/null/non-boolean data")

    if cis == "6.5.2":
        terms: list[str] = []
        for key in ("MailTipsAllTipsEnabled", "MailTipsExternalRecipientsTipsEnabled", "MailTipsGroupMetricsEnabled"):
            value, key_term = _one_bool(data, key)
            if value is None:
                return Evaluation("unknown", detail=f"{key} is missing, null, or not a boolean")
            if not value:
                terms.append(key_term)
        if terms:
            return _failure(terms, "Required MailTips settings are disabled")
        return Evaluation("unknown", detail="MailTips booleans pass; MailTipsLargeAudienceThreshold requires human review")

    if cis == "6.5.3":
        value, term = _one_bool(data, "AdditionalStorageProvidersAvailable")
        if value is None:
            return Evaluation("unknown", detail="AdditionalStorageProvidersAvailable is missing, null, or not a boolean")
        return _failure([term], "Additional storage providers are enabled") if value else Evaluation("no_failure", detail="Additional storage providers are disabled")

    if cis in {"6.1.1", "6.2.3", "6.5.5"}:
        key, expected, failure_detail, pass_detail = {
            "6.1.1": ("AuditDisabled", False, "Microsoft 365 auditing is disabled",
                      "Microsoft 365 auditing is enabled"),
            "6.2.3": ("Enabled", True, "External sender identification is disabled",
                      "External sender identification is enabled"),
            "6.5.5": ("RejectDirectSend", True, "Direct Send submissions are not rejected",
                      "Direct Send submissions are rejected"),
        }[cis]
        value, term = _one_bool(data, key)
        if value is None:
            return Evaluation("unknown", detail=f"{key} is missing, null, or not a boolean")
        if value != expected:
            return _failure([term], failure_detail)
        return Evaluation("no_failure", detail=pass_detail)

    if cis == "6.1.3":
        entries = _entries(data, "BypassedMailboxes")
        if len(entries) != 1 or not isinstance(entries[0][1], list):
            return Evaluation("unknown", detail="BypassedMailboxes is missing, null, or not a list")
        bypassed = entries[0][1]
        if bypassed:
            terms = [json.dumps(item, ensure_ascii=False) for item in bypassed]
            return _failure(terms, "One or more mailboxes bypass mailbox auditing")
        return Evaluation("no_failure", detail="No mailboxes bypass mailbox auditing")

    if cis == "2.1.3":
        records = _records(data, ("EnableInternalSenderAdminNotifications", "InternalSenderAdminAddress"))
        if records is None:
            return Evaluation("unknown", detail="Anti-malware policy records are missing or have unknown scope")
        terms: list[str] = []
        for record in records:
            flag = _record_entry(record, "EnableInternalSenderAdminNotifications")
            address = _record_entry(record, "InternalSenderAdminAddress")
            if flag is None or address is None or type(flag[1]) is not bool or not isinstance(address[1], str):
                return Evaluation("unknown", detail="Anti-malware policy fields are missing, null, or malformed")
            if not flag[1]:
                terms.append(_term(flag[0], flag[1]))
            if not address[1].strip():
                terms.append(_term(address[0], address[1]))
        return _failure(terms, "Internal sender malware notifications are incomplete") if terms else Evaluation("no_failure", detail="All returned anti-malware policies have notifications enabled and an address")

    if cis == "2.1.6":
        keys = ("BccSuspiciousOutboundMail", "BccSuspiciousOutboundAdditionalRecipients", "NotifyOutboundSpam", "NotifyOutboundSpamRecipients")
        records = _records(data, keys)
        if records is None:
            return Evaluation("unknown", detail="Outbound spam policy records are missing or have unknown scope")
        terms: list[str] = []
        for record in records:
            entries = [_record_entry(record, key) for key in keys]
            if any(entry is None for entry in entries):
                return Evaluation("unknown", detail="Outbound spam policy fields are missing, null, or malformed")
            bcc, bcc_recip, notify, notify_recip = entries
            if type(bcc[1]) is not bool or type(notify[1]) is not bool or not isinstance(bcc_recip[1], list) or not isinstance(notify_recip[1], list):
                return Evaluation("unknown", detail="Outbound spam policy fields are missing, null, or malformed")
            if not bcc[1]:
                terms.append(_term(bcc[0], bcc[1]))
            if not notify[1]:
                terms.append(_term(notify[0], notify[1]))
            if not bcc_recip[1]:
                terms.append(_term(bcc_recip[0], bcc_recip[1]))
            if not notify_recip[1]:
                terms.append(_term(notify_recip[0], notify_recip[1]))
        return _failure(terms, "Outbound spam administrator notification settings are incomplete") if terms else Evaluation("no_failure", detail="All returned outbound spam policies have notification flags and recipients")

    if cis in {"2.1.12", "2.1.14"}:
        key = "IPAllowList" if cis == "2.1.12" else "AllowedSenderDomains"
        records = _records(data, (key,))
        entries = [_record_entry(record, key) for record in records] if records else []
        if not entries or any(entry is None for entry in entries):
            return Evaluation("unknown", detail=f"{key} is missing from one or more policy records")
        values = [entry[1] for entry in entries]
        if any(value is None or not isinstance(value, list) or any(not isinstance(item, str) for item in value) for value in values):
            return Evaluation("unknown", detail=f"{key} is missing, null, or not a list of strings for every policy")
        offending = [item for value in values for item in value]
        if offending:
            return _failure([json.dumps(item, ensure_ascii=False) for item in offending], f"{key} contains entries; every policy must have an empty list")
        return Evaluation("no_failure", detail=f"{key} is empty for every policy")

    return Evaluation("unknown", detail=f"No evaluator is defined for CIS control {cis}")
