"""Evaluation for CIS 2.1.15 outbound anti-spam message limits."""

from __future__ import annotations

import json
from typing import Any

from .audit_evaluation import Evaluation

_LIMITS = {
    "RecipientLimitExternalPerHour": 500,
    "RecipientLimitInternalPerHour": 1000,
    "RecipientLimitPerDay": 1000,
}


def _term(name: str, value: Any) -> str:
    return f'{json.dumps(name, ensure_ascii=False)}: {json.dumps(value, ensure_ascii=False)}'


def _records(data: Any) -> list[dict[str, Any]] | None:
    if isinstance(data, dict):
        names = {name.casefold() for name in data if isinstance(name, str)}
        if any(name.casefold() in names for name in (*_LIMITS, "ActionWhenThresholdReached", "NotifyOutboundSpamRecipients")):
            return [data]
        for value in data.values():
            found = _records(value)
            if found is not None:
                return found
        return None
    if isinstance(data, list) and data and all(isinstance(item, dict) for item in data):
        return data
    return None


def _entry(record: dict[str, Any], key: str) -> tuple[str, Any] | None:
    found = [(name, value) for name, value in record.items()
             if isinstance(name, str) and name.casefold() == key.casefold()]
    return found[0] if len(found) == 1 else None


def evaluate_limits(data: Any) -> Evaluation:
    records = _records(data)
    if records is None:
        return Evaluation("unknown", detail="Outbound spam limit policy records are missing or have unknown scope")
    terms: list[str] = []
    for record in records:
        entries = {key: _entry(record, key) for key in (*_LIMITS, "ActionWhenThresholdReached", "NotifyOutboundSpamRecipients")}
        if any(entry is None or entry[1] is None for entry in entries.values()):
            return Evaluation("unknown", detail="Outbound spam limit fields are missing or null")
        for key, maximum in _LIMITS.items():
            actual_key, value = entries[key]
            if type(value) is not int:
                return Evaluation("unknown", detail=f"{key} is not an integer")
            if value == 0 or value < 0 or value > maximum:
                terms.append(_term(actual_key, value))
        action_key, action = entries["ActionWhenThresholdReached"]
        if not isinstance(action, str):
            return Evaluation("unknown", detail="ActionWhenThresholdReached is not a string")
        if action != "BlockUser":
            terms.append(_term(action_key, action))
        recipients_key, recipients = entries["NotifyOutboundSpamRecipients"]
        if not isinstance(recipients, list):
            return Evaluation("unknown", detail="NotifyOutboundSpamRecipients is not a list")
        if not recipients:
            terms.append(_term(recipients_key, recipients))
        elif any(not isinstance(item, str) or item is None for item in recipients):
            return Evaluation("unknown", detail="NotifyOutboundSpamRecipients contains a non-string recipient")
        else:
            for item in recipients:
                if not item.strip():
                    terms.append(_term(recipients_key, item))
    if terms:
        return Evaluation("failure", tuple(terms), "Outbound spam limits or recipient values do not meet CIS 2.1.15 requirements")
    return Evaluation("unknown", detail="Numeric limits and action are valid; recipient monitoring requires human review")
