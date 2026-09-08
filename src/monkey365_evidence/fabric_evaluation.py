"""Evaluate Microsoft Fabric tenant-setting evidence."""

from __future__ import annotations

import json
from typing import Any

from .audit_evaluation import Evaluation

SCOPED_OR_DISABLED = {"9.1.1", "9.1.2", "9.1.3", "9.1.7", "9.1.8", "9.1.10", "9.1.11", "9.1.12"}


def evaluate_fabric(cis: str, data: Any) -> Evaluation:
    if not isinstance(data, dict) or data.get("found") is not True:
        return Evaluation("unknown", detail="Fabric tenant setting was not returned exactly once")
    setting = data.get("setting")
    if not isinstance(setting, dict) or type(setting.get("enabled")) is not bool:
        return Evaluation("unknown", detail="Fabric setting enabled state is missing or malformed")
    enabled = setting["enabled"]
    if cis in SCOPED_OR_DISABLED:
        if not enabled:
            return Evaluation("no_failure", detail="Fabric setting is disabled")
        groups = setting.get("enabledSecurityGroups")
        if isinstance(groups, list) and groups:
            return Evaluation(
                "no_failure", detail="Fabric setting is restricted to security groups"
            )
        return Evaluation(
            "failure",
            ('"enabled": true',),
            "Fabric setting is enabled without a security-group restriction",
        )
    if cis == "9.1.4":
        if not enabled:
            return Evaluation("no_failure", detail="Publish to web is disabled")
        properties = setting.get("properties")
        create = properties.get("createP2w") if isinstance(properties, dict) else None
        groups = setting.get("enabledSecurityGroups")
        if create is False and isinstance(groups, list) and groups:
            return Evaluation("no_failure", detail="Only existing embed codes are group-scoped")
        terms = ['"enabled": true']
        if create is not None:
            terms.append(json.dumps(create))
        return Evaluation("failure", tuple(terms), "Publish to web is not sufficiently restricted")
    expected = {"9.1.5": False, "9.1.6": True, "9.1.9": True}.get(cis)
    if expected is None:
        return Evaluation("unknown", detail=f"No Fabric evaluator is defined for CIS control {cis}")
    if enabled != expected:
        return Evaluation(
            "failure",
            (f'"enabled": {str(enabled).lower()}',),
            "Fabric setting does not match the required state",
        )
    return Evaluation("no_failure", detail="Fabric setting matches the required state")
