"""Conservative evaluation for fixed Microsoft Graph audit collections."""
from __future__ import annotations

import json
from typing import Any

from .audit_evaluation import Evaluation

_CA_CONTROLS = {"5.2.2.1", "5.2.2.4", "5.2.2.5", "5.2.2.6", "5.2.2.7", "5.2.2.10", "5.2.2.11", "5.2.2.13"}


def evaluate_graph(cis: str, data: Any) -> Evaluation:
    """Evaluate only facts that the bounded Graph collectors return directly."""
    if cis in _CA_CONTROLS:
        if not isinstance(data, list):
            return Evaluation("unknown", detail="Conditional Access collection is missing or malformed")
        if not data:
            return Evaluation("failure", ("[]",), "No Conditional Access policies were returned")
        return Evaluation("unknown", detail="Conditional Access policies were returned; semantic coverage requires policy-level evaluation")

    if cis == "1.2.1":
        if not isinstance(data, list):
            return Evaluation("unknown", detail="Group collection is missing or malformed")
        if not data:
            return Evaluation("no_failure", detail="No public groups were returned")
        return Evaluation("unknown", detail="Public groups were returned; documented business exceptions require manual review")

    if cis == "1.3.2":
        if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict):
            return Evaluation("unknown", detail="Idle timeout collection is missing or malformed")
        record = data[0]
        if "TimeoutPolicy" not in record or "ConditionalAccessPolicies" not in record:
            return Evaluation("unknown", detail="Idle timeout or Conditional Access field is missing")
        failures = []
        if record["TimeoutPolicy"] is None:
            failures.append('"TimeoutPolicy": null')
        elif record["TimeoutPolicy"] == []:
            failures.append('"TimeoutPolicy": []')
        elif not isinstance(record["TimeoutPolicy"], (dict, list)):
            return Evaluation("unknown", detail="TimeoutPolicy is malformed; timeout value requires manual review")
        if record["ConditionalAccessPolicies"] is None:
            failures.append('"ConditionalAccessPolicies": null')
        elif record["ConditionalAccessPolicies"] == []:
            failures.append('"ConditionalAccessPolicies": []')
        elif not isinstance(record["ConditionalAccessPolicies"], list):
            return Evaluation("unknown", detail="ConditionalAccessPolicies is malformed")
        if failures:
            return Evaluation("failure", tuple(failures), "Idle timeout or its required unmanaged-device Conditional Access policy is absent")
        return Evaluation("unknown", detail="Idle timeout and Conditional Access data are present; semantic coverage requires policy-level evaluation")

    if cis == "1.1.4":
        return Evaluation("unknown", detail="Administrative license appropriateness requires manual review of privileged role members and assigned SKUs")

    if cis == "5.2.3.4":
        if not isinstance(data, list):
            return Evaluation("unknown", detail="User registration collection is missing or malformed")
        members = []
        for user in data:
            if not isinstance(user, dict):
                return Evaluation("unknown", detail="User registration record is malformed")
            user_type = user.get("UserType")
            if user_type is None or not isinstance(user_type, str):
                return Evaluation("unknown", detail="UserType is missing or malformed; guest exclusion cannot be verified")
            if user_type.casefold() == "guest":
                continue
            if user_type.casefold() != "member" or type(user.get("IsMfaCapable")) is not bool:
                return Evaluation("unknown", detail="Member user record lacks a boolean IsMfaCapable value")
            members.append(user)
        if not members:
            return Evaluation("unknown", detail="No member users were returned after excluding guests")
        failures = []
        for user in members:
            if user["IsMfaCapable"] is False:
                upn = user.get("UserPrincipalName")
                if not isinstance(upn, str) or not upn:
                    return Evaluation("unknown", detail="A non-MFA-capable member lacks UserPrincipalName identity")
                failures.append(json.dumps(upn, ensure_ascii=False))
        if failures:
            return Evaluation("failure", tuple(failures), "One or more identified member users have IsMfaCapable set to false")
        return Evaluation("no_failure", detail="All returned member users are MFA capable; guest users were excluded")

    return Evaluation("unknown", detail=f"No Graph evaluator is defined for CIS control {cis}")
