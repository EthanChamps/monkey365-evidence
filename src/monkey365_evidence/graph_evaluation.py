"""Conservative evaluation for fixed Microsoft Graph audit collections."""
from __future__ import annotations

import json
from datetime import datetime
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

    if cis == "1.1.1":
        if not isinstance(data, list):
            return Evaluation("unknown", detail="Privileged-user collection is malformed")
        synced = [user for user in data if isinstance(user, dict)
                  and user.get("OnPremisesSyncEnabled") is True]
        if synced:
            terms = tuple(json.dumps(user.get("UserPrincipalName"), ensure_ascii=False)
                          for user in synced if user.get("UserPrincipalName"))
            return Evaluation("failure", terms, "One or more privileged users are synchronized from on-premises")
        if any(not isinstance(user, dict) or "OnPremisesSyncEnabled" not in user for user in data):
            return Evaluation("unknown", detail="A privileged-user record is missing its synchronization state")
        return Evaluation("no_failure", detail="Returned privileged users are cloud-only")

    if cis == "1.1.2":
        return Evaluation("unknown", detail="Identify and verify exactly two monitored emergency access accounts from this active-user inventory")

    if cis == "1.1.3":
        if not isinstance(data, list):
            return Evaluation("unknown", detail="Global Administrator membership is malformed")
        count = len({item.get("Id") for item in data if isinstance(item, dict) and item.get("Id")})
        if count != len(data):
            return Evaluation("unknown", detail="A Global Administrator member lacks a unique ID")
        if not 2 <= count <= 4:
            return Evaluation("failure", (f'"count": {count}',), f"Global Administrator count is {count}; CIS requires 2 to 4")
        return Evaluation("no_failure", detail=f"Global Administrator count is {count}")

    if cis == "5.1.5.2":
        records = data if isinstance(data, list) else []
        if len(records) != 1 or not isinstance(records[0], dict) or type(records[0].get("IsEnabled")) is not bool:
            return Evaluation("unknown", detail="Admin consent request policy is missing or malformed")
        if records[0]["IsEnabled"] is False:
            return Evaluation("failure", ('"IsEnabled": false',), "Admin consent requests are disabled")
        return Evaluation("no_failure", detail="Admin consent requests are enabled")

    if cis in {"5.1.5.4", "5.1.5.6"}:
        return _evaluate_credential_lifetime(cis, data)

    return Evaluation("unknown", detail=f"No Graph evaluator is defined for CIS control {cis}")


def _evaluate_credential_lifetime(cis: str, data: Any) -> Evaluation:
    if not isinstance(data, list):
        return Evaluation("unknown", detail="Application credential inventory is malformed")
    key = "PasswordCredentials" if cis == "5.1.5.4" else "KeyCredentials"
    failures: list[str] = []
    for app in data:
        if not isinstance(app, dict) or key not in app:
            return Evaluation("unknown", detail=f"An application record is missing {key}")
        credentials = app[key] or []
        if not isinstance(credentials, list):
            return Evaluation("unknown", detail=f"{key} is malformed")
        for credential in credentials:
            if not isinstance(credential, dict):
                return Evaluation("unknown", detail="An application credential is malformed")
            start, end = credential.get("StartDateTime"), credential.get("EndDateTime")
            if not isinstance(start, str) or not isinstance(end, str):
                return Evaluation("unknown", detail="A credential lifetime cannot be calculated")
            try:
                duration = datetime.fromisoformat(end) - datetime.fromisoformat(start)
            except ValueError:
                return Evaluation("unknown", detail="A credential date is invalid")
            if duration.days > 180:
                failures.append(json.dumps(app.get("DisplayName") or app.get("Id"), ensure_ascii=False))
    if failures:
        return Evaluation("failure", tuple(failures), "One or more application credentials exceed 180 days")
    return Evaluation("no_failure", detail="Returned application credentials do not exceed 180 days")
