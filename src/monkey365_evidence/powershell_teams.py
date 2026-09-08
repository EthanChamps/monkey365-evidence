"""Bounded, read-only Microsoft Teams audit command runner."""

from __future__ import annotations

import json
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path
from uuid import UUID

from .powershell_audit import AuditResult, AuditSpec, powershell_executable

_REGISTRY = (
    AuditSpec(
        "8.1.1",
        "Get-CsTeamsClientConfiguration -Identity Global | Select-Object AllowDropbox,AllowBox,AllowGoogleDrive,AllowShareFile,AllowEgnyte",
        "Get-CsTeamsClientConfiguration -Identity Global | Select-Object AllowDropbox,AllowBox,AllowGoogleDrive,AllowShareFile,AllowEgnyte",
        {"providers": "organization-approved only"},
    ),
    AuditSpec(
        "8.1.2",
        "Get-CsTeamsClientConfiguration -Identity Global | Select-Object AllowEmailIntoChannel",
        "Get-CsTeamsClientConfiguration -Identity Global | Select-Object AllowEmailIntoChannel",
        {"AllowEmailIntoChannel": False},
    ),
    AuditSpec(
        "8.2.1",
        "[pscustomobject]@{Policy=(Get-CsExternalAccessPolicy -Identity Global | Select-Object EnableFederationAccess);Organization=(Get-CsTenantFederationConfiguration | Select-Object AllowFederatedUsers,AllowedDomains)}",
        "[pscustomobject]@{Policy=(Get-CsExternalAccessPolicy -Identity Global | Select-Object EnableFederationAccess);Organization=(Get-CsTenantFederationConfiguration | Select-Object AllowFederatedUsers,AllowedDomains)}",
        {"external_domains": "disabled or restricted"},
    ),
    AuditSpec(
        "8.2.2",
        "[pscustomobject]@{Policy=(Get-CsExternalAccessPolicy -Identity Global | Select-Object EnableTeamsConsumerAccess);Organization=(Get-CsTenantFederationConfiguration | Select-Object AllowTeamsConsumer)}",
        "[pscustomobject]@{Policy=(Get-CsExternalAccessPolicy -Identity Global | Select-Object EnableTeamsConsumerAccess);Organization=(Get-CsTenantFederationConfiguration | Select-Object AllowTeamsConsumer)}",
        {"consumer_access": False},
    ),
    AuditSpec(
        "8.2.3",
        "[pscustomobject]@{Policy=(Get-CsExternalAccessPolicy -Identity Global | Select-Object EnableTeamsConsumerInbound);Organization=(Get-CsTenantFederationConfiguration | Select-Object AllowTeamsConsumerInbound)}",
        "[pscustomobject]@{Policy=(Get-CsExternalAccessPolicy -Identity Global | Select-Object EnableTeamsConsumerInbound);Organization=(Get-CsTenantFederationConfiguration | Select-Object AllowTeamsConsumerInbound)}",
        {"consumer_inbound": False},
    ),
    AuditSpec(
        "8.2.4",
        "Get-CsTenantFederationConfiguration | Select-Object ExternalAccessWithTrialTenants",
        "Get-CsTenantFederationConfiguration | Select-Object ExternalAccessWithTrialTenants",
        {"ExternalAccessWithTrialTenants": "Blocked"},
    ),
    AuditSpec(
        "8.5.1",
        "Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowAnonymousUsersToJoinMeeting",
        "Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowAnonymousUsersToJoinMeeting",
        {"AllowAnonymousUsersToJoinMeeting": False},
    ),
    AuditSpec(
        "8.5.2",
        "Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowAnonymousUsersToStartMeeting",
        "Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowAnonymousUsersToStartMeeting",
        {"AllowAnonymousUsersToStartMeeting": False},
    ),
    AuditSpec(
        "8.5.3",
        "Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AutoAdmittedUsers",
        "Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AutoAdmittedUsers",
        {
            "AutoAdmittedUsers": [
                "InvitedUsers",
                "EveryoneInCompanyExcludingGuests",
                "OrganizerOnly",
            ]
        },
    ),
    AuditSpec(
        "8.5.4",
        "Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowPSTNUsersToBypassLobby",
        "Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowPSTNUsersToBypassLobby",
        {"AllowPSTNUsersToBypassLobby": False},
    ),
    AuditSpec(
        "8.5.5",
        "Get-CsTeamsMeetingPolicy -Identity Global | Select-Object MeetingChatEnabledType",
        "Get-CsTeamsMeetingPolicy -Identity Global | Select-Object MeetingChatEnabledType",
        {"MeetingChatEnabledType": ["Disabled", "EnabledExceptAnonymous"]},
    ),
    AuditSpec(
        "8.5.6",
        "Get-CsTeamsMeetingPolicy -Identity Global | Select-Object DesignatedPresenterRoleMode",
        "Get-CsTeamsMeetingPolicy -Identity Global | Select-Object DesignatedPresenterRoleMode",
        {"DesignatedPresenterRoleMode": "OrganizerOnlyUserOverride"},
    ),
    AuditSpec(
        "8.5.7",
        "Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowExternalParticipantGiveRequestControl",
        "Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowExternalParticipantGiveRequestControl",
        {"AllowExternalParticipantGiveRequestControl": False},
    ),
    AuditSpec(
        "8.5.8",
        "Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowExternalNonTrustedMeetingChat",
        "Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowExternalNonTrustedMeetingChat",
        {"AllowExternalNonTrustedMeetingChat": False},
    ),
    AuditSpec(
        "8.5.9",
        "Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowCloudRecording",
        "Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowCloudRecording",
        {"AllowCloudRecording": False},
    ),
)

REGISTRY = {spec.cis: spec for spec in _REGISTRY}


def _script(selected: list[AuditSpec], result_path: str) -> str:
    lines = [
        "param([string]$ExpectedTenantId)",
        "$ErrorActionPreference = 'Stop'",
        "$connect = @{}; if ($ExpectedTenantId) { $connect.TenantId = $ExpectedTenantId }",
        "Connect-MicrosoftTeams @connect | Out-Null",
        "if ($ExpectedTenantId) { $tenant = Get-CsTenant; if ([string]$tenant.TenantId -ne $ExpectedTenantId) { throw 'Connected Teams tenant does not match expected tenant ID' } }",
        "$records = [System.Collections.Generic.List[object]]::new()",
    ]
    for spec in selected:
        command = spec.command.replace("'", "''")
        lines.extend(
            [
                "try {",
                f"  $json = @({spec.script}) | ConvertTo-Json -Compress -Depth 12",
                "  $plain = ConvertFrom-Json -InputObject ('{\"items\":' + $json + '}')",
                f"  $records.Add([pscustomobject]@{{cis='{spec.cis}';command='{command}';output=$json;data=$plain.items;status='collected';error=$null}})",
                "} catch {",
                f"  $records.Add([pscustomobject]@{{cis='{spec.cis}';command='{command}';output='';data=$null;status='failed';error=$_.Exception.Message}})",
                "}",
            ]
        )
    escaped = result_path.replace("'", "''")
    lines.append(
        f"$records | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath '{escaped}' -Encoding UTF8"
    )
    return "\n".join(lines) + "\n"


def run_audits(
    control_ids: list[str],
    output_dir: Path,
    *,
    expected_tenant_id: str | None = None,
    pwsh: str = "pwsh",
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> list[AuditResult]:
    requested = list(control_ids)
    unknown = sorted(set(requested) - REGISTRY.keys())
    if unknown:
        raise ValueError("Unsupported Teams audit control(s): " + ", ".join(unknown))
    if not requested:
        return []
    if expected_tenant_id is not None:
        try:
            UUID(expected_tenant_id)
        except (ValueError, AttributeError) as error:
            raise ValueError("expected_tenant_id must be a UUID") from error
    selected = [REGISTRY[cis] for cis in requested]
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", suffix=".ps1", prefix="teams-audit-", dir=output_dir, encoding="utf-8", delete=False
    ) as handle:
        script_path = Path(handle.name)
    with tempfile.NamedTemporaryFile(
        "w", suffix=".json", prefix="teams-results-", dir=output_dir, encoding="utf-8", delete=False
    ) as handle:
        result_path = Path(handle.name)
    script_path.write_text(_script(selected, str(result_path)), encoding="utf-8")
    argv = [
        powershell_executable(pwsh),
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(script_path),
    ]
    if expected_tenant_id:
        argv.extend(["-ExpectedTenantId", expected_tenant_id])
    try:
        completed = runner(argv, cwd=str(output_dir), capture_output=True, text=True, check=False)
        if completed.returncode:
            detail = (completed.stderr or completed.stdout or "Teams PowerShell failed").strip()
            return [
                AuditResult(s.cis, s.command, completed.stdout or "", None, "failed", detail)
                for s in selected
            ]
        try:
            payload = json.loads(result_path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as error:
            return [
                AuditResult(
                    s.cis, s.command, "", None, "failed", f"Invalid Teams result transport: {error}"
                )
                for s in selected
            ]
        if isinstance(payload, dict):
            payload = [payload]
        records = {str(item.get("cis")): item for item in payload if isinstance(item, dict)}
        results = []
        for spec in selected:
            item = records.get(spec.cis)
            if not item:
                results.append(
                    AuditResult(
                        spec.cis, spec.command, "", None, "failed", "Missing Teams result record"
                    )
                )
                continue
            data = item.get("data")
            output = str(item.get("output", ""))
            status = (
                "collected"
                if item.get("status") == "collected" and data is not None and output
                else "failed"
            )
            results.append(
                AuditResult(spec.cis, spec.command, output, data, status, item.get("error"))
            )
        return results
    finally:
        script_path.unlink(missing_ok=True)
        result_path.unlink(missing_ok=True)
