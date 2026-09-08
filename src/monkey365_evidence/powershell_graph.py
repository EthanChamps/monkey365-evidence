"""Fixed, read-only Microsoft Graph audit command registry."""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path

from .powershell_audit import AuditResult, AuditSpec, powershell_executable

_CONTEXT = "$ctx=Get-MgContext; if (-not $ctx) { throw 'Microsoft Graph sign-in did not create a context' }"
_READ_SCOPES = (
    "Policy.Read.All",
    "Reports.Read.All",
    "Group.Read.All",
    "RoleManagement.Read.Directory",
    "User.Read.All",
    "Directory.Read.All",
)
_REGISTRY = (
    AuditSpec(
        "5.2.2.1",
        "Get-MgIdentityConditionalAccessPolicy -All | Select-Object Id,DisplayName,State,Conditions,SessionControls,GrantControls",
        "Get-MgIdentityConditionalAccessPolicy -All | Select-Object Id,DisplayName,State,Conditions,SessionControls,GrantControls",
        {"predicate": "administrator MFA policy"},
    ),
    AuditSpec(
        "5.2.2.4",
        "Get-MgIdentityConditionalAccessPolicy -All | Select-Object Id,DisplayName,State,Conditions,SessionControls,GrantControls",
        "Get-MgIdentityConditionalAccessPolicy -All | Select-Object Id,DisplayName,State,Conditions,SessionControls,GrantControls",
        {"predicate": "administrator sign-in frequency and persistent browser never"},
    ),
    AuditSpec(
        "5.2.2.5",
        "Get-MgIdentityConditionalAccessPolicy -All | Select-Object Id,DisplayName,State,Conditions,SessionControls,GrantControls",
        "Get-MgIdentityConditionalAccessPolicy -All | Select-Object Id,DisplayName,State,Conditions,SessionControls,GrantControls",
        {"predicate": "phishing-resistant authentication strength for administrators"},
    ),
    AuditSpec(
        "5.2.2.6",
        "Get-MgIdentityConditionalAccessPolicy -All | Select-Object Id,DisplayName,State,Conditions,SessionControls,GrantControls",
        "Get-MgIdentityConditionalAccessPolicy -All | Select-Object Id,DisplayName,State,Conditions,SessionControls,GrantControls",
        {"predicate": "all users high user risk password change and every time"},
    ),
    AuditSpec(
        "5.2.2.7",
        "Get-MgIdentityConditionalAccessPolicy -All | Select-Object Id,DisplayName,State,Conditions,SessionControls,GrantControls",
        "Get-MgIdentityConditionalAccessPolicy -All | Select-Object Id,DisplayName,State,Conditions,SessionControls,GrantControls",
        {"predicate": "all users high and medium sign-in risk MFA and every time"},
    ),
    AuditSpec(
        "5.2.2.10",
        "Get-MgIdentityConditionalAccessPolicy -All | Select-Object Id,DisplayName,State,Conditions,SessionControls,GrantControls",
        "Get-MgIdentityConditionalAccessPolicy -All | Select-Object Id,DisplayName,State,Conditions,SessionControls,GrantControls",
        {"predicate": "register security information requires compliant device"},
    ),
    AuditSpec(
        "5.2.2.11",
        "Get-MgIdentityConditionalAccessPolicy -All | Select-Object Id,DisplayName,State,Conditions,SessionControls,GrantControls",
        "Get-MgIdentityConditionalAccessPolicy -All | Select-Object Id,DisplayName,State,Conditions,SessionControls,GrantControls",
        {"predicate": "Intune Enrollment MFA and every time"},
    ),
    AuditSpec(
        "5.2.2.13",
        "Get-MgIdentityConditionalAccessPolicy -All | Select-Object Id,DisplayName,State,Conditions,SessionControls,GrantControls",
        "Get-MgIdentityConditionalAccessPolicy -All | Select-Object Id,DisplayName,State,Conditions,SessionControls,GrantControls",
        {"predicate": "all users periodic reauthentication seven days or less"},
    ),
    AuditSpec(
        "5.2.3.4",
        "Get-MgReportAuthenticationMethodUserRegistrationDetail -All | Select-Object Id,UserPrincipalName,UserDisplayName,UserType,IsMfaCapable",
        "Get-MgReportAuthenticationMethodUserRegistrationDetail -All | Select-Object Id,UserPrincipalName,UserDisplayName,UserType,IsMfaCapable",
        {"predicate": "all member users MFA capable"},
    ),
    AuditSpec(
        "1.2.1",
        "Get-MgGroup -All -Property Id,DisplayName,Visibility | Where-Object { $_.Visibility -eq 'Public' } | Select-Object Id,DisplayName,Visibility",
        "Get-MgGroup -All -Property Id,DisplayName,Visibility | Where-Object { $_.Visibility -eq 'Public' } | Select-Object Id,DisplayName,Visibility",
        {"predicate": "no public groups unless documented"},
    ),
    AuditSpec(
        "1.1.4",
        "[pscustomobject]@{AdministratorRoles=(Get-MgDirectoryRole | Where-Object { $_.DisplayName -like '*Administrator*' -or $_.DisplayName -eq 'Global Reader' } | Select-Object Id,DisplayName);RoleMembers=(Get-MgDirectoryRole | Where-Object { $_.DisplayName -like '*Administrator*' -or $_.DisplayName -eq 'Global Reader' } | ForEach-Object { $role=$_; Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All | ForEach-Object { $member=$_; if ($member.AdditionalProperties.userPrincipalName) { Get-MgUser -UserId $member.Id -Property UserPrincipalName,DisplayName,Id | Select-Object UserPrincipalName,DisplayName,Id,@{Name='Role';Expression={$role.DisplayName}},@{Name='LicenseDetails';Expression={ Get-MgUserLicenseDetail -UserId $member.Id | Select-Object SkuPartNumber } } } } })}",
        "[pscustomobject]@{AdministratorRoles=(Get-MgDirectoryRole | Where-Object { $_.DisplayName -like '*Administrator*' -or $_.DisplayName -eq 'Global Reader' } | Select-Object Id,DisplayName);RoleMembers=(Get-MgDirectoryRole | Where-Object { $_.DisplayName -like '*Administrator*' -or $_.DisplayName -eq 'Global Reader' } | ForEach-Object { $role=$_; Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All | ForEach-Object { $member=$_; if ($member.AdditionalProperties.userPrincipalName) { Get-MgUser -UserId $member.Id -Property UserPrincipalName,DisplayName,Id | Select-Object UserPrincipalName,DisplayName,Id,@{Name='Role';Expression={$role.DisplayName}},@{Name='LicenseDetails';Expression={ Get-MgUserLicenseDetail -UserId $member.Id | Select-Object SkuPartNumber } } } } })}",
        {
            "predicate": "manual license review; each privileged account has no license or only Entra ID P1/P2"
        },
    ),
    AuditSpec(
        "1.3.2",
        "[pscustomobject]@{TimeoutPolicy=(Get-MgPolicyActivityBasedTimeoutPolicy | Select-Object Id,Definition);ConditionalAccessPolicies=(Get-MgIdentityConditionalAccessPolicy -All | Select-Object Id,DisplayName,State,Conditions,SessionControls,GrantControls)}",
        "[pscustomobject]@{TimeoutPolicy=(Get-MgPolicyActivityBasedTimeoutPolicy | Select-Object Id,Definition);ConditionalAccessPolicies=(Get-MgIdentityConditionalAccessPolicy -All | Select-Object Id,DisplayName,State,Conditions,SessionControls,GrantControls)}",
        {
            "predicate": "timeout parses <= 03:00:00 and a separate enabled CA policy matches Office365/browser/app-enforced restrictions"
        },
    ),
)
REGISTRY = {spec.cis: spec for spec in _REGISTRY}


def run_audits(
    control_ids: list[str] | tuple[str, ...] | set[str],
    output_dir: Path,
    *,
    pwsh: str = "pwsh",
    expected_tenant_id: str | None = None,
    client_id: str | None = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> list[AuditResult]:
    requested = list(control_ids)
    if not requested:
        return []
    unknown = sorted(set(requested) - REGISTRY.keys())
    if unknown:
        raise ValueError("Unsupported Graph audit control(s): " + ", ".join(unknown))
    selected = [REGISTRY[cis] for cis in requested]
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    with (
        tempfile.NamedTemporaryFile("w", suffix=".ps1", dir=output_dir, delete=False) as sf,
        tempfile.NamedTemporaryFile("w", suffix=".json", dir=output_dir, delete=False) as rf,
    ):
        script_path, result_path = Path(sf.name), Path(rf.name)
    if expected_tenant_id is not None and not re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}",
        expected_tenant_id,
    ):
        raise ValueError("expected_tenant_id must be a UUID")
    if client_id is not None and not re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}",
        client_id,
    ):
        raise ValueError("client_id must be a UUID")
    if client_id is not None and expected_tenant_id is None:
        raise ValueError("client_id requires expected_tenant_id")
    result_literal = str(result_path).replace("'", "''")
    tenant_check = (
        f"; if ($ctx.TenantId -ne '{expected_tenant_id}') {{ throw 'Graph tenant mismatch' }}"
        if expected_tenant_id
        else ""
    )
    lines = [
        "param([string]$ExpectedTenantId, [string]$ClientId)",
        "$ErrorActionPreference = 'Stop'",
        "Import-Module Microsoft.Graph.Authentication -ErrorAction Stop",
        "$readScopes = @(" + ", ".join(f"'{scope}'" for scope in _READ_SCOPES) + ")",
    ]
    if client_id:
        lines.append("Connect-MgGraph -ClientId $ClientId -TenantId $ExpectedTenantId -Scopes 'https://graph.microsoft.com/.default' -ContextScope CurrentUser -NoWelcome")
    else:
        # Public Microsoft Azure PowerShell application, also Monkey365's default.
        lines += [
            "$auth = @{ClientId='1950a258-227b-4e31-a9cf-717495945fc2'; Scopes='https://graph.microsoft.com/.default'; ContextScope='Process'; NoWelcome=$true}",
            "if ($ExpectedTenantId) { $auth.TenantId = $ExpectedTenantId }",
            "Connect-MgGraph @auth",
        ]
    lines += [_CONTEXT + tenant_check, "$records = @()"]
    for spec in selected:
        command = spec.command.replace("'", "''")
        lines += [
            "try {",
            f" $data = @({spec.script})",
            " $json = ConvertTo-Json -InputObject $data -Depth 20",
            f" $records += [pscustomobject]@{{cis='{spec.cis}';command='{command}';output=$json;data=(ConvertFrom-Json -InputObject $json -NoEnumerate);status='collected';error=$null}}",
            "} catch {",
            f" $records += [pscustomobject]@{{cis='{spec.cis}';command='{command}';output='';data=$null;status='failed';error=$_.Exception.Message}}",
            "}",
        ]
    lines += [
        f"$records | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath '{result_literal}' -Encoding UTF8"
    ]
    script_path.write_text("\n".join(lines), encoding="utf-8")
    try:
        done = runner(
            [
                powershell_executable(pwsh),
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script_path),
                *( ["-ExpectedTenantId", expected_tenant_id, "-ClientId", client_id]
                   if client_id else (["-ExpectedTenantId", expected_tenant_id] if expected_tenant_id else []) ),
            ],
            cwd=str(output_dir),
            capture_output=True,
            text=True,
            check=False,
        )
        if done.returncode:
            return [
                AuditResult(
                    s.cis,
                    s.command,
                    done.stdout or "",
                    None,
                    "failed",
                    done.stderr or "PowerShell failed",
                )
                for s in selected
            ]
        try:
            raw = json.loads(result_path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as error:
            return [
                AuditResult(
                    s.cis, s.command, "", None, "failed", f"Invalid result transport: {error}"
                )
                for s in selected
            ]
        raw = raw if isinstance(raw, list) else [raw]
        by_cis = {str(x.get("cis")): x for x in raw if isinstance(x, dict)}
        results = []
        for spec in selected:
            item = by_cis.get(spec.cis)
            if not item:
                results.append(
                    AuditResult(spec.cis, spec.command, "", None, "failed", "Missing result record")
                )
                continue
            output, data = str(item.get("output", "")), item.get("data")
            status = item.get("status", "failed") if output and data is not None else "failed"
            results.append(
                AuditResult(
                    spec.cis,
                    spec.command,
                    output,
                    data,
                    status,
                    item.get("error") or ("Null audit data" if data is None else None),
                )
            )
        return results
    finally:
        script_path.unlink(missing_ok=True)
        result_path.unlink(missing_ok=True)
