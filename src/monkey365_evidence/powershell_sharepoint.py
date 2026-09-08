"""Bounded, read-only SharePoint Online tenant audits."""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path
from uuid import UUID

from .powershell_audit import AuditResult, AuditSpec, powershell_executable

_REGISTRY = (
    AuditSpec(
        "7.2.1",
        "Get-SPOTenant | Select-Object LegacyAuthProtocolsEnabled",
        "Get-SPOTenant | Select-Object LegacyAuthProtocolsEnabled",
        {"LegacyAuthProtocolsEnabled": False},
    ),
    AuditSpec(
        "7.2.2",
        "Get-SPOTenant | Select-Object EnableAzureADB2BIntegration",
        "Get-SPOTenant | Select-Object EnableAzureADB2BIntegration",
        {"EnableAzureADB2BIntegration": True},
    ),
    AuditSpec(
        "7.2.3",
        "Get-SPOTenant | Select-Object SharingCapability",
        "Get-SPOTenant | Select-Object SharingCapability",
        {
            "SharingCapability": [
                "ExternalUserSharingOnly",
                "ExistingExternalUserSharingOnly",
                "Disabled",
            ]
        },
    ),
    AuditSpec(
        "7.2.4",
        "Get-SPOTenant | Select-Object OneDriveSharingCapability",
        "Get-SPOTenant | Select-Object OneDriveSharingCapability",
        {"OneDriveSharingCapability": "Disabled"},
    ),
    AuditSpec(
        "7.2.5",
        "Get-SPOTenant | Select-Object PreventExternalUsersFromResharing",
        "Get-SPOTenant | Select-Object PreventExternalUsersFromResharing",
        {"PreventExternalUsersFromResharing": True},
    ),
    AuditSpec(
        "7.2.6",
        "Get-SPOTenant | Select-Object SharingCapability,SharingDomainRestrictionMode,SharingAllowedDomainList",
        "Get-SPOTenant | Select-Object SharingCapability,SharingDomainRestrictionMode,SharingAllowedDomainList",
        {"sharing": "disabled or approved allow-list"},
    ),
    AuditSpec(
        "7.2.7",
        "Get-SPOTenant | Select-Object DefaultSharingLinkType",
        "Get-SPOTenant | Select-Object DefaultSharingLinkType",
        {"DefaultSharingLinkType": ["Direct", "Internal"]},
    ),
    AuditSpec(
        "7.2.8",
        "Get-SPOTenant | Select-Object SharingCapability,WhoCanShareAuthenticatedGuestAllowList",
        "Get-SPOTenant | Select-Object SharingCapability,WhoCanShareAuthenticatedGuestAllowList",
        {"sharing": "disabled or security-group scoped"},
    ),
    AuditSpec(
        "7.2.9",
        "Get-SPOTenant | Select-Object ExternalUserExpirationRequired,ExternalUserExpireInDays",
        "Get-SPOTenant | Select-Object ExternalUserExpirationRequired,ExternalUserExpireInDays",
        {"ExternalUserExpirationRequired": True, "ExternalUserExpireInDays": 30},
    ),
    AuditSpec(
        "7.2.10",
        "Get-SPOTenant | Select-Object EmailAttestationRequired,EmailAttestationReAuthDays",
        "Get-SPOTenant | Select-Object EmailAttestationRequired,EmailAttestationReAuthDays",
        {"EmailAttestationRequired": True, "EmailAttestationReAuthDays_max": 15},
    ),
    AuditSpec(
        "7.2.11",
        "Get-SPOTenant | Select-Object DefaultLinkPermission",
        "Get-SPOTenant | Select-Object DefaultLinkPermission",
        {"DefaultLinkPermission": "View"},
    ),
    AuditSpec(
        "7.3.1",
        "Get-SPOTenant | Select-Object DisallowInfectedFileDownload",
        "Get-SPOTenant | Select-Object DisallowInfectedFileDownload",
        {"DisallowInfectedFileDownload": True},
    ),
    AuditSpec(
        "7.3.2",
        "Get-SPOTenant | Select-Object ConditionalAccessPolicy,AllowDownloadingNonWebViewableFiles",
        "Get-SPOTenant | Select-Object ConditionalAccessPolicy,AllowDownloadingNonWebViewableFiles",
        {"note": "removed from CIS v7; retained for older Monkey365 finding compatibility"},
    ),
)

REGISTRY = {spec.cis: spec for spec in _REGISTRY}
ADMIN_URL = re.compile(r"https://[a-z0-9-]+-admin\.sharepoint\.com/?", re.IGNORECASE)


def validate_admin_url(value: str | None) -> None:
    if value is not None and not ADMIN_URL.fullmatch(value):
        raise ValueError(
            "sharepoint_admin_url must be an https://<tenant>-admin.sharepoint.com URL"
        )


def _script(selected: list[AuditSpec], result_path: str) -> str:
    lines = [
        "param([string]$SharePointAdminUrl,[string]$TenantOrganization,[string]$ExpectedTenantId)",
        "$ErrorActionPreference = 'Stop'",
        "if ($PSVersionTable.PSEdition -eq 'Core') { Import-Module Microsoft.Online.SharePoint.PowerShell -UseWindowsPowerShell -ErrorAction Stop } else { Import-Module Microsoft.Online.SharePoint.PowerShell -ErrorAction Stop }",
        "if (-not $SharePointAdminUrl -or $ExpectedTenantId) {",
        "  if ($TenantOrganization) { Connect-ExchangeOnline -Organization $TenantOrganization -ShowBanner:$false } else { Connect-ExchangeOnline -ShowBanner:$false }",
        "  $connection = Get-ConnectionInformation | Select-Object -First 1",
        "  if ($ExpectedTenantId -and [string]$connection.TenantID -ne $ExpectedTenantId) { throw 'Connected Exchange tenant does not match expected tenant ID' }",
        "  if (-not $SharePointAdminUrl) {",
        "    $domain = Get-AcceptedDomain | Where-Object InitialDomain | Select-Object -First 1 -ExpandProperty DomainName",
        "    if (-not $domain -or $domain -notmatch '^([a-zA-Z0-9-]+)\\.onmicrosoft\\.com$') { throw 'Could not derive the SharePoint admin URL; supply --sharepoint-admin-url' }",
        "    $SharePointAdminUrl = 'https://' + $Matches[1] + '-admin.sharepoint.com'",
        "  }",
        "}",
        "if ($SharePointAdminUrl -notmatch '^https://[a-zA-Z0-9-]+-admin\\.sharepoint\\.com/?$') { throw 'Invalid SharePoint admin URL' }",
        "Connect-SPOService -Url $SharePointAdminUrl",
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
    sharepoint_admin_url: str | None = None,
    tenantorganization: str | None = None,
    expected_tenant_id: str | None = None,
    pwsh: str = "pwsh",
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> list[AuditResult]:
    requested = list(control_ids)
    unknown = sorted(set(requested) - REGISTRY.keys())
    if unknown:
        raise ValueError("Unsupported SharePoint audit control(s): " + ", ".join(unknown))
    if not requested:
        return []
    validate_admin_url(sharepoint_admin_url)
    if expected_tenant_id is not None:
        try:
            UUID(expected_tenant_id)
        except (ValueError, AttributeError) as error:
            raise ValueError("expected_tenant_id must be a UUID") from error
    selected = [REGISTRY[cis] for cis in requested]
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", suffix=".ps1", prefix="spo-audit-", dir=output_dir, encoding="utf-8", delete=False
    ) as handle:
        script_path = Path(handle.name)
    with tempfile.NamedTemporaryFile(
        "w", suffix=".json", prefix="spo-results-", dir=output_dir, encoding="utf-8", delete=False
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
    for name, value in (
        ("SharePointAdminUrl", sharepoint_admin_url),
        ("TenantOrganization", tenantorganization),
        ("ExpectedTenantId", expected_tenant_id),
    ):
        if value:
            argv.extend([f"-{name}", value])
    try:
        completed = runner(argv, cwd=str(output_dir), capture_output=True, text=True, check=False)
        if completed.returncode:
            detail = (completed.stderr or completed.stdout or "SharePoint audit failed").strip()
            return [
                AuditResult(s.cis, s.command, completed.stdout or "", None, "failed", detail)
                for s in selected
            ]
        try:
            payload = json.loads(result_path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as error:
            return [
                AuditResult(
                    s.cis,
                    s.command,
                    "",
                    None,
                    "failed",
                    f"Invalid SharePoint result transport: {error}",
                )
                for s in selected
            ]
        if isinstance(payload, dict):
            payload = [payload]
        by_cis = {str(item.get("cis")): item for item in payload if isinstance(item, dict)}
        results = []
        for spec in selected:
            item = by_cis.get(spec.cis)
            if not item:
                results.append(
                    AuditResult(
                        spec.cis,
                        spec.command,
                        "",
                        None,
                        "failed",
                        "Missing SharePoint result record",
                    )
                )
                continue
            data, output = item.get("data"), str(item.get("output", ""))
            status = "collected" if data is not None and output else "failed"
            results.append(
                AuditResult(spec.cis, spec.command, output, data, status, item.get("error"))
            )
        return results
    finally:
        script_path.unlink(missing_ok=True)
        result_path.unlink(missing_ok=True)
