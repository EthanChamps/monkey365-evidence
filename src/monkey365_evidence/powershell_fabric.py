"""Read Microsoft Fabric tenant settings once and emit bounded CIS evidence."""

from __future__ import annotations

import json
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path
from uuid import UUID

from .powershell_audit import AuditResult, powershell_executable

SETTINGS = {
    "9.1.1": "AllowGuestUserToAccessSharedContent",
    "9.1.2": "ExternalSharingV2",
    "9.1.3": "ElevatedGuestsTenant",
    "9.1.4": "PublishToWeb",
    "9.1.5": "RScriptVisual",
    "9.1.6": "EimInformationProtectionEdit",
    "9.1.7": "ShareLinkToEntireOrg",
    "9.1.8": "EnableDatasetInPlaceSharing",
    "9.1.9": "BlockResourceKeyAuthentication",
    "9.1.10": "ServicePrincipalAccessPermissionAPIs",
    "9.1.11": "AllowServicePrincipalsCreateAndUseProfiles",
    "9.1.12": "ServicePrincipalAccessGlobalAPIs",
}

REGISTRY = {
    cis: f"GET https://api.fabric.microsoft.com/v1/admin/tenantsettings | Where settingName -eq '{name}'"
    for cis, name in SETTINGS.items()
}


def _script(selected: list[str], result_path: str) -> str:
    pairs = ",".join(f"'{cis}'='{SETTINGS[cis]}'" for cis in selected)
    escaped = result_path.replace("'", "''")
    return f"""param([string]$ExpectedTenantId)
$ErrorActionPreference = 'Stop'
$connect = @{{}}; if ($ExpectedTenantId) {{ $connect.Tenant = $ExpectedTenantId }}
Connect-AzAccount @connect | Out-Null
$context = Get-AzContext
if ($ExpectedTenantId -and [string]$context.Tenant.Id -ne $ExpectedTenantId) {{ throw 'Connected Azure tenant does not match expected tenant ID' }}
$access = Get-AzAccessToken -ResourceUrl 'https://api.fabric.microsoft.com'
if ($access.Token -is [securestring]) {{
  $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($access.Token)
  try {{ $token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }} finally {{ [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }}
}} else {{ $token = [string]$access.Token }}
$response = Invoke-RestMethod -Method Get -Uri 'https://api.fabric.microsoft.com/v1/admin/tenantsettings' -Headers @{{Authorization="Bearer $token"}}
$all = @($response.tenantSettings); if (-not $all.Count) {{ $all = @($response.value) }}
$wanted = @{{{pairs}}}
$records = [System.Collections.Generic.List[object]]::new()
foreach ($entry in $wanted.GetEnumerator()) {{
  $matches = @($all | Where-Object settingName -eq $entry.Value)
  $data = [pscustomobject]@{{settingName=$entry.Value;found=($matches.Count -eq 1);setting=if ($matches.Count -eq 1) {{$matches[0]}} else {{$null}}}}
  $json = $data | ConvertTo-Json -Compress -Depth 20
  $plain = ConvertFrom-Json -InputObject $json
  $command = "GET https://api.fabric.microsoft.com/v1/admin/tenantsettings | Where settingName -eq '$($entry.Value)'"
  $records.Add([pscustomobject]@{{cis=$entry.Key;command=$command;output=$json;data=$plain;status='collected';error=$null}})
}}
$records | ConvertTo-Json -Depth 25 | Set-Content -LiteralPath '{escaped}' -Encoding UTF8
"""


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
        raise ValueError("Unsupported Fabric audit control(s): " + ", ".join(unknown))
    if not requested:
        return []
    if expected_tenant_id is not None:
        try:
            UUID(expected_tenant_id)
        except (ValueError, AttributeError) as error:
            raise ValueError("expected_tenant_id must be a UUID") from error
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", suffix=".ps1", prefix="fabric-audit-", dir=output_dir, encoding="utf-8", delete=False
    ) as handle:
        script_path = Path(handle.name)
    with tempfile.NamedTemporaryFile(
        "w",
        suffix=".json",
        prefix="fabric-results-",
        dir=output_dir,
        encoding="utf-8",
        delete=False,
    ) as handle:
        result_path = Path(handle.name)
    script_path.write_text(_script(requested, str(result_path)), encoding="utf-8")
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
            detail = (completed.stderr or completed.stdout or "Fabric audit failed").strip()
            return [
                AuditResult(cis, REGISTRY[cis], completed.stdout or "", None, "failed", detail)
                for cis in requested
            ]
        try:
            payload = json.loads(result_path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as error:
            return [
                AuditResult(
                    cis,
                    REGISTRY[cis],
                    "",
                    None,
                    "failed",
                    f"Invalid Fabric result transport: {error}",
                )
                for cis in requested
            ]
        if isinstance(payload, dict):
            payload = [payload]
        by_cis = {str(item.get("cis")): item for item in payload if isinstance(item, dict)}
        results = []
        for cis in requested:
            item = by_cis.get(cis)
            if not item:
                results.append(
                    AuditResult(
                        cis, REGISTRY[cis], "", None, "failed", "Missing Fabric result record"
                    )
                )
                continue
            data = item.get("data")
            output = str(item.get("output", ""))
            status = "collected" if data is not None and output else "failed"
            results.append(AuditResult(cis, REGISTRY[cis], output, data, status, item.get("error")))
        return results
    finally:
        script_path.unlink(missing_ok=True)
        result_path.unlink(missing_ok=True)
