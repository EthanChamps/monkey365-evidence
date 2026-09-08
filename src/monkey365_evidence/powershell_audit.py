"""Bounded, read-only Exchange Online audit command runner.

The command registry is deliberately built in.  Callers can select control IDs,
but cannot supply PowerShell source or arbitrary command arguments.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID


@dataclass(frozen=True)
class AuditSpec:
    cis: str
    command: str
    script: str
    expected: dict[str, Any]


@dataclass(frozen=True)
class AuditResult:
    cis: str
    command: str
    output: str
    data: Any
    status: str
    error: str | None = None


_REGISTRY: tuple[AuditSpec, ...] = (
    AuditSpec("1.3.6", "Get-OrganizationConfig | Select-Object CustomerLockBoxEnabled",
              "Get-OrganizationConfig | Select-Object CustomerLockBoxEnabled",
              {"CustomerLockBoxEnabled": True}),
    AuditSpec("1.3.9", "[pscustomobject]@{DefaultPolicy=(Get-OwaMailboxPolicy -Identity 'OwaMailboxPolicy-Default' | Select-Object BookingsMailboxCreationEnabled);Organization=(Get-OrganizationConfig | Select-Object BookingsEnabled)}",
              "[pscustomobject]@{DefaultPolicy=(Get-OwaMailboxPolicy -Identity 'OwaMailboxPolicy-Default' | Select-Object BookingsMailboxCreationEnabled);Organization=(Get-OrganizationConfig | Select-Object BookingsEnabled)}",
              {"BookingsMailboxCreationEnabled": False}),
    AuditSpec("6.3.1", "Get-RoleAssignmentPolicy | Where-Object { $_.IsDefault -eq $true } | Select-Object Name,Identity,AssignedRoles",
              "Get-RoleAssignmentPolicy | Where-Object { $_.IsDefault -eq $true } | Select-Object Name,Identity,AssignedRoles",
              {"AssignedRoles_excludes": ["My Custom Apps", "My Marketplace Apps", "My ReadWriteMailbox Apps"]}),
    AuditSpec("6.3.2", "Get-OwaMailboxPolicy | Where-Object { $_.IsDefault } | Select-Object Identity,PersonalAccountsEnabled,PersonalAccountCalendarsEnabled",
              "Get-OwaMailboxPolicy | Where-Object { $_.IsDefault } | Select-Object Identity,PersonalAccountsEnabled,PersonalAccountCalendarsEnabled",
              {"PersonalAccountsEnabled": False, "PersonalAccountCalendarsEnabled": False}),
    AuditSpec("6.5.2", "Get-OrganizationConfig | Select-Object MailTipsAllTipsEnabled,MailTipsExternalRecipientsTipsEnabled,MailTipsGroupMetricsEnabled,MailTipsLargeAudienceThreshold",
              "Get-OrganizationConfig | Select-Object MailTipsAllTipsEnabled,MailTipsExternalRecipientsTipsEnabled,MailTipsGroupMetricsEnabled,MailTipsLargeAudienceThreshold",
              {"MailTipsAllTipsEnabled": True, "MailTipsExternalRecipientsTipsEnabled": True,
               "MailTipsGroupMetricsEnabled": True, "MailTipsLargeAudienceThreshold": "acceptable"}),
    AuditSpec("6.5.3", "Get-OwaMailboxPolicy -Identity 'OwaMailboxPolicy-Default' | Select-Object AdditionalStorageProvidersAvailable",
              "Get-OwaMailboxPolicy -Identity 'OwaMailboxPolicy-Default' | Select-Object AdditionalStorageProvidersAvailable",
              {"AdditionalStorageProvidersAvailable": False}),
    AuditSpec("2.1.1", "[pscustomobject]@{Policies=(Get-SafeLinksPolicy | Select-Object Identity,EnableSafeLinksForEmail,EnableSafeLinksForTeams,EnableSafeLinksForOffice,TrackClicks,AllowClickThrough,ScanUrls,EnableForInternalSenders,DeliverMessageAfterScan,DisableUrlRewrite);Rules=(Get-SafeLinksRule | Select-Object SafeLinksPolicy,Priority,State,SentToMemberOf,RecipientDomainIs,ExceptIfSentTo,ExceptIfSentToMemberOf,ExceptIfRecipientDomainIs)}",
              "[pscustomobject]@{Policies=(Get-SafeLinksPolicy | Select-Object Identity,EnableSafeLinksForEmail,EnableSafeLinksForTeams,EnableSafeLinksForOffice,TrackClicks,AllowClickThrough,ScanUrls,EnableForInternalSenders,DeliverMessageAfterScan,DisableUrlRewrite);Rules=(Get-SafeLinksRule | Select-Object SafeLinksPolicy,Priority,State,SentToMemberOf,RecipientDomainIs,ExceptIfSentTo,ExceptIfSentToMemberOf,ExceptIfRecipientDomainIs)}",
              {"policy_settings": "structured policy records; qualifying priority and organization coverage require review"}),
    AuditSpec("2.1.3", "Get-MalwareFilterPolicy | Select-Object Identity,EnableInternalSenderAdminNotifications,InternalSenderAdminAddress",
              "Get-MalwareFilterPolicy | Select-Object Identity,EnableInternalSenderAdminNotifications,InternalSenderAdminAddress",
              {"EnableInternalSenderAdminNotifications": True, "InternalSenderAdminAddress": "nonempty email address"}),
    AuditSpec("2.1.6", "Get-HostedOutboundSpamFilterPolicy | Select-Object Identity,BccSuspiciousOutboundMail,BccSuspiciousOutboundAdditionalRecipients,NotifyOutboundSpam,NotifyOutboundSpamRecipients",
              "Get-HostedOutboundSpamFilterPolicy | Select-Object Identity,BccSuspiciousOutboundMail,BccSuspiciousOutboundAdditionalRecipients,NotifyOutboundSpam,NotifyOutboundSpamRecipients",
              {"policy_settings": "structured policy records; priority and recipient review required"}),
    AuditSpec("2.1.7", "[pscustomobject]@{Policies=(Get-AntiPhishPolicy | Select-Object Name,Enabled,PhishThresholdLevel,EnableTargetedUserProtection,EnableOrganizationDomainsProtection,EnableMailboxIntelligence,EnableMailboxIntelligenceProtection,EnableSpoofIntelligence,TargetedUserProtectionAction,TargetedDomainProtectionAction,MailboxIntelligenceProtectionAction,EnableFirstContactSafetyTips,EnableSimilarUsersSafetyTips,EnableSimilarDomainsSafetyTips,EnableUnusualCharactersSafetyTips,TargetedUsersToProtect,HonorDmarcPolicy);Rules=(Get-AntiPhishRule | Select-Object AntiPhishPolicy,Priority,State,SentToMemberOf,RecipientDomainIs,ExceptIfSentTo,ExceptIfSentToMemberOf,ExceptIfRecipientDomainIs)}",
              "[pscustomobject]@{Policies=(Get-AntiPhishPolicy | Select-Object Name,Enabled,PhishThresholdLevel,EnableTargetedUserProtection,EnableOrganizationDomainsProtection,EnableMailboxIntelligence,EnableMailboxIntelligenceProtection,EnableSpoofIntelligence,TargetedUserProtectionAction,TargetedDomainProtectionAction,MailboxIntelligenceProtectionAction,EnableFirstContactSafetyTips,EnableSimilarUsersSafetyTips,EnableSimilarDomainsSafetyTips,EnableUnusualCharactersSafetyTips,TargetedUsersToProtect,HonorDmarcPolicy);Rules=(Get-AntiPhishRule | Select-Object AntiPhishPolicy,Priority,State,SentToMemberOf,RecipientDomainIs,ExceptIfSentTo,ExceptIfSentToMemberOf,ExceptIfRecipientDomainIs)}",
              {"policy_and_rule_settings": "structured policy and rule records; coverage review required"}),
    AuditSpec("2.1.11", "[pscustomobject]@{Policies=(Get-MalwareFilterPolicy | Select-Object Identity,FileTypes,EnableFileFilter);Rules=(Get-MalwareFilterRule | Select-Object MalwareFilterPolicy,State)}",
              "[pscustomobject]@{Policies=(Get-MalwareFilterPolicy | Select-Object Identity,FileTypes,EnableFileFilter);Rules=(Get-MalwareFilterRule | Select-Object MalwareFilterPolicy,State)}",
              {"policy_and_rule_settings": "structured policy and rule records; extension-list comparison required"}),
    AuditSpec("2.1.12", "Get-HostedConnectionFilterPolicy -Identity 'Default' | Select-Object Identity,IPAllowList",
              "Get-HostedConnectionFilterPolicy -Identity 'Default' | Select-Object Identity,IPAllowList",
              {"IPAllowList": "empty"}),
    AuditSpec("2.1.14", "Get-HostedContentFilterPolicy | Select-Object Identity,AllowedSenderDomains",
              "Get-HostedContentFilterPolicy | Select-Object Identity,AllowedSenderDomains",
              {"AllowedSenderDomains": "undefined or empty for every policy"}),
    AuditSpec("2.1.15", "Get-HostedOutboundSpamFilterPolicy -Identity 'Default' | Select-Object Identity,RecipientLimitExternalPerHour,RecipientLimitInternalPerHour,RecipientLimitPerDay,ActionWhenThresholdReached,NotifyOutboundSpamRecipients",
              "Get-HostedOutboundSpamFilterPolicy -Identity 'Default' | Select-Object Identity,RecipientLimitExternalPerHour,RecipientLimitInternalPerHour,RecipientLimitPerDay,ActionWhenThresholdReached,NotifyOutboundSpamRecipients",
              {"policy_settings": "structured policy records; numeric thresholds and recipient review required"}),
)

REGISTRY = {spec.cis: spec for spec in _REGISTRY}


def _script(selected: list[AuditSpec], result_path: str, tenantorganization: str | None) -> str:
    # Values are passed through an argv parameter; they are never interpolated into code.
    lines = [
        "param([string]$TenantOrganization, [string]$ExpectedTenantId)",
        "$ErrorActionPreference = 'Stop'",
        "if ($TenantOrganization) { Connect-ExchangeOnline -Organization $TenantOrganization -ShowBanner:$false } else { Connect-ExchangeOnline -ShowBanner:$false }",
        "if ($ExpectedTenantId) { $connection = Get-ConnectionInformation | Select-Object -First 1; if (-not $connection -or [string]$connection.TenantID -ne $ExpectedTenantId) { throw 'Connected Exchange tenant does not match expected tenant ID' } }",
        "$records = [System.Collections.Generic.List[object]]::new()",
    ]
    for spec in selected:
        # Registry scripts are constants defined in this module, never user input.
        lines.extend([
            "try {",
            f"  $value = {spec.script} | ConvertTo-Json -Compress -Depth 8",
            f"  $records.Add([pscustomobject]@{{cis='{spec.cis}'; command='{spec.command.replace(chr(39), chr(39)+chr(39))}'; output=$value; data=($value | ConvertFrom-Json); status=if ([string]::IsNullOrWhiteSpace($value)) {{ 'failed' }} else {{ 'collected' }}; error=$null}})",
            "} catch {",
            f"  $records.Add([pscustomobject]@{{cis='{spec.cis}'; command='{spec.command.replace(chr(39), chr(39)+chr(39))}'; output=''; data=$null; status='failed'; error=$_.Exception.Message}})",
            "}",
        ])
    lines.extend([
        f"$records | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath '{result_path.replace(chr(39), chr(39)+chr(39))}' -Encoding UTF8",
    ])
    return "\n".join(lines) + "\n"


def run_audits(
    control_ids: list[str] | tuple[str, ...] | set[str],
    output_dir: Path,
    *,
    pwsh: str = "pwsh",
    tenantorganization: str | None = None,
    expected_tenant_id: str | None = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> list[AuditResult]:
    """Run selected built-in audits and return raw, structured command evidence.

    No control IDs means no execution. Unknown IDs are rejected before a process is
    started. Empty command output is always failed and never treated as compliant.
    """
    requested = list(control_ids)
    if not requested:
        return []
    unknown = sorted(set(requested) - REGISTRY.keys())
    if unknown:
        raise ValueError("Unsupported PowerShell audit control(s): " + ", ".join(unknown))
    if expected_tenant_id is not None:
        try:
            UUID(expected_tenant_id)
        except (ValueError, AttributeError) as error:
            raise ValueError("expected_tenant_id must be a UUID") from error
    selected = [REGISTRY[cis] for cis in requested]
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", suffix=".ps1", prefix="m365-audit-", dir=output_dir,
                                     encoding="utf-8", delete=False) as script_file:
        script_path = Path(script_file.name)
    with tempfile.NamedTemporaryFile("w", suffix=".json", prefix="m365-audit-results-",
                                     dir=output_dir, encoding="utf-8", delete=False) as result_file:
        result_path = Path(result_file.name)
    script_path.write_text(_script(selected, str(result_path), tenantorganization), encoding="utf-8")
    argv = [pwsh, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
            str(script_path)]
    if tenantorganization:
        argv.extend(["-TenantOrganization", tenantorganization])
    if expected_tenant_id:
        argv.extend(["-ExpectedTenantId", expected_tenant_id])
    try:
        completed = runner(argv, cwd=str(output_dir), capture_output=True, text=True, check=False)
        if completed.returncode != 0:
            message = (completed.stderr or completed.stdout or "PowerShell exited with an error").strip()
            return [AuditResult(s.cis, s.command, completed.stdout or "", None, "failed", message)
                    for s in selected]
        if not result_path.exists():
            return [AuditResult(s.cis, s.command, completed.stdout or "", None, "failed",
                                "PowerShell produced no result transport") for s in selected]
        try:
            raw = json.loads(result_path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as error:
            return [AuditResult(s.cis, s.command, "", None, "failed",
                                f"Invalid result transport: {error}") for s in selected]
        if isinstance(raw, dict):
            raw = [raw]
        by_cis = {str(item.get("cis")): item for item in raw if isinstance(item, dict)}
        return [AuditResult(s.cis, s.command, str(item.get("output", "")), item.get("data"),
                            item.get("status", "failed")
                            if item.get("output") and item.get("data") is not None else "failed",
                            item.get("error") or ("Null audit data" if item.get("data") is None else None))
                if (item := by_cis.get(s.cis)) else
                AuditResult(s.cis, s.command, "", None, "failed", "Missing result record")
                for s in selected]
    finally:
        script_path.unlink(missing_ok=True)
        result_path.unlink(missing_ok=True)
