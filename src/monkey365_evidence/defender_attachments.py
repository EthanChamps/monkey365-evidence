"""Evaluation for CIS 2.1.11 attachment filtering command output."""
from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from typing import Any

from .audit_evaluation import Evaluation

# CIS Microsoft 365 Foundations Benchmark v7.0.0, 2.1.11 Audit script ($AttachExts).
REFERENCE_EXTENSIONS = (
    '7z','a3x','ace','ade','adp','ani','apk','app','appinstaller','applescript','application','appref-ms','appx','appxbundle','arj','asd','asx','bas','bat','bgi','bz2','cab','chm','cmd','com','cpl','crt','cs','csh','daa','dbf','dcr','deb','desktopthemepackfile','dex','diagcab','dif','dir','dll','dmg','doc','docm','dot','dotm','elf','eml','exe','fxp','gadget','gz','hlp','hta','htc','htm','html','hwpx','ics','img','inf','ins','iqy','iso','isp','jar','jnlp','js','jse','kext','ksh','lha','lib','library','library-ms','lnk','lzh','macho','mam','mda','mdb','mde','mdt','mdw','mdz','mht','mhtml','mof','msc','msi','msix','msp','msrcincident','mst','ocx','odt','ops','oxps','pcd','pif','plg','pot','potm','ppa','ppam','ppkg','pps','ppsm','ppt','pptm','prf','prg','ps1','ps11','ps11xml','ps1xml','ps2','ps2xml','psc1','psc2','pub','py','pyc','pyo','pyw','pyz','pyzw','rar','reg','rev','rtf','scf','scpt','scr','sct','searchConnector-ms','service','settingcontent-ms','sh','shb','shs','shtm','shtml','sldm','slk','so','spl','stm','svg','swf','sys','tar','theme','themepack','timer','uif','url','uue','vb','vbe','vbs','vhd','vhdx','vxd','wbk','website','wim','wiz','ws','wsc','wsf','wsh','xla','xlam','xlc','xll','xlm','xls','xlsb','xlsm','xlt','xltm','xlw','xnk','xps','xsl','xz','z',
)


def _records(value: Any) -> list[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, list) and all(isinstance(item, Mapping) for item in value):
        return value
    return []


def evaluate_attachment_filtering(
    structured_policies: Any,
    rules: Any,
    reference_extensions: Iterable[str] | None = None,
) -> Evaluation:
    """Apply the benchmark's 120-extension/90%-coverage policy test.

    Only policies with more than 120 configured file types are assessed. A policy
    must have an enabled matching malware-filter rule and ``EnableFileFilter`` true.
    Missing policy scope or reference data produces ``unknown``.
    """
    source = REFERENCE_EXTENSIONS if reference_extensions is None else reference_extensions
    reference = {str(ext).casefold().lstrip(".") for ext in source if str(ext).strip()}
    if not reference:
        return Evaluation("unknown", detail="Reference attachment extension list is missing")
    policies = _records(structured_policies)
    policy_rules = _records(rules)
    comprehensive = []
    for policy in policies:
        file_types = policy.get("FileTypes")
        if isinstance(file_types, list) and len(file_types) > 120:
            comprehensive.append((policy, {str(ext).casefold().lstrip(".") for ext in file_types}))
    if not comprehensive:
        return Evaluation("unknown", detail="No comprehensive attachment policy found to evaluate")
    failures: list[str] = []
    uncertain = 0
    passing = False
    fail_threshold = int(len(reference) * 0.10)
    for policy, configured in comprehensive:
        missing = sorted(reference - configured)
        policy_id = policy.get("Id", policy.get("Identity"))
        matches = [rule for rule in policy_rules if rule.get("MalwareFilterPolicy") == policy_id]
        if not matches:
            uncertain += 1
            continue
        enabled_rule = any(rule.get("State") == "Enabled" for rule in matches)
        file_filter = policy.get("EnableFileFilter")
        if len(missing) < fail_threshold and enabled_rule and file_filter is True:
            passing = True
        else:
            identity = policy.get('Identity', policy_id)
            failures.append(json.dumps(identity, ensure_ascii=False))
            if file_filter is not True:
                failures.append(json.dumps({"EnableFileFilter": file_filter}, ensure_ascii=False))
            failures.extend(json.dumps({"State": rule.get("State")}, ensure_ascii=False) for rule in matches if rule.get("State") != "Enabled")
    if passing:
        return Evaluation("no_failure", detail="At least one comprehensive active policy meets the extension threshold")
    if uncertain == len(comprehensive):
        return Evaluation("unknown", detail="Comprehensive policy scope or matching rule state is unavailable")
    return Evaluation("failure", tuple(failures), "No comprehensive attachment policy meets the 90% extension, enabled-rule, and file-filter requirements")
