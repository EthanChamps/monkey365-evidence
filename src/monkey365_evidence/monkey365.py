from __future__ import annotations

import json
import re
import warnings
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from bs4 import BeautifulSoup


@dataclass(frozen=True)
class FailedFinding:
    rule_id: str
    source: Path
    record_index: int
    record: dict[str, Any]
    control_id: str | None = None
    benchmark_version: str | None = None


def _read_json(path: Path, *, strict: bool = True) -> Any:
    raw = path.read_bytes()
    for encoding in ("utf-8-sig", "utf-16", "utf-8"):
        try:
            return json.loads(raw.decode(encoding), strict=strict)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
    raise ValueError(f"unable to decode JSON: {path}")


def _objects(value: Any) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        # Resource payloads can themselves contain statusCode fields. They are
        # not additional findings and must not influence the capture plan.
        if "statusCode" in value:
            return
        for child in value.values():
            yield from _objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from _objects(child)


def failed_rule_ids(path: Path, mapping: dict[str, str] | None = None) -> set[str]:
    return {finding.rule_id for finding in load_failed_findings(path, mapping)}


def load_failed_findings(path: Path, mapping: dict[str, str] | None = None) -> list[FailedFinding]:
    if path.suffix.lower() in {".html", ".htm"}:
        return _html_failed_findings(path)
    failed: list[FailedFinding] = []
    paths = sorted(path.rglob("*.json")) if path.is_dir() else [path]
    if not paths:
        raise ValueError(f"no JSON exports found in {path}")
    findings = 0
    for source in paths:
        for record_index, item in enumerate(_objects(_read_json(source))):
            if "statusCode" not in item:
                continue
            findings += 1
            if str(item["statusCode"]).strip().lower() != "fail":
                continue
            candidate = _rule_id(item)
            metadata = item.get("metadata")
            event = metadata.get("eventCode") if isinstance(metadata, dict) else None
            if mapping is not None and isinstance(event, str) and event in mapping:
                candidate = event
            if candidate is None:
                raise ValueError(f"failed finding has no rule/event ID in {source}")
            failed.append(FailedFinding(candidate, source, record_index, item))
    if not findings:
        raise ValueError(f"no findings found in {path}; supply Monkey365 -ExportTo JSON output")
    return failed


def _html_failed_findings(path: Path) -> list[FailedFinding]:
    """Read rendered finding cards as inert HTML. Never execute report scripts."""
    soup = BeautifulSoup(path.read_bytes(), "html.parser")
    cards = soup.select(".monkey-finding-card")
    if not cards:
        raise ValueError("HTML contains no Monkey365 finding cards")
    failed = []
    for index, card in enumerate(cards):
        info = card.select(".monkey-finding-info")
        badges = [badge.get_text(" ", strip=True)
                  for item in info for badge in item.select(".badge")]
        statuses = [text for text in badges if text.lower() in {"fail", "pass", "manual"}]
        if len(statuses) != 1:
            raise ValueError(f"HTML card {index}: missing or ambiguous finding status")
        if statuses[0].lower() != "fail":
            continue
        references = []
        for item in info:
            parts = [badge.get_text(" ", strip=True) for badge in item.select(".badge")]
            if len(parts) == 3 and parts[0].startswith("CIS Microsoft 365 Foundations"):
                version, reference = parts[1:]
                if not re.fullmatch(r"\d+(?:\.\d+){2,3}", reference):
                    raise ValueError(f"HTML card {index}: invalid CIS reference")
                references.append((version, reference))
        if not references:
            raise ValueError(f"HTML failed card {index}: no CIS Microsoft 365 reference")
        heading = card.select_one(".monkey-finding-header")
        record = {
            "statusCode": "fail",
            "findingInfo": {"title": heading.get_text(" ", strip=True) if heading else ""},
        }
        for version, reference in references:
            failed.append(FailedFinding(
                f"cis:{version}:{reference}", path, index, record, reference, version
            ))
    return failed


def _rule_id(item: dict[str, Any]) -> str | None:
    def obj(key):
        value = item.get(key)
        return value if isinstance(value, dict) else {}

    info, unmapped, metadata = obj("findingInfo"), obj("unmapped"), obj("metadata")
    candidates = (
        unmapped.get("ruleId"), metadata.get("eventCode"), info.get("ruleId"),
        info.get("eventCode"), item.get("ruleId"), item.get("id"), item.get("idSuffix"),
    )
    return next((str(value) for value in candidates if isinstance(value, str) and value), None)


def import_rule_map(ruleset: Path, findings_directory: Path) -> dict[str, str]:
    """Resolve IDs using the chosen upstream ruleset, never guess CIS versions."""
    data = _read_json(ruleset)
    if not isinstance(data, dict) or not isinstance(data.get("rules"), dict):
        raise ValueError("ruleset must contain a rules object")  # noqa: TRY004
    files: dict[str, list[Path]] = {}
    for source in findings_directory.rglob("*.json"):
        files.setdefault(source.name, []).append(source)
    mapping: dict[str, str] = {}
    ambiguous: set[str] = set()
    for filename, variants in data["rules"].items():
        references = {
            str(compliance["reference"])
            for variant in variants if variant.get("enabled", True)
            for compliance in variant.get("compliance", [])
            if compliance.get("reference")
        }
        if not references:
            continue
        if len(references) != 1:
            raise ValueError(f"{filename}: multiple compliance references require separate mappings")
        matches = files.get(filename, [])
        current = [p for p in matches if "old" not in p.relative_to(findings_directory).parts]
        matches = current or matches
        if len(matches) != 1:
            raise ValueError(f"{filename}: expected one finding definition, found {len(matches)}")
        # Some upstream rule descriptions contain literal tabs/newlines inside
        # strings (accepted by PowerShell). Exports remain strictly parsed.
        try:
            definition = _read_json(matches[0], strict=False)
        except ValueError:
            # Import only standalone identity fields when upstream has invalid
            # prose in another field. Never evaluate or repair the rule itself.
            fields = re.findall(
                r'^\s*"(id|idSuffix)"\s*:\s*("(?:\\.|[^"\\])*")\s*,?\s*$',
                matches[0].read_text(encoding="utf-8-sig"), re.MULTILINE,
            )
            if len(fields) != 2 or {key for key, _ in fields} != {"id", "idSuffix"}:
                raise ValueError(f"{filename}: cannot extract unambiguous identity fields") from None
            definition = {key: json.loads(value) for key, value in fields}
            warnings.warn(f"{filename}: invalid rule JSON; imported identity fields only", stacklevel=2)
        reference = next(iter(references))
        if not definition.get("id") and not definition.get("idSuffix"):
            raise ValueError(f"{filename}: missing id and idSuffix")
        for key in (definition.get("id"), definition.get("idSuffix")):
            if not key:
                continue
            if not isinstance(key, str):
                raise ValueError(f"{filename}: invalid id/idSuffix")  # noqa: TRY004
            if key in mapping and mapping[key] != reference:
                # Upstream reuses some numeric IDs for unrelated findings.
                # Omit ambiguous aliases; the unique eventCode remains usable.
                ambiguous.add(key)
            mapping[key] = reference
    for key in ambiguous:
        del mapping[key]
    if not mapping:
        raise ValueError("ruleset contains no enabled compliance mappings")
    return mapping


def load_rule_map(path: Path) -> dict[str, str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or any(
        not isinstance(value, str) or not value.strip() for value in data.values()
    ):
        raise ValueError("rule map must map rule/event IDs to nonempty control ID strings")
    return data
