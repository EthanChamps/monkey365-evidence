from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any


def _read_json(path: Path) -> Any:
    raw = path.read_bytes()
    for encoding in ("utf-8-sig", "utf-16", "utf-8"):
        try:
            return json.loads(raw.decode(encoding))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
    raise ValueError(f"unable to decode JSON: {path}")


def _objects(value: Any) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from _objects(child)


def failed_rule_ids(path: Path) -> set[str]:
    rules: set[str] = set()
    for item in _objects(_read_json(path)):
        if str(item.get("statusCode", "")).lower() != "fail":
            continue
        info = item.get("findingInfo") or {}
        unmapped = item.get("unmapped") or {}
        metadata = item.get("metadata") or {}
        candidates = (
            unmapped.get("ruleId"),
            metadata.get("eventCode"),
            info.get("ruleId"),
            info.get("eventCode"),
            item.get("ruleId"),
        )
        candidate = next((candidate for candidate in candidates if candidate), None)
        if candidate:
            rules.add(str(candidate))
    return rules


def load_rule_map(path: Path) -> dict[str, str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return {str(key): str(value) for key, value in data.items()}
