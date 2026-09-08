from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from .models import Control

ALLOWED_ACTIONS = {"click", "wait_for"}


def load_manifest(path: Path) -> tuple[set[str], dict[str, Control]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    hosts = set(data.get("allowed_hosts", []))
    if not hosts:
        raise ValueError("manifest requires at least one allowed_hosts entry")
    controls: dict[str, Control] = {}
    for raw in data.get("controls", []):
        cis = str(raw["cis"])
        if cis in controls:
            raise ValueError(f"duplicate CIS control: {cis}")
        host = (urlparse(raw["start_url"]).hostname or "").lower()
        if host not in hosts:
            raise ValueError(f"{cis}: start_url host {host!r} is not allowed")
        steps = tuple(raw.get("steps", []))
        for step in steps:
            if step.get("action") not in ALLOWED_ACTIONS:
                raise ValueError(f"{cis}: unsupported action {step.get('action')!r}")
            if not step.get("selector"):
                raise ValueError(f"{cis}: {step['action']} requires selector")
        controls[cis] = Control(
            cis=cis,
            title=raw["title"],
            start_url=raw["start_url"],
            steps=steps,
            screenshot_selector=raw.get("screenshot_selector"),
            full_page=bool(raw.get("full_page", True)),
            enabled=bool(raw.get("enabled", True)),
        )
    if not controls:
        raise ValueError("manifest contains no controls")
    return hosts, controls

