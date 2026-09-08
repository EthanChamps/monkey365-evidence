from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

from .models import Control

ALLOWED_ACTIONS = {"click", "wait_for"}


def validate_url(url: str, hosts: set[str]) -> None:
    parsed = urlparse(url)
    if (parsed.scheme != "https" or parsed.username or parsed.password
            or parsed.port not in (None, 443) or parsed.hostname not in hosts):
        raise ValueError(f"URL is not allowed: {url}")


def load_manifest(path: Path) -> tuple[set[str], dict[str, Control]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("manifest must be an object")  # noqa: TRY004
    raw_hosts = data.get("allowed_hosts", [])
    if not isinstance(raw_hosts, list) or any(not isinstance(host, str) for host in raw_hosts):
        raise ValueError("allowed_hosts must be a list of hostnames")
    hosts = set(raw_hosts)
    if not hosts:
        raise ValueError("manifest requires at least one allowed_hosts entry")
    if any(not isinstance(host, str) or not re.fullmatch(r"[a-z0-9.-]+", host)
           or "." not in host for host in hosts):
        raise ValueError("allowed_hosts must contain lowercase exact hostnames")
    controls: dict[str, Control] = {}
    raw_controls = data.get("controls", [])
    if not isinstance(raw_controls, list):
        raise ValueError("controls must be a list")  # noqa: TRY004
    for raw in raw_controls:
        if not isinstance(raw, dict) or not {"cis", "title", "start_url"} <= raw.keys():
            raise ValueError("each control requires cis, title and start_url")
        if not isinstance(raw["start_url"], str):
            raise ValueError("start_url must be a string")  # noqa: TRY004
        cis = str(raw["cis"])
        if not re.fullmatch(r"\d+(?:\.\d+)+", cis):
            raise ValueError(f"invalid CIS control ID: {cis}")
        if cis in controls:
            raise ValueError(f"duplicate CIS control: {cis}")
        host = (urlparse(raw["start_url"]).hostname or "").lower()
        if host not in hosts:
            raise ValueError(f"{cis}: start_url host {host!r} is not allowed")
        validate_url(raw["start_url"], hosts)
        for flag in ("enabled", "full_page"):
            if flag in raw and not isinstance(raw[flag], bool):
                raise ValueError(f"{cis}: {flag} must be a boolean")
        if not isinstance(raw.get("title"), str) or not raw["title"].strip():
            raise ValueError(f"{cis}: title is required")
        raw_steps = raw.get("steps", [])
        if not isinstance(raw_steps, list) or any(not isinstance(step, dict) for step in raw_steps):
            raise ValueError(f"{cis}: steps must be a list of actions")
        steps = tuple(raw_steps)
        for step in steps:
            if step.get("action") not in ALLOWED_ACTIONS:
                raise ValueError(f"{cis}: unsupported action {step.get('action')!r}")
            if not isinstance(step.get("selector"), str) or not step["selector"]:
                raise ValueError(f"{cis}: {step['action']} requires selector")
            if step["action"] == "click" and step.get("navigation") is not True:
                raise ValueError(f"{cis}: click requires navigation: true")
            timeout = step.get("timeout_ms", 30_000)
            if type(timeout) is not int or not 1 <= timeout <= 120_000:
                raise ValueError(f"{cis}: timeout_ms must be between 1 and 120000")
            if step.get("state", "visible") not in {"visible", "hidden", "attached", "detached"}:
                raise ValueError(f"{cis}: invalid wait state")
        expected_url = raw.get("expected_url")
        ready_selector = raw.get("ready_selector")
        frame_selector = raw.get("frame_selector")
        if frame_selector is not None and (
            not isinstance(frame_selector, str) or not frame_selector.strip()
        ):
            raise ValueError(f"{cis}: frame_selector must be a nonempty selector")
        highlights = raw.get("highlight_selectors", [])
        checks = raw.get("expected_checks", [])
        if not isinstance(checks, list) or any(
            not isinstance(check, dict) or not isinstance(check.get("selector"), str)
            or not check["selector"] or not any(
                key in check for key in (
                    "checked", "value", "allowed_values", "min_value", "max_value",
                    "not_value", "text", "not_text",
                )
            ) or ("checked" in check and type(check["checked"]) is not bool)
            or any(key in check and not isinstance(check[key], (int, float))
                   for key in ("min_value", "max_value"))
            or any(key in check and not isinstance(check[key], str)
                   for key in ("value", "not_value", "text", "not_text"))
            or ("allowed_values" in check and (
                not isinstance(check["allowed_values"], list)
                or not check["allowed_values"]
                or any(not isinstance(value, str) for value in check["allowed_values"])
            ))
            for check in checks
        ):
            raise ValueError(
                f"{cis}: expected_checks require a selector and a checked/value comparison"
            )
        if len(checks) > 1 and any(not isinstance(check.get("highlight_selector"), str)
                                   or not check["highlight_selector"] for check in checks):
            raise ValueError(f"{cis}: multiple expected_checks each require highlight_selector")
        if not isinstance(highlights, list) or any(
            not isinstance(selector, str) or not selector.strip() for selector in highlights
        ):
            raise ValueError(f"{cis}: highlight_selectors must be a list of selectors")
        if raw.get("enabled", True):
            if not isinstance(expected_url, str) or not expected_url or not isinstance(
                ready_selector, str
            ) or not ready_selector:
                raise ValueError(f"{cis}: enabled routes require expected_url and ready_selector")
            validate_url(expected_url, hosts)
        controls[cis] = Control(
            cis=cis,
            title=raw["title"],
            start_url=raw["start_url"],
            steps=steps,
            screenshot_selector=raw.get("screenshot_selector"),
            full_page=bool(raw.get("full_page", True)),
            enabled=bool(raw.get("enabled", True)),
            expected_url=expected_url,
            ready_selector=ready_selector,
            highlight_selectors=tuple(highlights),
            expected_checks=tuple(checks),
            frame_selector=frame_selector,
        )
    if not controls:
        raise ValueError("manifest contains no controls")
    return hosts, controls

