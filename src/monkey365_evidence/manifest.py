from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

from .models import Control

ALLOWED_ACTIONS = {"click", "expand", "wait_for"}


def validate_url(url: str, hosts: set[str], host_patterns: tuple[re.Pattern[str], ...] = ()) -> None:
    parsed = urlparse(url)
    encoded_patterns = tuple(
        re.compile(host[3:]) for host in hosts if host.startswith("re:")
    )
    exact_hosts = {host for host in hosts if not host.startswith("re:")}
    if (parsed.scheme != "https" or parsed.username or parsed.password
            or parsed.port not in (None, 443) or not parsed.hostname
            or (parsed.hostname not in exact_hosts and not any(
                pattern.fullmatch(parsed.hostname) for pattern in (*host_patterns, *encoded_patterns)
            ))):
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
    raw_patterns = data.get("allowed_host_patterns", [])
    if not isinstance(raw_patterns, list) or any(
        not isinstance(pattern, str) or not pattern for pattern in raw_patterns
    ):
        raise ValueError("allowed_host_patterns must be a list of nonempty regexes")
    try:
        host_patterns = tuple(re.compile(pattern) for pattern in raw_patterns)
    except re.error as error:
        raise ValueError(f"invalid allowed host pattern: {error}") from error
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
        if host not in hosts and not any(pattern.fullmatch(host) for pattern in host_patterns):
            raise ValueError(f"{cis}: start_url host {host!r} is not allowed")
        validate_url(raw["start_url"], hosts, host_patterns)
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
            if step["action"] == "expand" and step.get("navigation") is not None:
                raise ValueError(f"{cis}: expand must not navigate")
            timeout = step.get("timeout_ms", 30_000)
            if type(timeout) is not int or not 1 <= timeout <= 120_000:
                raise ValueError(f"{cis}: timeout_ms must be between 1 and 120000")
            if step.get("state", "visible") not in {"visible", "hidden", "attached", "detached"}:
                raise ValueError(f"{cis}: invalid wait state")
        expected_url = raw.get("expected_url")
        expected_url_pattern = raw.get("expected_url_pattern")
        if expected_url is not None and expected_url_pattern is not None:
            raise ValueError(f"{cis}: use expected_url or expected_url_pattern, not both")
        if expected_url_pattern is not None:
            if not isinstance(expected_url_pattern, str) or not expected_url_pattern:
                raise ValueError(f"{cis}: expected_url_pattern must be a nonempty regex")
            try:
                re.compile(expected_url_pattern)
            except re.error as error:
                raise ValueError(f"{cis}: invalid expected_url_pattern: {error}") from error
        ready_selector = raw.get("ready_selector")
        frame_selector = raw.get("frame_selector")
        if frame_selector is not None and (
            not isinstance(frame_selector, str) or not frame_selector.strip()
        ):
            raise ValueError(f"{cis}: frame_selector must be a nonempty selector")
        highlights = raw.get("highlight_selectors", [])
        checks = raw.get("expected_checks", [])
        any_checks = raw.get("expected_any_checks", [])
        def valid_check(check):
            return isinstance(check, dict) and isinstance(check.get("selector"), str) and bool(check["selector"]) and any(
                key in check for key in (
                    "checked", "value", "allowed_values", "min_value", "max_value",
                    "not_value", "text", "not_text", "min_count",
                )
            ) and ("checked" not in check or type(check["checked"]) is bool) and all(
                key not in check or isinstance(check[key], (int, float))
                for key in ("min_value", "max_value", "min_count")
            ) and all(
                key not in check or isinstance(check[key], str)
                for key in ("value", "not_value", "text", "not_text")
            ) and ("allowed_values" not in check or (
                isinstance(check["allowed_values"], list) and check["allowed_values"]
                and all(isinstance(value, str) for value in check["allowed_values"])
            ))
        if not isinstance(checks, list) or any(
            not valid_check(check) for check in checks
        ):
            raise ValueError(
                f"{cis}: expected_checks require a selector and a checked/value comparison"
            )
        if not isinstance(any_checks, list) or any(
            not isinstance(group, list) or not group or any(not valid_check(check) for check in group)
            for group in any_checks
        ):
            raise ValueError(f"{cis}: expected_any_checks must be nonempty check groups")
        all_checks = checks + [check for group in any_checks for check in group]
        if len(all_checks) > 1 and any(not isinstance(check.get("highlight_selector"), str)
                                       or not check["highlight_selector"] for check in all_checks):
            raise ValueError(f"{cis}: multiple expected_checks each require highlight_selector")
        if not isinstance(highlights, list) or any(
            not isinstance(selector, str) or not selector.strip() for selector in highlights
        ):
            raise ValueError(f"{cis}: highlight_selectors must be a list of selectors")
        if raw.get("enabled", True):
            if (not ((isinstance(expected_url, str) and expected_url)
                     or (isinstance(expected_url_pattern, str) and expected_url_pattern))
                    or not isinstance(ready_selector, str) or not ready_selector):
                raise ValueError(f"{cis}: enabled routes require expected_url and ready_selector")
            if expected_url:
                validate_url(expected_url, hosts, host_patterns)
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
            expected_any_checks=tuple(tuple(group) for group in any_checks),
            frame_selector=frame_selector,
            expected_url_pattern=expected_url_pattern,
        )
    if not controls:
        raise ValueError("manifest contains no controls")
    return hosts | {f"re:{pattern}" for pattern in raw_patterns}, controls

