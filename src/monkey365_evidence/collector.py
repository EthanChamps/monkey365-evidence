from __future__ import annotations

import hashlib
import re
import time
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from urllib.parse import urljoin, urlparse

from playwright.sync_api import Locator, Page, sync_playwright
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

from .manifest import validate_url
from .models import CaptureResult, Control

MUTATING_LABEL = re.compile(
    r"\b(save|apply|delete|remove|reset|enable|disable|allow|block|create|add|"
    r"submit|confirm|consent|revoke|purchase|buy|activate|deactivate|update)\b", re.IGNORECASE
)


def _assert_allowed(page: Page, allowed_hosts: set[str], host_patterns=()) -> None:
    validate_url(page.url, allowed_hosts, host_patterns)


def wait_for_rendered(page: Page, locator: Locator, timeout: int = 30_000) -> None:
    """Playwright visibility ignores opacity; Entra keeps inputs under skeletons."""
    locator.wait_for(state="visible", timeout=timeout)
    deadline = time.monotonic() + timeout / 1000
    while time.monotonic() < deadline:
        rendered = locator.evaluate("""el => {
            // Visibility may be overridden by descendants (Fluent UI layers do
            // this); opacity cannot. Check visibility only on the target.
            if (getComputedStyle(el).visibility !== 'visible') return false;
            for (let parent = el; parent; parent = parent.parentElement) {
                const style = getComputedStyle(parent);
                const nativeChoice = parent === el && el.tagName === 'INPUT'
                    && ['checkbox', 'radio'].includes(el.type);
                if ((!nativeChoice && Number(style.opacity) < 0.99)
                    || style.display === 'none' || parent.getAttribute('aria-busy') === 'true'
                    || parent.getAttribute('aria-hidden') === 'true') return false;
            }
            return true;
        }""")
        if rendered:
            return
        page.wait_for_timeout(100)
    raise RuntimeError("setting did not finish rendering; refusing loading-placeholder evidence")


def navigate_click(page: Page, selector: str, hosts: set[str], timeout: int,
                   frame_selector: str | None = None) -> None:
    """Only links and tabs; buttons, inputs and action menu items fail closed."""
    scope = page.frame_locator(frame_selector) if frame_selector else page
    locator = scope.locator(selector)
    locator.wait_for(state="visible", timeout=timeout)
    attributes = locator.evaluate("""el => ({
        tag: el.tagName.toLowerCase(), role: el.getAttribute('role'),
        href: el.getAttribute('href'), text: el.getAttribute('aria-label') || el.textContent,
        toggle: el.hasAttribute('aria-checked') || el.hasAttribute('aria-pressed')
    })""")
    if attributes["toggle"] or MUTATING_LABEL.search(attributes["text"] or ""):
        raise RuntimeError("refused a potentially mutating click")
    if attributes["tag"] == "a" and attributes["href"]:
        destination = urljoin(page.url, attributes["href"])
        validate_url(destination, hosts)
        page.goto(destination, wait_until="domcontentloaded", timeout=timeout)
    elif attributes["role"] in {"tab", "button"} or attributes["tag"] == "button":
        locator.click(timeout=timeout)
    else:
        raise RuntimeError("read-only clicks require a navigation link or tab")


def expand_section(page: Page, selector: str, timeout: int, frame_selector: str | None = None) -> None:
    """Open an aria disclosure control without changing any tenant setting."""
    scope = page.frame_locator(frame_selector) if frame_selector else page
    locator = scope.locator(selector)
    if locator.count() != 1:
        raise RuntimeError(f"expand control must identify exactly one element: {selector}")
    locator.wait_for(state="visible", timeout=timeout)
    attributes = locator.evaluate("""el => ({
        tag: el.tagName.toLowerCase(), role: el.getAttribute('role'),
        text: el.getAttribute('aria-label') || el.textContent,
        expanded: el.getAttribute('aria-expanded')
    })""")
    if (attributes["tag"] != "button" and attributes["role"] != "button") or (
        attributes["expanded"] not in {"true", "false"}
    ) or MUTATING_LABEL.search(attributes["text"] or ""):
        raise RuntimeError("refused a non-disclosure expand action")
    if attributes["expanded"] == "false":
        locator.click(timeout=timeout)


def screenshot_control(page: Page, control: Control, destination: Path) -> bool:
    """Outline the exact setting in the browser, then restore its presentation."""
    highlighted = []
    scope = page.frame_locator(control.frame_selector) if control.frame_selector else page
    try:
        for selector in control.highlight_selectors:
            locator = scope.locator(selector)
            if locator.count() != 1:
                raise RuntimeError(f"highlight must identify exactly one setting: {selector}")
            wait_for_rendered(page, locator)
            locator.scroll_into_view_if_needed()
            old = locator.evaluate("""el => {
                const old = ['outline', 'outline-offset'].map(name =>
                    [name, el.style.getPropertyValue(name), el.style.getPropertyPriority(name)]);
                el.style.setProperty('outline', '3px solid #e00000', 'important');
                el.style.setProperty('outline-offset', '3px', 'important');
                return old;
            }""")
            highlighted.append((locator, old))
        if control.screenshot_selector:
            scope.locator(control.screenshot_selector).screenshot(path=str(destination))
        else:
            page.screenshot(path=str(destination), full_page=control.full_page)
        return bool(highlighted)
    finally:
        for locator, old in highlighted:
            locator.evaluate("""(el, old) => old.forEach(([name, value, priority]) => {
                if (value) el.style.setProperty(name, value, priority);
                else el.style.removeProperty(name);
            })""", old)


def setting_matches(locator: Locator, check: dict) -> bool:
    """Compare a visible form setting without changing it."""
    if "min_count" in check and locator.count() < check["min_count"]:
        return False
    if "checked" in check and locator.is_checked() != check["checked"]:
        return False
    if any(key in check for key in (
        "value", "allowed_values", "not_value", "min_value", "max_value"
    )):
        actual = locator.input_value().strip()
        if "value" in check and actual != check["value"]:
            return False
        if "allowed_values" in check and actual not in check["allowed_values"]:
            return False
        if "not_value" in check and actual == check["not_value"]:
            return False
        if "min_value" in check or "max_value" in check:
            try:
                number = float(actual)
            except ValueError:
                return False
            if "min_value" in check and number < check["min_value"]:
                return False
            if "max_value" in check and number > check["max_value"]:
                return False
    if "text" in check or "not_text" in check:
        actual_text = " ".join(locator.inner_text().split())
        if "text" in check and check["text"] not in actual_text:
            return False
        if "not_text" in check and check["not_text"] in actual_text:
            return False
    return True


def capture_page(page: Page, control: Control, output: Path, hosts: set[str],
                 *, retry_timeout: bool = True) -> CaptureResult:
    try:
        validate_url(control.start_url, hosts)
        # SharePoint Admin Center redirects the generic admin URL while its SPA
        # starts. Waiting only for the navigation commit avoids treating that
        # legitimate redirect as a failed capture.
        page.goto(control.start_url, wait_until="commit")
        page.wait_for_timeout(750)
        scope = page.frame_locator(control.frame_selector) if control.frame_selector else page
        for step in control.steps:
            _assert_allowed(page, hosts)
            timeout = step.get("timeout_ms", 30_000)
            if step["action"] == "click":
                navigate_click(page, step["selector"], hosts, timeout, control.frame_selector)
            elif step["action"] == "expand":
                expand_section(page, step["selector"], timeout, control.frame_selector)
            elif step["action"] == "wait_for":
                scope.locator(step["selector"]).wait_for(
                    state=step.get("state", "visible"), timeout=timeout
                )
        if not control.expected_url or not control.ready_selector:
            raise RuntimeError("route requires expected_url and ready_selector")
        if control.expected_url:
            page.wait_for_url(lambda url: str(url) == control.expected_url, timeout=30_000)
        elif control.expected_url_pattern:
            pattern = re.compile(control.expected_url_pattern)
            page.wait_for_url(lambda url: bool(pattern.fullmatch(str(url))), timeout=30_000)
        else:
            raise RuntimeError("route requires expected_url or expected_url_pattern")
        wait_for_rendered(page, scope.locator(control.ready_selector))
        scope.locator(control.ready_selector).scroll_into_view_if_needed()
        _assert_allowed(page, hosts)
        if "login" in (urlparse(page.url).hostname or "") or page.locator(
            'input[type="password"]'
        ).count():
            raise RuntimeError("authentication page cannot be captured as evidence")
        destination = output / control.filename
        if destination.exists():
            raise RuntimeError(f"refusing to overwrite existing evidence: {destination.name}")
        failing_checks = []
        for check in control.expected_checks:
            setting = scope.locator(check["selector"])
            if "min_count" in check:
                if not setting_matches(setting, check):
                    failing_checks.append(check)
                continue
            wait_for_rendered(page, setting)
            if not setting_matches(setting, check):
                failing_checks.append(check)
        if control.expected_any_checks:
            matching_groups = []
            for group in control.expected_any_checks:
                group_matches = True
                for check in group:
                    setting = scope.locator(check["selector"])
                    if setting.count() == 0 or not setting_matches(setting, check):
                        group_matches = False
                        failing_checks.append(check)
                matching_groups.append(group_matches)
            if any(matching_groups):
                failing_checks = [check for check in failing_checks
                                  if check in control.expected_checks]
        if (control.expected_checks or control.expected_any_checks) and not failing_checks:
            screenshot_control(page, replace(control, highlight_selectors=()), destination)
            return CaptureResult(
                control.cis, "needs_review", destination,
                detail="The visible setting now matches the expected state; no red box added",
                sha256=hashlib.sha256(destination.read_bytes()).hexdigest(), url=page.url,
            )
        if failing_checks and all(check.get("highlight_selector") for check in failing_checks):
            control = replace(control, highlight_selectors=tuple(dict.fromkeys(
                check["highlight_selector"] for check in failing_checks
            )))
        marked = screenshot_control(page, control, destination)
        return CaptureResult(
            control.cis, "captured", destination,
            detail=None if marked else "No setting highlight configured for this route",
            highlighted=marked, sha256=hashlib.sha256(destination.read_bytes()).hexdigest(),
            url=page.url,
        )
    except PlaywrightTimeoutError as error:
        if retry_timeout and not (output / control.filename).exists():
            try:
                page.goto("about:blank", wait_until="domcontentloaded")
                return capture_page(page, control, output, hosts, retry_timeout=False)
            except Exception as retry_error:  # noqa: BLE001 - preserve subsequent controls
                return CaptureResult(control.cis, "failed", detail=str(retry_error))
        return CaptureResult(control.cis, "failed", detail=str(error))
    except Exception as error:  # noqa: BLE001 - record each control's failure and continue
        return CaptureResult(control.cis, "failed", detail=str(error))


def capture_controls(
    controls: list[Control], output: Path, profile: Path, allowed_hosts: set[str],
    *, interactive: bool = True,
    on_result: Callable[[CaptureResult], None] | None = None,
    storage_state: Path | None = None,
) -> list[CaptureResult]:
    if not controls:
        return []
    output.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as playwright:
        browser = None
        if storage_state:
            browser = playwright.chromium.launch(headless=False)
            context = browser.new_context(storage_state=str(storage_state.resolve()),
                                          viewport={"width": 1600, "height": 1000})
        else:
            context = playwright.chromium.launch_persistent_context(
                str(profile.resolve()), headless=False, viewport={"width": 1600, "height": 1000}
            )
        try:
            page = context.pages[0] if context.pages else context.new_page()
            if interactive:
                page.goto(controls[0].start_url, wait_until="domcontentloaded")
                input("Sign in and complete MFA in the browser, then press Enter here: ")
            results = []
            for control in controls:
                result = capture_page(page, control, output, allowed_hosts)
                results.append(result)
                if on_result:
                    on_result(result)
            return results
        finally:
            context.close()
            if browser:
                browser.close()
