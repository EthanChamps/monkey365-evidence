from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from playwright.sync_api import Page, sync_playwright

from .models import CaptureResult, Control


def _assert_allowed(page: Page, allowed_hosts: set[str]) -> None:
    host = (urlparse(page.url).hostname or "").lower()
    if host not in allowed_hosts:
        raise RuntimeError(f"navigation left allowed hosts: {host or page.url}")


def capture_controls(
    controls: list[Control], output: Path, profile: Path, allowed_hosts: set[str]
) -> list[CaptureResult]:
    output.mkdir(parents=True, exist_ok=True)
    results: list[CaptureResult] = []
    with sync_playwright() as playwright:
        context = playwright.chromium.launch_persistent_context(
            str(profile), headless=False, viewport={"width": 1600, "height": 1000}
        )
        page = context.pages[0] if context.pages else context.new_page()
        page.goto(controls[0].start_url, wait_until="domcontentloaded")
        input("Sign in and complete MFA in the browser, then press Enter here: ")
        for control in controls:
            try:
                page.goto(control.start_url, wait_until="domcontentloaded")
                _assert_allowed(page, allowed_hosts)
                for step in control.steps:
                    locator = page.locator(step["selector"])
                    if step["action"] == "click":
                        locator.click(timeout=step.get("timeout_ms", 30_000))
                    elif step["action"] == "wait_for":
                        locator.wait_for(state=step.get("state", "visible"), timeout=step.get("timeout_ms", 30_000))
                    _assert_allowed(page, allowed_hosts)
                if "login" in page.url.lower():
                    raise RuntimeError("authentication page cannot be captured as evidence")
                destination = output / control.filename
                if control.screenshot_selector:
                    page.locator(control.screenshot_selector).screenshot(path=str(destination))
                else:
                    page.screenshot(path=str(destination), full_page=control.full_page)
                results.append(CaptureResult(control.cis, "captured", destination))
            # Per-control isolation is deliberate: the manifest must account for the
            # remaining controls when a portal selector or browser operation fails.
            except Exception as error:  # noqa: BLE001
                results.append(CaptureResult(control.cis, "failed", detail=str(error)))
        context.close()
    return results
