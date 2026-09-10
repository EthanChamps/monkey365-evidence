[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^https://[a-zA-Z0-9-]+-admin\.sharepoint\.com/?$')]
    [string] $SharePointAdminUrl,

    [string] $Profile = (Join-Path $PSScriptRoot 'browser-profile'),

    [string] $Output = (Join-Path $PSScriptRoot 'sharepoint-ui-diagnostic')
)

$ErrorActionPreference = 'Stop'
$adminUrl = $SharePointAdminUrl.TrimEnd('/')
New-Item -ItemType Directory -Path $Output -Force | Out-Null
New-Item -ItemType Directory -Path $Profile -Force | Out-Null

$python = @'
import json
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

admin_url, profile, output = sys.argv[1:]
sharing_url = admin_url + "/_layouts/15/online/AdminHome.aspx?modern=true#/sharing"
output_path = Path(output)

with sync_playwright() as playwright:
    context = playwright.chromium.launch_persistent_context(
        profile, headless=False, viewport={"width": 1600, "height": 1000}
    )
    try:
        page = context.pages[0] if context.pages else context.new_page()
        page.goto(sharing_url, wait_until="domcontentloaded")
        input("Sign in and complete MFA in the browser, then press Enter here: ")
        page.goto(sharing_url, wait_until="commit")
        page.wait_for_timeout(3000)
        page.screenshot(path=str(output_path / "sharing-page.png"), full_page=True)
        elements = page.locator("a, button, input, select, textarea, [role]").evaluate_all("""
            nodes => nodes.filter(el => {
                const style = getComputedStyle(el);
                return style.display !== 'none' && style.visibility !== 'hidden'
                    && el.getBoundingClientRect().width > 0 && el.getBoundingClientRect().height > 0;
            }).map(el => ({
                tag: el.tagName.toLowerCase(), role: el.getAttribute('role'),
                label: el.getAttribute('aria-label'), text: (el.innerText || el.textContent || '')
                    .replace(/\\s+/g, ' ').trim().slice(0, 300),
                href: el.getAttribute('href'), type: el.getAttribute('type'),
                name: el.getAttribute('name'), value: el.getAttribute('value'),
                checked: el.checked === undefined ? null : el.checked,
                expanded: el.getAttribute('aria-expanded')
            })).filter(item => item.label || item.text || item.href || item.name);
        """)
        (output_path / "sharing-page-elements.json").write_text(json.dumps({
            "url": page.url, "title": page.title(), "elements": elements
        }, indent=2), encoding="utf-8")
        print("Wrote " + str(output_path / "sharing-page.png"))
        print("Wrote " + str(output_path / "sharing-page-elements.json"))
    finally:
        context.close()
'@

$temporary = Join-Path $Output 'sharepoint-ui-diagnostic.py'
[IO.File]::WriteAllText($temporary, $python, [Text.UTF8Encoding]::new($false))
try {
    & py $temporary $adminUrl (Resolve-Path -LiteralPath $Profile) (Resolve-Path -LiteralPath $Output)
    if ($LASTEXITCODE -ne 0) { throw "Playwright diagnostic exited with code $LASTEXITCODE" }
} finally {
    Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
}
