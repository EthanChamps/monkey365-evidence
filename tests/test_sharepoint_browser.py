from __future__ import annotations

from pathlib import Path

import pytest

from monkey365_evidence.cli import sharepoint_browser_controls
from monkey365_evidence.collector import capture_page
from monkey365_evidence.manifest import load_manifest

SHAREPOINT_FIXTURE = r"""
<!doctype html>
<html><head><style>
[role=main], .ms-Panel-main { padding:12px; }
[role="slider"] { display:block; width:30px; height:180px; }
input[type=checkbox], input[type=radio] { opacity:0; }
</style></head><body>
<div role="main" data-automation-id="sharingPageMain">
  <h1>Sharing</h1>
  <span>SharePoint</span>
  <div aria-label="Tenant SharePoint"><div role="slider" aria-valuenow="3"></div></div>
  <span>OneDrive</span>
  <div aria-label="OneDrive"><div role="slider" aria-valuenow="3"></div></div>
  <button aria-expanded="false" type="button">More external sharing settings</button>
  <section id="advanced" hidden>
    <div class="ms-Checkbox"><input id="domain" type="checkbox">
      <label for="domain">Limit external sharing by domain</label></div>
    <div class="ms-Checkbox"><input id="groups" type="checkbox">
      <label for="groups">Allow only users in specific security groups to share externally</label>
    </div>
    <div class="ms-Checkbox"><input id="reshare" data-automation-id="resharing-setting"
      type="checkbox" checked><label for="reshare">Allow guests to share items they don't own</label>
    </div>
    <div class="row">
      <div class="ms-Checkbox"><input id="guest" type="checkbox">
        <label for="guest">Guest access to a site or OneDrive will expire automatically after this many days</label>
      </div><input aria-label="Enter the Number of Days" type="text" value="60" disabled>
    </div>
    <div class="row">
      <div class="ms-Checkbox"><input id="reauth" type="checkbox">
        <label for="reauth">People who use a verification code must reauthenticate after this many days</label>
      </div><input aria-label="Enter the Number of Days" type="text" value="30" disabled>
    </div>
  </section>
  <div class="ms-ChoiceFieldGroup">
    <input id="specific" type="radio" name="links">
    <label for="specific">Specific people (only the people the user specifies)</label>
    <input id="internal" type="radio" name="links">
    <label for="internal">Only people in your organization</label>
    <input id="anyone" type="radio" name="links" checked>
    <label for="anyone">Anyone with the link</label>
  </div>
  <div class="ms-ChoiceFieldGroup">
    <input id="view" type="radio" name="permission"><label for="view">View</label>
    <input id="edit" type="radio" name="permission" checked><label for="edit">Edit</label>
  </div>
</div>
<div role="dialog" aria-label="Apps that don't use modern authentication" hidden>
  <div class="ms-Panel-main" style="width:600px;height:500px">
    <div class="ms-ChoiceFieldGroup">
      <input id="allow" type="radio" name="legacy" checked><label for="allow">Allow access</label>
      <input id="block" type="radio" name="legacy"><label for="block">Block access</label>
    </div>
  </div>
</div>
<script>
  const legacy = location.hash.includes('LegacyAuthentication');
  document.querySelector('[role=main]').hidden = legacy;
  document.querySelector('[role=dialog]').hidden = !legacy;
  const button = document.querySelector('button');
  button.addEventListener('click', () => {
    button.setAttribute('aria-expanded', 'true');
    document.querySelector('#advanced').hidden = false;
  });
</script>
</body></html>
"""

def test_sharepoint_manifest_routes_capture_against_browser_fixture(tmp_path: Path):
    playwright = pytest.importorskip("playwright.sync_api")
    root = Path(__file__).parents[1]
    hosts, controls = load_manifest(root / "controls.v7.json")
    tenant = "https://example-admin.sharepoint.com"
    selected = [controls[cis] for cis in (
        "7.2.1", "7.2.3", "7.2.4", "7.2.5", "7.2.6", "7.2.7",
        "7.2.8", "7.2.9", "7.2.10", "7.2.11",
    )]
    selected = sharepoint_browser_controls(selected, tenant)
    output = tmp_path / "evidence"
    output.mkdir()

    with playwright.sync_playwright() as pw:
        try:
            browser = pw.chromium.launch(headless=True)
        except playwright.Error as error:  # pragma: no cover - missing local browser
            if "Executable doesn't exist" not in str(error):
                raise
            pytest.skip("Install Chromium with: python -m playwright install chromium")
        try:
            page = browser.new_page()
            page.route("**/*", lambda route: route.fulfill(
                status=200, content_type="text/html", body=SHAREPOINT_FIXTURE
            ))
            before = None
            results = []
            for control in selected:
                page.goto("about:blank")
                result = capture_page(page, control, output, hosts)
                results.append(result)
                assert result.status == "captured", result.detail
                assert result.highlighted
                assert result.path is not None and result.path.is_file()
                values = page.locator("input").evaluate_all(
                    "els => els.map(el => ({type: el.type, value: el.value, checked: el.checked}))"
                )
                if before is None:
                    before = values
                else:
                    assert values == before
            assert {result.cis for result in results} == {control.cis for control in selected}
            assert all(result.path and result.path.stat().st_size > 0 for result in results)
        finally:
            browser.close()
