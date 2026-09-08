# Monkey365 Evidence Collector

Turn failed Monkey365 CIS findings into browser screenshots and PowerShell text evidence.
Browser screenshots use red outlines around incorrect settings. PowerShell audits
produce `.txt` files with Command and Output sections, without launching a browser.

The CIS v7 map covers 161 controls. Use `plan` to see which failed controls have
browser routes or PowerShell audits; missing coverage is reported explicitly.

The scanner and browser have separate jobs: Monkey365 determines which controls
failed; a versioned control manifest defines where the setting lives in the UI.
This separation makes portal navigation maintainable when Microsoft changes it.

## Safety model

- Routes use HTTPS navigation, waits, screenshots, and restricted navigation clicks.
- Automated clicks accept links and tabs only; setting inputs and Save buttons are rejected.
- Configured URLs require exact approved hostnames and HTTPS.
- Authentication is interactive and stored in a local ignored browser profile.
- A route must match its expected URL and setting selector before capture.
- Login pages are never accepted as evidence.
- Red outlines temporarily change browser styling and are removed after capture.
- Supported checkbox routes recheck the live state. Settings now matching CIS are
  captured without a red outline and reported as `needs_review`.
- Screenshots and browser profiles are ignored by Git.
- Review screenshots for names, email addresses, tenant IDs, and other sensitive data.

Use this only against a tenant you are authorised to assess. The collector reads
pages but does not change tenant configuration.

## Quick start

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
playwright install chromium
```

The bundled manifest and map target CIS Microsoft 365 Foundations v7.0.0. Validate them:

```powershell
monkey365-evidence validate
```

Preview which failed controls have automated routes:

```powershell
monkey365-evidence plan --monkey365 path\to\monkey365-output
```

Capture evidence in a visible browser. Sign in when prompted, then return to the
terminal and press Enter:

```powershell
monkey365-evidence capture `
  --monkey365 path\to\monkey365.json `
  --output evidence `
  --profile browser-profile
```

Every run creates a timestamped folder under `evidence`, containing evidence files and
`run-manifest.json` with captured, skipped, failed, and review-needed controls.
The report includes evidence SHA-256 hashes and whether red outlines were added.
It is checkpointed after each capture so completed results survive an interruption.
Existing evidence files are never overwritten. Exit codes: `0` complete, `1` invalid
input/setup, `2` incomplete coverage or findings needing review, `130` interrupted.
Use `--controls 1.3.3,1.3.4` to test a small subset before a full run.
Use `--non-interactive` after signing in to reuse the browser profile without a
terminal prompt. Close other browsers using that profile before capture.

## Use from PowerShell

```powershell
Import-Module .\powershell\Monkey365.Evidence\Monkey365.Evidence.psd1
Invoke-Monkey365Evidence -Monkey365Output .\monkey365-output -Plan
Invoke-Monkey365Evidence -Monkey365Output .\monkey365-output
```

Supply an existing scan created with `Invoke-Monkey365 -ExportTo JSON`.
The wrapper processes that export; it does not run remediation or grant consent.

Monkey365 HTML reports are also accepted. The importer reads finding cards as
data; it never executes embedded scripts or commands from the report.

To include the bundled Exchange Online PowerShell audits:

```powershell
Invoke-Monkey365Evidence -Monkey365Output .\report.html -PowerShellAudits -Plan
Invoke-Monkey365Evidence -Monkey365Output .\report.html -PowerShellAudits `
  -ExpectedTenantId '<tenant GUID>' -TestRun
```

Install `ExchangeOnlineManagement` in PowerShell before using Exchange audits.
Graph audits use `Microsoft.Graph.Authentication`, `Microsoft.Graph.Identity.SignIns`,
`Microsoft.Graph.Reports`, `Microsoft.Graph.Groups`, `Microsoft.Graph.Users`, and
`Microsoft.Graph.Identity.DirectoryManagement`.
Authentication may prompt for sign-in. `ExpectedTenantId` stops PowerShell
collection if the connected organization differs. `TestRun` labels the run as
route testing, useful when testing checks from a report against another tenant;
it does not select the browser tenant.

Graph audits start the standard Microsoft Graph PowerShell sign-in when
`-PowerShellAudits` is used. Microsoft may ask for sign-in or for administrator
consent to the required read-only permissions. `ExpectedTenantId` is optional and
stops collection if the selected tenant differs. `GraphClientId` remains available
for organisations that require their own authorised application. The Python CLI
equivalents are `--powershell`, `--graph-client-id`, `--expected-tenant-id`, and
`--test-run`.

PowerShell `.txt` files show the fixed command and its structured output under
Command and Output headings. The extension also saves the original command results.
Evaluation details and review requirements are recorded in `run-manifest.json`;
PowerShell evidence does not use images or red highlighting. Command errors are
recorded as failures without an evidence file. Policy precedence, organization coverage, business exceptions,
and license suitability can require human review even when collection succeeds.
Exit code `2` means the run contains missing evidence or review items; inspect
`run-manifest.json` to distinguish them.

If a persistent browser profile is already open or was created by a different
browser version, use an existing Playwright storage-state file with
`-BrowserStorageState .\login.local.json` (`--storage-state` in the Python CLI).
That starts an isolated browser with the saved login. Keep this file private.

## Monkey365 mapping

Monkey365 records expose `statusCode`, `findingInfo.ruleId`, and often benchmark
metadata. Because exports vary by Monkey365 version and profile, mappings live in
`monkey365-map.json`. Each entry maps a Monkey365 rule/event ID to a CIS control.
Unmapped failed rules are reported and are never silently discarded. Both JSON
files and folders of JSON exports are accepted, including UTF-8 and UTF-16 exports.
Files containing no findings are rejected rather than treated as a clean scan.

The bundled mapping comes from Monkey365 v0.99's CIS v7 ruleset; its source commit
is recorded in `monkey365-map.source.json`. Some upstream numeric IDs are reused,
so unique event IDs take precedence and ambiguous numeric aliases are omitted.
Regenerate mappings for your installed Monkey365 version:

```powershell
monkey365-evidence import-ruleset `
  --ruleset C:\monkey365\rules\rulesets\cis_m365_7.0.0.json `
  --findings C:\monkey365\rules\findings `
  --output mapping.local.json
```

Then supply `--rule-map mapping.local.json` to `plan` and `capture`.

## Manifest actions

Selectors are Playwright locators. Prefer resilient role or text selectors over
generated CSS.

```json
{
  "action": "click",
  "navigation": true,
  "selector": "role=link[name='Example navigation item']"
}
```

The final screenshot can capture the full page or a specific locator. CIS licences
and benchmark text are not included; supply navigation instructions you are entitled
to use.

Copy `controls.v7.json` to `controls.local.json` to extend the routes, then pass
`--manifest controls.local.json`. Enabled routes require `expected_url` and
`ready_selector`. `highlight_selectors` must each identify exactly one visible
element. For checkbox controls, `expected_checks` specifies the expected checked
state and each check's `highlight_selector`, so only incorrect settings are outlined.

## Verification

```powershell
ruff check .
pytest
```

The test suite runs local Chromium fixtures; it does not connect to a tenant.
