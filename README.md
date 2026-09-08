# Monkey365 Evidence Collector

Boilerplate for turning failed Monkey365 CIS findings into consistently named,
read-only screenshots of the corresponding Microsoft administration pages.

The scanner and browser have separate jobs: Monkey365 determines which controls
failed; a versioned control manifest defines where the setting lives in the UI.
This separation makes portal navigation maintainable when Microsoft changes it.

## Safety model

- Only `goto`, `click`, `wait_for`, and `screenshot` actions are supported.
- Navigation is restricted to configured Microsoft hostnames.
- Authentication is interactive and stored in a local ignored browser profile.
- Login pages are never accepted as evidence.
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
Copy-Item controls.example.json controls.local.json
```

Populate `controls.local.json` from the applicable CIS audit instructions. Validate it:

```powershell
monkey365-evidence validate --manifest controls.local.json
```

Preview which failed controls have automated routes:

```powershell
monkey365-evidence plan `
  --monkey365 path\to\monkey365.json `
  --manifest controls.local.json
```

Capture evidence in a visible browser. Sign in when prompted, then return to the
terminal and press Enter:

```powershell
monkey365-evidence capture `
  --monkey365 path\to\monkey365.json `
  --manifest controls.local.json `
  --output evidence `
  --profile browser-profile
```

Every run writes `run-manifest.json` containing captured, skipped, and failed controls.
Use `--controls 0.0.0,0.0.1` to test a small subset before a full run.

## Monkey365 mapping

Monkey365 records expose `statusCode`, `findingInfo.ruleId`, and often benchmark
metadata. Because exports vary by Monkey365 version and profile, mappings live in
`monkey365-map.json`. Each entry maps a Monkey365 rule/event ID to a CIS control.
Unmapped failed rules are reported and are never silently discarded.

## Manifest actions

Selectors are Playwright locators. Prefer resilient role or text selectors over
generated CSS.

```json
{
  "action": "click",
  "selector": "role=link[name='Example navigation item']"
}
```

The final screenshot can capture the full page or a specific locator. CIS licences
and benchmark text are not included; supply navigation instructions you are entitled
to use.
