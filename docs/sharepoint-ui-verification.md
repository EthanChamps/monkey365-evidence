# SharePoint UI verification — 2026-09-10

The updated collector was run against the authenticated test tenant, not just
against mocked selectors. No tenant settings were changed.

- All ten CIS v7 UI routes (7.2.1 and 7.2.3–7.2.11): ten highlighted screenshots,
  zero failures/skips/review items, exit code 0.
- `Invoke-ManualSharePointEvidence.ps1 -BrowserOnly -NonInteractive`: five
  screenshots for 7.2.4, 7.2.6, 7.2.8, 7.2.9 and 7.2.10, exit code 0.
- Local run manifests: `evidence/live-sharepoint-verification/20260910T151158.042602Z/`
  and `evidence/wrapper-live-verification/20260910T151241.932086Z/`.
  Tenant screenshots and browser profiles are not included in Git.

## Observed routes and elements

The tenant-specific base is `https://TENANT-admin.sharepoint.com`.

| Controls | Path after the tenant hostname | Observed setting |
| --- | --- | --- |
| 7.2.1 | `/_layouts/15/online/AdminHome.aspx?modern=true#/accessControl/LegacyAuthentication` | Visible `.ms-Panel-main` with Allow/Block access radios |
| 7.2.3–7.2.11 | `/_layouts/15/online/AdminHome.aspx?modern=true#/sharing` | Sharing page's `data-automation-id="sharingPageMain"` |

Sharing levels are ARIA sliders; checkbox/radio inputs are siblings of their
labels. Advanced controls require expanding **More external sharing settings**.
The two day fields share the same accessible name and must be scoped to their
respective setting rows. The legacy dialog wrapper has zero height; capture its
visible panel instead.

Browser-only mode deliberately excludes 7.2.2 and 7.3.1; their PowerShell audits
were not exercised in these browser verification runs. Enabled domain/group
restrictions need review of the configured lists; their enabled state alone is
not treated as proof of compliance. The test tenant had these restrictions off.

This verifies the observed English-language test-tenant UI. It does not guarantee
access permissions, authentication, or identical UI rollout in another tenant.

## Run the five manually identified browser findings

```powershell
git pull --ff-only
python -m pip install -e '.[dev]'
.\Invoke-ManualSharePointEvidence.ps1 -SharePointAdminUrl 'https://YOURTENANT-admin.sharepoint.com/' -BrowserOnly
```

Complete sign-in in the collector browser, then press Enter in PowerShell.
Use `-NonInteractive` only when that collector profile is already signed in.
