# SharePoint UI verification — 2026-09-10

## Highlight correction after ZIP review

The original run succeeded at collection but its outward CSS outlines were
clipped. Its `highlighted` flag did not validate the rendered borders. The ZIP
review found incomplete borders in all five supplied screenshots.

SharePoint screenshots now use fixed, content-fitted overlays outside the
portal's clipping containers. Slider boxes include their headings; checkbox
and day-value boxes stop at their visible content. Transparent full-width
radio hit targets are excluded from measurement. All overlays are removed
after capture, without changing settings.

The collector checks the actual PNG for all four red borders **before writing
the evidence file**. A clipped or obscured border fails capture. Browser tests
cover overflow containers, both 1x/2x pixel density, invisible radio hit targets,
cleanup on failure, and deliberately missing border pixels.

The corrected live run `evidence/box-verification/20260910T154044.738167Z/`
produced ten screenshots. Visual inspection and a separate PNG pixel scan
confirmed all 12 rectangles had complete borders. The same scan failed all
five images from the original ZIP. The final PowerShell wrapper run with
in-collector PNG verification also passed, five files and exit code 0:
`evidence/box-wrapper-verification/20260910T154345.744643Z/`.
The final all-ten run with in-collector PNG verification passed at
`evidence/box-final-verification/20260910T154441.919242Z/`.

## Original route verification

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
