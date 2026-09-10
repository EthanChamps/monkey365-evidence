[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^https://[a-zA-Z0-9-]+-admin\.sharepoint\.com/?$')]
    [string] $SharePointAdminUrl,

    [string] $Output = (Join-Path $PSScriptRoot 'evidence'),

    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string] $ExpectedTenantId,

    [switch] $NonInteractive
)

$ErrorActionPreference = 'Stop'

# These were confirmed manually from Get-SPOTenant.  The evidence collector will
# re-query the live tenant and write evidence only for these controls.
$controls = @('7.2.2', '7.2.4', '7.2.6', '7.2.8', '7.2.9', '7.2.10', '7.3.1')

$tool = Get-Command monkey365-evidence -ErrorAction SilentlyContinue
if (-not $tool) {
    throw "monkey365-evidence was not found. From the repository folder, install it with: py -m pip install -e '.[dev]'"
}

New-Item -ItemType Directory -Path $Output -Force | Out-Null
$inputDirectory = Join-Path $Output ("manual-sharepoint-input-" + (Get-Date -Format 'yyyyMMddTHHmmss'))
New-Item -ItemType Directory -Path $inputDirectory -ErrorAction Stop | Out-Null

$findingsPath = Join-Path $inputDirectory 'manual-sharepoint-failures.json'
$mapPath = Join-Path $inputDirectory 'manual-sharepoint-map.json'

$findings = foreach ($control in $controls) {
    [pscustomobject]@{
        statusCode  = 'fail'
        ruleId      = "manual-sharepoint-$control"
        findingInfo = @{ title = "Manual SharePoint finding $control" }
    }
}

$ruleMap = @{}
foreach ($control in $controls) {
    $ruleMap["manual-sharepoint-$control"] = $control
}

$findings | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $findingsPath -Encoding utf8
$ruleMap | ConvertTo-Json | Set-Content -LiteralPath $mapPath -Encoding utf8

$captureArguments = @(
    'capture',
    '--monkey365', $findingsPath,
    '--rule-map', $mapPath,
    '--controls', ($controls -join ','),
    '--powershell',
    '--sharepoint-admin-url', $SharePointAdminUrl,
    '--output', $Output
)
if ($ExpectedTenantId) {
    $captureArguments += @('--expected-tenant-id', $ExpectedTenantId)
}
if ($NonInteractive) {
    $captureArguments += '--non-interactive'
}

Write-Host "Collecting live SharePoint evidence for: $($controls -join ', ')"
& $tool.Source @captureArguments
if ($LASTEXITCODE -ne 0) {
    throw "monkey365-evidence exited with code $LASTEXITCODE. Inspect the run-manifest.json in $Output."
}
