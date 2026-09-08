Set-StrictMode -Version Latest

function Invoke-Monkey365Evidence {
    <#
    .SYNOPSIS
    Capture portal evidence for failed Monkey365 findings without changing tenant settings.
    .DESCRIPTION
    Pass a Monkey365 HTML report or the folder or JSON file created by -ExportTo JSON.
    The extension does not run remediation or grant application consent.
    .EXAMPLE
    Invoke-Monkey365Evidence -Monkey365Output .\monkey365-output -Plan
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Monkey365Output,
        [string] $Manifest,
        [string] $RuleMap,
        [string] $OutputDirectory = 'evidence',
        [string] $BrowserProfile = 'browser-profile',
        [string] $BrowserStorageState,
        [string[]] $Controls,
        [string] $Python,
        [switch] $PowerShellAudits,
        [string] $TenantOrganization,
        [guid] $ExpectedTenantId,
        [guid] $GraphClientId,
        [string] $SharePointAdminUrl,
        [switch] $TestRun,
        [switch] $Plan,
        [switch] $NonInteractive
    )
    $repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    if (-not $Manifest) { $Manifest = Join-Path $repositoryRoot 'controls.v7.json' }
    if (-not $RuleMap) { $RuleMap = Join-Path $repositoryRoot 'monkey365-map.json' }
    if (-not $Python) {
        $localPython = Join-Path $repositoryRoot '.venv/Scripts/python.exe'
        if (Test-Path -LiteralPath $localPython) { $Python = $localPython }
        else { $Python = (Get-Command python -ErrorAction Stop).Source }
    }
    $mode = if ($Plan) { 'plan' } else { 'capture' }
    $arguments = @('-m', 'monkey365_evidence.cli', $mode,
                   '--monkey365', $Monkey365Output, '--manifest', $Manifest, '--rule-map', $RuleMap)
    if ($Controls) { $arguments += @('--controls', ($Controls -join ',')) }
    if ($PowerShellAudits) { $arguments += '--powershell' }
    if (-not $Plan) {
        $arguments += @('--output', $OutputDirectory, '--profile', $BrowserProfile)
        if ($BrowserStorageState) { $arguments += @('--storage-state', $BrowserStorageState) }
        if ($NonInteractive) { $arguments += '--non-interactive' }
        if ($TenantOrganization) { $arguments += @('--tenant-organization', $TenantOrganization) }
        if ($ExpectedTenantId -ne [guid]::Empty) {
            $arguments += @('--expected-tenant-id', $ExpectedTenantId.ToString())
        }
        if ($GraphClientId -ne [guid]::Empty) {
            $arguments += @('--graph-client-id', $GraphClientId.ToString())
        }
        if ($SharePointAdminUrl) { $arguments += @('--sharepoint-admin-url', $SharePointAdminUrl) }
        if ($TestRun) { $arguments += '--test-run' }
    }
    & $Python @arguments
    if ($LASTEXITCODE -eq 2) {
        Write-Warning 'The run contains review items or missing captures. See run-manifest.json for details.'
    }
    elseif ($LASTEXITCODE -ne 0) {
        throw "Monkey365 evidence collection failed (exit code $LASTEXITCODE)."
    }
}

Export-ModuleMember -Function Invoke-Monkey365Evidence
