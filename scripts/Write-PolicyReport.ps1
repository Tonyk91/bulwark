<#
.SYNOPSIS
    Turns conftest JSON output into a Markdown report for the developer.

.DESCRIPTION
    Reads the result of `conftest test -o json`, writes a Markdown table of
    blocking findings and active exceptions, and exits non-zero when anything
    blocks. In GitHub Actions the report goes to the job summary; in GitLab CI
    it is written to a file that the pipeline keeps as an artifact.

.EXAMPLE
    conftest test ... -o json > results.json
    pwsh scripts/Write-PolicyReport.ps1 -ResultsPath results.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $ResultsPath,

    # Defaults to the GitHub job summary when running in GitHub Actions.
    [string] $ReportPath = $env:GITHUB_STEP_SUMMARY
)

$ErrorActionPreference = 'Stop'

# Fail closed: if conftest crashed or wrote nothing, block instead of
# reporting a pass.
$raw = Get-Content -Raw -Path $ResultsPath -ErrorAction SilentlyContinue
if ([string]::IsNullOrWhiteSpace($raw)) {
    Write-Error "No conftest results in '$ResultsPath'; treating as failure." -ErrorAction Continue
    exit 2
}
$results = @($raw | ConvertFrom-Json)
if ($results.Count -eq 0) {
    Write-Error 'conftest returned no results; treating as failure.' -ErrorAction Continue
    exit 2
}
$failures = @($results | ForEach-Object { $_.failures } | Where-Object { $_ })
$warnings = @($results | ForEach-Object { $_.warnings } | Where-Object { $_ })

# conftest nests rule metadata one level down: { msg, metadata: { metadata: {...} } }
function Get-Finding($result) {
    if ($result.metadata.metadata) { return $result.metadata.metadata }
    return $result.metadata
}

function Format-Cell([string] $text) {
    # Pipes would break the Markdown table.
    return ($text -replace '\|', '\|' -replace "`r?`n", ' ')
}

$lines = [System.Collections.Generic.List[string]]::new()

if ($failures.Count -eq 0) {
    $lines.Add('## Guardrails: passed')
} else {
    $lines.Add("## Guardrails: $($failures.Count) blocking finding(s)")
    $lines.Add('')
    $lines.Add('| Rule | Resource | Problem | How to fix |')
    $lines.Add('|---|---|---|---|')
    foreach ($f in $failures | Sort-Object { (Get-Finding $_).rule }, { (Get-Finding $_).resource }) {
        $m = Get-Finding $f
        $lines.Add("| $($m.rule) | ``$($m.resource)`` | $(Format-Cell $m.problem) | $(Format-Cell $m.fix) |")
    }
}

if ($warnings.Count -gt 0) {
    $lines.Add('')
    $lines.Add("### Active exceptions ($($warnings.Count))")
    $lines.Add('')
    $lines.Add('| Rule | Resource | Ticket | Expires |')
    $lines.Add('|---|---|---|---|')
    foreach ($w in $warnings) {
        $m = Get-Finding $w
        $lines.Add("| $($m.rule) | ``$($m.resource)`` | $($m.ticket) | $($m.waived_until) |")
    }
}

$report = $lines -join "`n"
Write-Output $report

if ($ReportPath) {
    Add-Content -Path $ReportPath -Value $report
}

if ($failures.Count -gt 0) {
    exit 1
}
