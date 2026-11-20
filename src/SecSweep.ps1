<#
.SYNOPSIS
    Read-only local security sweep. Writes an HTML and a JSON report.
.DESCRIPTION
    Nothing on this machine gets changed unless -Fix is passed.
    Every result stays on disk locally; there is no outbound request anywhere in the code.
.EXAMPLE
    .\SecSweep.ps1
.EXAMPLE
    .\SecSweep.ps1 -Domains accounts,persistence -Lang en-US
#>
[CmdletBinding()]
param(
    [string]$OutDir,
    [ValidateSet('auto', 'zh-CN', 'en-US')][string]$Lang = 'auto',
    [string[]]$Domains = @('accounts', 'persistence', 'services', 'network', 'processes', 'hardening', 'files', 'credentials', 'events', 'software', 'baseline'),
    [switch]$Fix,
    [switch]$Apply,
    [switch]$IncludeRaw,
    [switch]$SaveBaseline
)

$ErrorActionPreference = 'Stop'

$rootDir = Split-Path -Parent $PSScriptRoot
$libDir = Join-Path $PSScriptRoot 'lib'
$checkDir = Join-Path $PSScriptRoot 'checks'

. (Join-Path $libDir 'i18n.ps1')
. (Join-Path $libDir 'report.ps1')

$langCode = Resolve-UiLanguage -Requested $Lang -LangDir (Join-Path $rootDir 'lang')
$uiText = Import-UiText -Code $langCode -LangDir (Join-Path $rootDir 'lang')
$ctx = New-SweepContext -RootDir $rootDir -RulesDir (Join-Path $rootDir 'rules') -Text $uiText -LangCode $langCode -IncludeRaw:$IncludeRaw

# Native callers hand -Domains over as one comma-joined string; split it back.
$domainList = @()
foreach ($raw in @($Domains)) {
    foreach ($piece in ($raw -split ',')) {
        $item = $piece.Trim()
        if ($item) { $domainList += $item }
    }
}

Write-Host ("=== {0} ===" -f $uiText.cli.banner)
Write-Host ("{0}: {1}" -f $uiText.cli.lang, $uiText.meta.name)

if ($SaveBaseline) {
    # One-shot write, then out.
    $baselineScript = Join-Path $checkDir 'baseline.ps1'
    if (-not (Test-Path -LiteralPath $baselineScript)) { throw 'baseline.ps1 not found next to the other checks' }
    . $baselineScript
    $written = Save-SweepBaseline -RootDir $rootDir
    Write-Host ('baseline: ' + $written)
    return
}

$available = @{}
foreach ($d in $domainList) {
    $scriptPath = Join-Path $checkDir ($d + '.ps1')
    if (Test-Path -LiteralPath $scriptPath) {
        . $scriptPath
        $available[$d] = $true
    }
}

$findings = @()
foreach ($d in $domainList) {
    if (-not $available.ContainsKey($d)) {
        Write-Host ("[{0}] {1}" -f $d, $uiText.cli.skipped)
        continue
    }
    $funcName = 'Invoke-Check' + $d.Substring(0, 1).ToUpperInvariant() + $d.Substring(1)
    $cmd = Get-Command -Name $funcName -ErrorAction SilentlyContinue
    if (-not $cmd) {
        Write-Host ("[{0}] {1}" -f $d, $uiText.cli.skipped)
        continue
    }
    $hits = @(& $cmd $ctx)
    $findings += $hits
    Write-Host ("[{0}] {1} {2}" -f $d, $hits.Count, $uiText.cli.findings)
}

$score = Get-SweepScore -Findings $findings
$grade = Get-SweepGrade -Score $score
$gradeInfo = $uiText.grade.PSObject.Properties[$grade].Value
Write-Host ("{0}: {1}   {2}: {3} ({4})" -f $uiText.cli.score, $score, $uiText.cli.grade, $grade, $gradeInfo.label)

$targetOut = $OutDir
if (-not $targetOut) { $targetOut = Join-Path $rootDir 'out' }
$report = New-SweepReport -Ctx $ctx -Findings $findings -OutDir $targetOut -HostName $env:COMPUTERNAME -Score $score -Grade $grade -KeepRaw:$IncludeRaw
Write-Host ("{0}: {1}" -f $uiText.cli.report_html, $report.HtmlPath)
Write-Host ("{0}: {1}" -f $uiText.cli.report_json, $report.JsonPath)

if ($Fix) {
    . (Join-Path $libDir 'fix.ps1')
    $plan = @(New-FixPlan -Findings $findings)
    if ($plan.Count -eq 0) {
        Write-Host $uiText.cli.fix_none
    }
    else {
        Write-Host $uiText.cli.fix_preview
        foreach ($item in $plan) {
            Write-Host ("  - [{0}] {1}  [{2}]" -f $item.RuleId, $item.Description, $item.PreState)
        }
        if (-not $Apply) {
            Write-Host $uiText.cli.fix_need_apply
        }
        else {
            $applied = @(Invoke-FixApply -Plan $plan)
            $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
            $undoPath = New-UndoScript -Applied $applied -OutDir $targetOut -Stamp $stamp
            Write-Host ($uiText.cli.fix_applied -f $applied.Count)
            Write-Host ($uiText.cli.fix_undo -f $undoPath)
        }
    }
}
else {
    Write-Host $uiText.cli.readonly
}

Write-Host $uiText.cli.done
