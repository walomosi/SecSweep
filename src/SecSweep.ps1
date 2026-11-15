<#
.SYNOPSIS
    本机安全体检：只读扫描，输出 HTML 与 JSON 报告。
.DESCRIPTION
    默认不改任何系统配置。加 -Fix 才会列出可逆处置动作。
    报告与中间数据全部留在本地，代码里没有任何出站请求。
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

# 外部传参时 accounts,services 会被压成一个字符串，这里统一拆开
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
    # 基线只写一次，写完就退，不用继续扫
    $baselineScript = Join-Path $checkDir 'baseline.ps1'
    if (-not (Test-Path -LiteralPath $baselineScript)) { throw '找不到 baseline.ps1' }
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
    $actions = @(Get-FixCandidates -Ctx $ctx -Findings $findings)
    if ($actions.Count -eq 0) {
        Write-Host $uiText.cli.fix_none
    }
    else {
        Write-Host $uiText.cli.fix_dry
        foreach ($a in $actions) { Write-Host ("  - [{0}] {1}" -f $a.rule, $a.action) }
    }
}
else {
    Write-Host $uiText.cli.readonly
}

Write-Host $uiText.cli.done
