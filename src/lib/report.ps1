# 报告与评分。检查函数只产出事实，判读和文案都在这里做，便于单独调整。

$script:GradeThresholdA = 90
$script:GradeThresholdB = 75
$script:GradeThresholdC = 50

function New-SweepContext {
    param(
        [string]$RootDir,
        [string]$RulesDir,
        $Text,
        [string]$LangCode,
        [switch]$IncludeRaw,
        $Whitelist
    )

    $ruleRaw = [System.IO.File]::ReadAllText((Join-Path $RulesDir 'rules.json'), [System.Text.Encoding]::UTF8)
    $ruleSet = $ruleRaw | ConvertFrom-Json
    $index = @{}
    foreach ($r in $ruleSet.rules) { $index[$r.id] = $r }

    if (-not $Whitelist) {
        $wlRaw = [System.IO.File]::ReadAllText((Join-Path $RulesDir 'whitelist.json'), [System.Text.Encoding]::UTF8)
        $Whitelist = $wlRaw | ConvertFrom-Json
    }

    return @{
        RootDir    = $RootDir
        RuleIndex  = $index
        Whitelist  = $Whitelist
        Text       = $Text
        LangCode   = $LangCode
        IncludeRaw = [bool]$IncludeRaw
    }
}

function New-ReportBody {
    param($Ctx, $Findings, [bool]$KeepRaw, $AltText)

    if (@($Findings).Count -eq 0) {
        $empty = ConvertTo-HtmlSafe $Ctx.Text.report.no_issues
        return "<p class=""empty"">$empty</p>"
    }

    $sb = New-Object System.Text.StringBuilder
    foreach ($group in (@($Findings) | Group-Object -Property Domain)) {
        $key = $group.Name
        $here = [string]$Ctx.Text.domains.$key
        $other = ''
        if ($AltText) { $other = [string]$AltText.domains.$key }
        if ($Ctx.LangCode -match '^zh') { $zh = $here; $en = $other }
        else { $en = $here; $zh = $other }
        $shown = $here
        if (-not $shown) { $shown = $key }
        $domainHtml = ConvertTo-HtmlSafe $shown
        $zhHtml = ConvertTo-HtmlSafe $zh
        $enHtml = ConvertTo-HtmlSafe $en
        if (-not $enHtml) { $enHtml = $domainHtml }
        [void]$sb.Append("<section class=""domain""><h2 class=""t"" data-zh=""$zhHtml"" data-en=""$enHtml"">$domainHtml</h2>")
        foreach ($f in $group.Group) {
            [void]$sb.Append((New-FindingRow -Ctx $Ctx -Finding $f -KeepRaw $KeepRaw))
        }
        [void]$sb.Append('</section>')
    }
    return $sb.ToString()
}

function New-ReportStyle {
    return @"
<style>
*{box-sizing:border-box}
body{margin:0;padding:32px;font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;background:#f5f6f8;color:#1f2328}
.wrap{max-width:960px;margin:0 auto}
header{background:#fff;border-radius:10px;padding:24px 28px;border:1px solid #e3e6ea}
h1{margin:0 0 6px;font-size:22px}
.sub{color:#6b7480;font-size:13px}
.scorebar{display:flex;gap:28px;margin-top:18px;flex-wrap:wrap}
.scorebar div span{display:block;font-size:12px;color:#6b7480}
.scorebar div b{font-size:26px}
button{margin-left:auto;border:1px solid #d6dae0;background:#fff;border-radius:6px;padding:6px 12px;cursor:pointer;font-size:13px}
section.domain{background:#fff;border-radius:10px;margin-top:20px;padding:6px 0 12px;border:1px solid #e3e6ea}
section h2{font-size:15px;margin:16px 24px 8px;color:#3d4654}
.row{padding:14px 24px;border-top:1px solid #eef0f3}
.rowhead{display:flex;align-items:center;gap:10px;font-weight:600}
.badge{font-size:11px;font-weight:600;padding:2px 8px;border-radius:4px;background:#eef0f3;color:#4a5568}
.sev-4 .badge,.sev-5 .badge{background:#fdecea;color:#b42318}
.sev-3 .badge{background:#fff4e5;color:#b54708}
.rid{margin-left:auto;color:#98a2b3;font-weight:400;font-size:12px}
.subject{margin:6px 0 2px;color:#1f2328}
.evidence{font-family:ui-monospace,Consolas,monospace;font-size:12px;color:#5a6472;background:#f8f9fa;border-radius:4px;padding:6px 8px;margin:6px 0;word-break:break-all}
.meta{display:grid;gap:4px;font-size:13px;color:#4a5568}
.meta b{color:#1f2328;margin-right:8px}
.empty{background:#fff;border-radius:10px;padding:28px;text-align:center;color:#4a5568;margin-top:20px}
footer{margin-top:22px;font-size:12px;color:#6b7480;text-align:center}
</style>
"@
}

function New-SweepReport {
    param(
        $Ctx,
        $Findings,
        [string]$OutDir,
        [string]$HostName,
        [int]$Score,
        [string]$Grade,
        [switch]$KeepRaw
    )

    if (-not (Test-Path -LiteralPath $OutDir)) {
        New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
    }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $jsonPath = Join-Path $OutDir ("sweep-" + $stamp + ".json")
    $htmlPath = Join-Path $OutDir ("sweep-" + $stamp + ".html")

    $items = New-FindingsJson -Ctx $Ctx -Findings $Findings -KeepRaw:$KeepRaw
    $jsonDoc = [pscustomobject]@{
        generated = (Get-Date).ToString('s')
        host      = ConvertTo-Masked $HostName ([bool]$KeepRaw)
        score     = $Score
        grade     = $Grade
        lang      = $Ctx.LangCode
        findings  = $items
    }
    $jsonText = $jsonDoc | ConvertTo-Json -Depth 6
    [System.IO.File]::WriteAllText($jsonPath, $jsonText, (New-Object System.Text.UTF8Encoding($false)))

    $body = New-ReportBody -Ctx $Ctx -Findings $Findings -KeepRaw ([bool]$KeepRaw) -AltText $altText
    $style = New-ReportStyle
    # 报告里要两门语言的文案，另一份包只用来填 data-en / data-zh
    $altText = $null
    $altCode = 'en-US'
    if ($Ctx.LangCode -eq 'en-US') { $altCode = 'zh-CN' }
    $altPath = Join-Path (Join-Path $Ctx.RootDir 'lang') ($altCode + '.json')
    if (Test-Path -LiteralPath $altPath) {
        $altRaw = [System.IO.File]::ReadAllText($altPath, [System.Text.Encoding]::UTF8)
        $altText = $altRaw | ConvertFrom-Json
    }

    $gradeNode = $Ctx.Text.grade.PSObject.Properties[$Grade].Value
    $gradeLabel = [string]$gradeNode.label
    $gradeAlt = ''
    if ($altText) { $gradeAlt = [string]$altText.grade.PSObject.Properties[$Grade].Value.label }
    if (-not $gradeAlt) { $gradeAlt = $gradeLabel }
    if ($Ctx.LangCode -match '^zh') { $gradeZh = $gradeLabel; $gradeEn = $gradeAlt }
    else { $gradeEn = $gradeLabel; $gradeZh = $gradeAlt }
    $title = ConvertTo-HtmlSafe ([string]$Ctx.Text.report.title)
    $maskedNote = ''
    if (-not $KeepRaw) { $maskedNote = ConvertTo-HtmlSafe ([string]$Ctx.Text.report.masked) }
    $privacy = ConvertTo-HtmlSafe ([string]$Ctx.Text.report.privacy)
    $totalText = [string]$Ctx.Text.report.total -f @($Findings).Count
    $generated = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $hostText = ConvertTo-HtmlSafe (ConvertTo-Masked $HostName ([bool]$KeepRaw))

    $htmlDoc = @"
<!DOCTYPE html>
<html lang="$(ConvertTo-HtmlSafe $Ctx.LangCode)">
<head><meta charset="utf-8"><title>$title</title>$style</head>
<body><div class="wrap">
<header>
  <h1 class="t" data-zh="$(ConvertTo-HtmlSafe $Ctx.Text.report.title)" data-en="Local Security Report">$title</h1>
  <div class="sub">$generated | $hostText | $totalText</div>
  <div class="scorebar">
    <div><span class="t" data-zh="得分" data-en="Score">得分</span><b>$Score</b></div>
    <div><span class="t" data-zh="等级" data-en="Grade">等级</span><b>$Grade</b></div>
    <div><span class="t" data-zh="说明" data-en="Note">说明</span><b style="font-size:15px" class="t" data-zh="$gradeZh" data-en="$gradeEn">$gradeLabel</b></div>
    <button onclick="setLang('zh-CN')">中文</button>
    <button onclick="setLang('en-US')">English</button>
  </div>
</header>
$body
<footer>$privacy $maskedNote</footer>
</div>
<script>
function setLang(c){
  document.querySelectorAll('.t').forEach(function(e){
    var v = e.getAttribute(c === 'zh-CN' ? 'data-zh' : 'data-en');
    if (v) e.textContent = v;
  });
}
</script>
</body></html>
"@
    [System.IO.File]::WriteAllText($htmlPath, $htmlDoc, (New-Object System.Text.UTF8Encoding($true)))

    return [pscustomobject]@{ JsonPath = $jsonPath; HtmlPath = $htmlPath }
}

function ConvertTo-Masked {
    param([string]$Value, [bool]$KeepRaw)

    if ($KeepRaw -or -not $Value) { return $Value }
    $out = $Value
    # 账户名与主机名换掉，报告可能被截图发出去
    if ($env:USERNAME) { $out = $out -replace [regex]::Escape($env:USERNAME), '<user>' }
    if ($env:COMPUTERNAME) { $out = $out -replace [regex]::Escape($env:COMPUTERNAME), '<host>' }
    # IPv4 只留前两段，用来判断内外网足够
    $out = [regex]::Replace($out, '\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b', '$1.$2.x.x')
    return $out
}

function Get-SweepScore {
    param($Findings)

    # 同一规则命中多次算一个问题，否则十条小毛病会把分数压成 0
    $worst = @{}
    foreach ($f in @($Findings)) {
        $ruleId = [string]$f.RuleId
        $sev = [int]$f.Severity
        if (-not $worst.ContainsKey($ruleId) -or $worst[$ruleId] -lt $sev) { $worst[$ruleId] = $sev }
    }

    # 线性扣分对严重度不敏感，2^(sev-2) 让 5 分项真正拉开差距
    $penalty = 0
    foreach ($sev in $worst.Values) {
        $penalty += [math]::Pow(2, ($sev - 2))
    }
    $score = 100 - [int][math]::Round($penalty)
    if ($score -lt 0) { return 0 }
    return $score
}

function Get-SweepGrade {
    param([int]$Score)

    if ($Score -ge $script:GradeThresholdA) { return 'A' }
    if ($Score -ge $script:GradeThresholdB) { return 'B' }
    if ($Score -ge $script:GradeThresholdC) { return 'C' }
    return 'D'
}

function ConvertTo-HtmlSafe {
    param([string]$Value)

    if (-not $Value) { return '' }
    $out = $Value -replace '&', '&amp;'
    $out = $out -replace '<', '&lt;'
    $out = $out -replace '>', '&gt;'
    $out = $out -replace '"', '&quot;'
    return $out
}

function New-FindingRow {
    param($Ctx, $Finding, [bool]$KeepRaw)

    $rule = $Ctx.RuleIndex[$Finding.RuleId]
    if (-not $rule) { $rule = $null }

    $titleZh = ''
    $titleEn = ''
    $whyZh = ''
    $whyEn = ''
    $fixZh = ''
    $fixEn = ''
    if ($rule) {
        $titleZh = [string]$rule.title.zh
        $titleEn = [string]$rule.title.en
        $whyZh = [string]$rule.why.zh
        $whyEn = [string]$rule.why.en
        $fixZh = [string]$rule.fix.zh
        $fixEn = [string]$rule.fix.en
    }

    $sev = [int]$Finding.Severity
    $subject = ConvertTo-HtmlSafe (ConvertTo-Masked ([string]$Finding.Subject) $KeepRaw)
    $evidence = ConvertTo-HtmlSafe (ConvertTo-Masked ([string]$Finding.Evidence) $KeepRaw)

    $sevLabel = $Ctx.Text.severity.([string]$sev)
    $html = @"
    <div class="row sev-$sev">
      <div class="rowhead">
        <span class="badge">$sevLabel</span>
        <span class="t" data-zh="$(ConvertTo-HtmlSafe $titleZh)" data-en="$(ConvertTo-HtmlSafe $titleEn)">$(ConvertTo-HtmlSafe $titleZh)</span>
        <span class="rid">$($Finding.RuleId)</span>
      </div>
      <div class="subject">$subject</div>
      <div class="evidence">$evidence</div>
      <div class="meta">
        <div><b class="t" data-zh="为什么要管" data-en="Why it matters">为什么要管</b><span class="t" data-zh="$(ConvertTo-HtmlSafe $whyZh)" data-en="$(ConvertTo-HtmlSafe $whyEn)">$(ConvertTo-HtmlSafe $whyZh)</span></div>
        <div><b class="t" data-zh="处置建议" data-en="Fix">处置建议</b><span class="t" data-zh="$(ConvertTo-HtmlSafe $fixZh)" data-en="$(ConvertTo-HtmlSafe $fixEn)">$(ConvertTo-HtmlSafe $fixZh)</span></div>
      </div>
    </div>
"@
    return $html
}

function New-FindingsJson {
    param($Ctx, $Findings, [bool]$KeepRaw)

    $items = @()
    foreach ($f in @($Findings)) {
        $rule = $Ctx.RuleIndex[$f.RuleId]
        $items += [pscustomobject]@{
            rule      = $f.RuleId
            domain    = $f.Domain
            severity  = [int]$f.Severity
            subject   = ConvertTo-Masked ([string]$f.Subject) $KeepRaw
            evidence  = ConvertTo-Masked ([string]$f.Evidence) $KeepRaw
            title_zh  = $(if ($rule) { [string]$rule.title.zh } else { '' })
            title_en  = $(if ($rule) { [string]$rule.title.en } else { '' })
            fix_zh    = $(if ($rule) { [string]$rule.fix.zh } else { '' })
            fix_en    = $(if ($rule) { [string]$rule.fix.en } else { '' })
        }
    }
    return $items
}

function Get-FixCandidates {
    param($Ctx, $Findings)

    # 只挑规则里标了 reversible 的，不可逆的一律不自动动
    $list = @()
    foreach ($f in @($Findings)) {
        $rule = $Ctx.RuleIndex[$f.RuleId]
        if (-not $rule) { continue }
        if (-not $rule.reversible) { continue }
        if ($f.FixAction) {
            $list += [pscustomobject]@{
                rule   = $f.RuleId
                subject = $f.Subject
                action = $f.FixAction
            }
        }
    }
    return $list
}
