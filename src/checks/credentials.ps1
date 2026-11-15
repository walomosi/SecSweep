# 凭据：只看文件名和大小，不读内容。读内容就违背隐私前提了。

function Get-SuspectCredentialFiles {
    $roots = @(
        (Join-Path $env:USERPROFILE 'Desktop'),
        (Join-Path $env:USERPROFILE 'Documents'),
        (Join-Path $env:USERPROFILE 'Downloads')
    )
    $namePattern = '(?i)(password|passwd|pwd|cred|token|secret|apikey|api_key|access_key)'
    $extPattern = '(?i)\.(txt|ini|json|csv|xml|yml|yaml|conf|env|log)$'
    # 只翻一层，不递归——递归会把 node_modules 之类全扫进来，慢且没意义
    $rows = @()
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($f in (Get-ChildItem -LiteralPath $root -File -ErrorAction SilentlyContinue)) {
            if ($f.Name -notmatch $namePattern) { continue }
            if ($f.Name -notmatch $extPattern) { continue }
            $rows += $f
        }
    }
    return $rows
}

function Invoke-CheckCredentials {
    param($Ctx)

    $found = @()
    foreach ($f in (Get-SuspectCredentialFiles)) {
        $sizeKb = [math]::Round($f.Length / 1KB, 1)
        $found += [pscustomobject]@{
            RuleId   = 'CR-001'
            Domain   = 'credentials'
            Severity = 4
            Subject  = $f.Name
            Evidence = ("{0} KB ⇒ {1}（未读取内容，仅按文件名判定）" -f $sizeKb, $f.FullName)
        }
    }
    return $found
}
