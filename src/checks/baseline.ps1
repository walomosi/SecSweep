# 基线比对。只记"关键位置的键和值"，不比内容，避免基线文件本身变成隐私泄露源。

function Get-SweepSnapshot {
    $snap = [ordered]@{}

    foreach ($u in (Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue)) {
        # Enabled 在某些内置账户上是空值，直接 ToString() 会炸
        $snap['account:' + $u.Name] = [string]$u.Enabled
    }

    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    )
    foreach ($k in $runKeys) {
        if (-not (Test-Path -LiteralPath $k)) { continue }
        $props = Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -in @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) { continue }
            $snap['run:' + $p.Name] = [string]$p.Value
        }
    }

    foreach ($s in (Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
        $snap['service:' + $s.Name] = [string]$s.PathName
    }

    foreach ($c in (Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)) {
        $snap['listen:' + $c.LocalAddress + ':' + $c.LocalPort] = '1'
    }

    return $snap
}

function Save-SweepBaseline {
    param([string]$RootDir)

    $snap = Get-SweepSnapshot
    $doc = [pscustomobject]@{
        created = (Get-Date).ToString('s')
        items   = $snap
    }
    $path = Join-Path (Join-Path $RootDir 'rules') 'baseline.json'
    $text = $doc | ConvertTo-Json -Depth 4
    [System.IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding($false)))
    return $path
}

function Invoke-CheckBaseline {
    param($Ctx)

    $found = @()
    $path = Join-Path (Join-Path $Ctx.RootDir 'rules') 'baseline.json'
    if (-not (Test-Path -LiteralPath $path)) {
        # 没有基线就没什么可比的，不猜
        return $found
    }

    $raw = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)
    $doc = $raw | ConvertFrom-Json
    $old = @{}
    foreach ($p in $doc.items.PSObject.Properties) { $old[$p.Name] = [string]$p.Value }

    $new = Get-SweepSnapshot
    foreach ($key in $new.Keys) {
        if (-not $old.ContainsKey($key)) {
            $found += [pscustomobject]@{
                RuleId   = 'BL-001'
                Domain   = 'baseline'
                Severity = 3
                Subject  = ('新增 ' + $key)
                Evidence = [string]$new[$key]
            }
            continue
        }
        if ($old[$key] -ne [string]$new[$key]) {
            $found += [pscustomobject]@{
                RuleId   = 'BL-001'
                Domain   = 'baseline'
                Severity = 3
                Subject  = ('变化 ' + $key)
                Evidence = ('旧: ' + $old[$key] + ' → 新: ' + $new[$key])
            }
        }
    }
    foreach ($key in $old.Keys) {
        if (-not $new.Contains($key)) {
            $found += [pscustomobject]@{
                RuleId   = 'BL-001'
                Domain   = 'baseline'
                Severity = 3
                Subject  = ('消失 ' + $key)
                Evidence = ('基线值: ' + $old[$key])
            }
        }
    }

    return $found
}
