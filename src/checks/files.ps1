# 文件落地：最近往临时目录丢了什么、桌面上摆着什么可执行文件。

function Get-RecentTempExe {
    param([int]$Days = 30)

    if (-not (Test-Path -LiteralPath $env:TEMP)) { return @() }
    $cutoff = (Get-Date).AddDays(-$Days)
    $rows = @()
    foreach ($f in (Get-ChildItem -LiteralPath $env:TEMP -Filter '*.exe' -File -ErrorAction SilentlyContinue)) {
        if ($f.LastWriteTime -lt $cutoff) { continue }
        $rows += [pscustomobject]@{
            Name = $f.Name
            Path = $f.FullName
            Size = $f.Length
            When = $f.LastWriteTime
        }
    }
    return $rows
}

function Get-DesktopExecutables {
    $rows = @()
    $desktop = Join-Path $env:USERPROFILE 'Desktop'
    if (-not (Test-Path -LiteralPath $desktop)) { return $rows }
    foreach ($f in (Get-ChildItem -LiteralPath $desktop -File -ErrorAction SilentlyContinue)) {
        if ($f.Extension -match '(?i)\.(exe|bat|cmd|vbs|ps1|lnk)') {
            $rows += [pscustomobject]@{
                Name = $f.Name
                Path = $f.FullName
                Size = $f.Length
            }
        }
    }
    return $rows
}

function Invoke-CheckFiles {
    param($Ctx)

    $found = @()

    foreach ($f in (Get-RecentTempExe 30)) {
        $found += [pscustomobject]@{
            RuleId   = 'FS-001'
            Domain   = 'files'
            Severity = 3
            Subject  = $f.Name
            Evidence = ("{0:N0} 字节，写入于 {1:yyyy-MM-dd HH:mm} ⇒ {2}" -f $f.Size, $f.When, $f.Path)
        }
    }

    foreach ($f in (Get-DesktopExecutables)) {
        $found += [pscustomobject]@{
            RuleId   = 'FS-002'
            Domain   = 'files'
            Severity = 2
            Subject  = $f.Name
            Evidence = ("{0:N0} 字节 ⇒ {1}" -f $f.Size, $f.Path)
        }
    }

    return $found
}
