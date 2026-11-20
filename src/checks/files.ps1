# File surface: what got dropped in Temp recently, what executables are sitting on the desktop.

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
        # .lnk left out on purpose: shortcuts are how anyone puts things on a desktop. Reporting them buries the actual exe.
        if ($f.Extension -match '(?i)\.(exe|bat|cmd|vbs|ps1)$') {
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
            Evidence = ("{0:N0} bytes, written {1:yyyy-MM-dd HH:mm} => {2}" -f $f.Size, $f.When, $f.Path)
        }
    }

    foreach ($f in (Get-DesktopExecutables)) {
        $found += [pscustomobject]@{
            RuleId   = 'FS-002'
            Domain   = 'files'
            Severity = 2
            Subject  = $f.Name
            Evidence = ("{0:N0} bytes => {1}" -f $f.Size, $f.Path)
        }
    }

    $found += @(Get-UserDropFindings)

    return $found
}

function Get-UserDropFindings {
    $f = @()

    # ProgramData is world-writable on many builds, so an exe sitting at its root is
    # either an installer leftover or a staged payload.
    if ($env:ProgramData -and (Test-Path -LiteralPath $env:ProgramData)) {
        foreach ($exe in @(Get-ChildItem -LiteralPath $env:ProgramData -Filter '*.exe' -File -ErrorAction SilentlyContinue | Select-Object -First 10)) {
            $f += [pscustomobject]@{
                RuleId   = 'FS-003'
                Domain   = 'files'
                Severity = 3
                Subject  = $exe.Name
                Evidence = $exe.FullName
            }
        }
    }

    # A dll at the top of a profile is unusual; anything loading it resolves by relative path.
    if ($env:USERPROFILE -and (Test-Path -LiteralPath $env:USERPROFILE)) {
        foreach ($dll in @(Get-ChildItem -LiteralPath $env:USERPROFILE -Filter '*.dll' -File -ErrorAction SilentlyContinue | Select-Object -First 10)) {
            $f += [pscustomobject]@{
                RuleId   = 'FS-004'
                Domain   = 'files'
                Severity = 3
                Subject  = $dll.Name
                Evidence = $dll.FullName
            }
        }
    }
    return $f
}
