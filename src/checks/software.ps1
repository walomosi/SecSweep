# 软件面：装了但说不清 publisher 的程序。

function Get-InstalledPrograms {
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $rows = @()
    foreach ($root in $roots) {
        foreach ($entry in (Get-ItemProperty -Path $root -ErrorAction SilentlyContinue)) {
            if (-not $entry.DisplayName) { continue }
            $rows += [pscustomobject]@{
                Name      = [string]$entry.DisplayName
                Publisher = [string]$entry.Publisher
                Version   = [string]$entry.DisplayVersion
            }
        }
    }
    return $rows
}

function Invoke-CheckSoftware {
    param($Ctx)

    $found = @()
    foreach ($p in (Get-InstalledPrograms)) {
        if ($p.Publisher) { continue }
        $found += [pscustomobject]@{
            RuleId   = 'SW-001'
            Domain   = 'software'
            Severity = 2
            Subject  = $p.Name
            Evidence = ("Publisher 为空，版本 " + $p.Version)
        }
    }
    return $found
}
