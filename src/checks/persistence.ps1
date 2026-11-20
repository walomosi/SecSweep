# Persistence surface. This is where intrusions actually live; seven location families checked together.

function Test-PathUserWritable {
    param([string]$ExePath, $Whitelist)

    if (-not $ExePath) { return $false }
    foreach ($prefix in @($Whitelist.path_prefixes)) {
        if ($ExePath.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
    }
    $lower = $ExePath
    if ($lower -match '(?i)^[A-Z]:\\Users\\') { return $true }
    if ($lower -match '(?i)\\Desktop\\') { return $true }
    if ($lower -match '(?i)\\Temp\\') { return $true }
    if ($lower -match '(?i)^[A-Z]:\\ProgramData\\') { return $true }
    return $false
}

function Get-RunValues {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    $rows = @()
    foreach ($k in $keys) {
        if (-not (Test-Path -LiteralPath $k)) { continue }
        $item = Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue
        foreach ($p in $item.PSObject.Properties) {
            if ($p.Name -in @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) { continue }
            $rows += [pscustomobject]@{ Key = $k; Name = $p.Name; Value = [string]$p.Value }
        }
    }
    return $rows
}

function Get-ExeFromCommandLine {
    param([string]$CommandLine)

    if (-not $CommandLine) { return '' }
    if ($CommandLine -match '^"([^"]+\.exe)"') { return $matches[1] }
    if ($CommandLine -match '^([^\s]+\.exe)') { return $matches[1] }
    if ($CommandLine -match '(?:^|\s)([A-Za-z]:\\[^"]+?\.exe)') { return $matches[1] }
    return ''
}

function Get-AutorunFindings {
    param($Whitelist)

    $found = @()
    foreach ($row in (Get-RunValues)) {
        $exe = Get-ExeFromCommandLine $row.Value
        if (-not $exe) {
            # Bare filename: no drive, no separator, resolved off PATH at boot. That is how a hijack hides.
            if ($row.Value -notmatch '[:\\/]') {
                $found += [pscustomobject]@{
                    RuleId   = 'PS-002'
                    Domain   = 'persistence'
                    Severity = 4
                    Subject  = $row.Name
                    Evidence = ("$($row.Key) => $($row.Value)")
                }
            }
            continue
        }
        if (-not (Test-Path -LiteralPath $exe)) {
            $found += [pscustomobject]@{
                RuleId   = 'PS-001'
                Domain   = 'persistence'
                Severity = 3
                Subject  = $row.Name
                Evidence = $exe
            }
        }
    }
    return $found
}

function Get-ScheduledTaskFindings {
    param($Whitelist)

    $found = @()
    $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue)
    foreach ($t in $tasks) {
        $path = [string]$t.TaskPath + [string]$t.TaskName
        $allowed = $false
        foreach ($w in @($Whitelist.task_paths)) {
            if ($path.StartsWith($w, [System.StringComparison]::OrdinalIgnoreCase)) { $allowed = $true; break }
            if ($path -match [regex]::Escape($w)) { $allowed = $true; break }
        }
        if ($allowed) { continue }
        foreach ($a in @($t.Actions)) {
            $exe = Get-ExeFromCommandLine ([string]$a.Execute)
            if (-not $exe) { continue }
            if (Test-PathUserWritable -ExePath $exe -Whitelist $Whitelist) {
                $found += [pscustomobject]@{
                    RuleId   = 'PS-003'
                    Domain   = 'persistence'
                    Severity = 5
                    Subject  = $path
                    Evidence = ('RunAs=' + $t.Principal.UserId + ' => ' + $exe)
                }
            }
        }
    }
    return $found
}

function Get-WmiSubscriptionFindings {
    $found = @()
    $filters = @(Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue)
    foreach ($f in $filters) {
        if ($f.Name -eq 'SCM Event Log Filter') { continue }
        $found += [pscustomobject]@{
            RuleId   = 'PS-004'
            Domain   = 'persistence'
            Severity = 5
            Subject  = [string]$f.Name
            Evidence = [string]$f.Query
        }
    }
    $consumers = @(Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue)
    foreach ($c in $consumers) {
        $found += [pscustomobject]@{
            RuleId   = 'PS-004'
            Domain   = 'persistence'
            Severity = 5
            Subject  = [string]$c.Name
            Evidence = [string]$c.CommandLineTemplate
        }
    }
    return $found
}

function Get-WinlogonFindings {
    $found = @()
    $winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $props = Get-ItemProperty -LiteralPath $winlogon -ErrorAction SilentlyContinue
    if (-not $props) { return $found }
    foreach ($name in @('Shell', 'Userinit')) {
        if (-not $props.PSObject.Properties[$name]) { continue }
        $value = [string]$props.$name
        if ($name -eq 'Shell' -and $value -notmatch '(?i)^explorer\.exe') {
            $found += [pscustomobject]@{ RuleId='PS-005'; Domain='persistence'; Severity=5; Subject='Winlogon Shell'; Evidence=$value }
        }
        if ($name -eq 'Userinit' -and $value -notmatch '(?i)^[A-Z]:\\Windows\\system32\\userinit\.exe') {
            $found += [pscustomobject]@{ RuleId='PS-005'; Domain='persistence'; Severity=5; Subject='Winlogon Userinit'; Evidence=$value }
        }
    }
    return $found
}

function Get-IfeoFindings {
    $found = @()
    $root = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    if (-not (Test-Path -LiteralPath $root)) { return $found }
    foreach ($sub in (Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
        $props = Get-ItemProperty -LiteralPath $sub.PSPath -ErrorAction SilentlyContinue
        if ($props -and $props.PSObject.Properties['Debugger']) {
            $found += [pscustomobject]@{
                RuleId   = 'PS-006'
                Domain   = 'persistence'
                Severity = 4
                Subject  = $sub.PSChildName
                Evidence = [string]$props.Debugger
            }
        }
    }
    return $found
}

function Get-AppInitFindings {
    $found = @()
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows'
    )
    foreach ($k in $keys) {
        $props = Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue
        if (-not $props) { continue }
        if (-not $props.PSObject.Properties['AppInit_DLLs']) { continue }
        $dlls = [string]$props.AppInit_DLLs
        if ($dlls -and $dlls.Trim() -ne '') {
            $found += [pscustomobject]@{ RuleId='PS-007'; Domain='persistence'; Severity=4; Subject='AppInit_DLLs'; Evidence=$dlls }
        }
    }
    return $found
}

function Get-StartupFolderFindings {
    $found = @()
    $folders = @(
        (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'),
        (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup')
    )
    foreach ($dir in $folders) {
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        foreach ($f in (Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue)) {
            if ($f.Extension -match '(?i)\.(exe|lnk|bat|cmd|vbs|ps1)') {
                $found += [pscustomobject]@{
                    RuleId   = 'PS-008'
                    Domain   = 'persistence'
                    Severity = 3
                    Subject  = $f.Name
                    Evidence = [string]$f.FullName
                }
            }
        }
    }
    return $found
}

function Invoke-CheckPersistence {
    param($Ctx)

    $wl = $Ctx.Whitelist
    $all = @()
    $all += @(Get-AutorunFindings $wl)
    $all += @(Get-ScheduledTaskFindings $wl)
    $all += @(Get-WmiSubscriptionFindings)
    $all += @(Get-WinlogonFindings)
    $all += @(Get-IfeoFindings)
    $all += @(Get-AppInitFindings)
    $all += @(Get-StartupFolderFindings)
    return $all
}
