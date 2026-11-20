# Persistence surface. This is where intrusions actually live; location families checked together.
# Test-PathUserWritable lives in lib/paths.ps1 so services can run without this file.

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

function Get-PrintProcessorFindings {
    $found = @()
    $root = 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments'
    if (-not (Test-Path -LiteralPath $root)) { return $found }
    foreach ($env in (Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
        $ppRoot = Join-Path $env.PSPath 'Print Processors'
        if (-not (Test-Path -LiteralPath $ppRoot)) { continue }
        foreach ($sub in (Get-ChildItem -LiteralPath $ppRoot -ErrorAction SilentlyContinue)) {
            # winprint is the only one that ships with Windows.
            if ($sub.PSChildName -eq 'winprint') { continue }
            $props = Get-ItemProperty -LiteralPath $sub.PSPath -ErrorAction SilentlyContinue
            $driver = ''
            if ($props -and $props.PSObject.Properties['Driver']) { $driver = [string]$props.Driver }
            $found += [pscustomobject]@{
                RuleId   = 'PS-009'
                Domain   = 'persistence'
                Severity = 5
                Subject  = $sub.PSChildName
                Evidence = ('Driver=' + $driver + ' [' + $env.PSChildName + ']')
            }
        }
    }
    return $found
}

function Get-AppCertDllFindings {
    $found = @()
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'
    if (-not (Test-Path -LiteralPath $key)) { return $found }
    $props = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
    if (-not $props) { return $found }
    foreach ($p in $props.PSObject.Properties) {
        if ($p.Name -in @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) { continue }
        $found += [pscustomobject]@{
            RuleId   = 'PS-010'
            Domain   = 'persistence'
            Severity = 5
            Subject  = $p.Name
            Evidence = [string]$p.Value
        }
    }
    return $found
}

function Get-ServiceFailureFindings {
    $found = @()
    $root = 'HKLM:\SYSTEM\CurrentControlSet\Services'
    # One wildcard read beats two hundred per-key reads on a single core.
    $items = @(Get-ItemProperty -Path "$root\*" -Name 'FailureActions' -ErrorAction SilentlyContinue)
    foreach ($props in $items) {
        $raw = $props.FailureActions
        if (-not $raw) { continue }
        # The launch command is stored as UTF-16 inside the binary blob, so decode that way.
        $text = [System.Text.Encoding]::Unicode.GetString([byte[]]$raw)
        if ($text -notmatch '(?i)([A-Za-z]:\\[^\x00]+?\.exe)') { continue }
        $found += [pscustomobject]@{
            RuleId   = 'PS-011'
            Domain   = 'persistence'
            Severity = 4
            Subject  = [string]$props.PSChildName
            Evidence = ('FailureActions => ' + $matches[1])
        }
    }
    return $found
}

function Get-ComHandlerFindings {
    param($Whitelist)

    $found = @()
    foreach ($t in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        $path = [string]$t.TaskPath + [string]$t.TaskName
        $allowed = $false
        foreach ($w in @($Whitelist.task_paths)) {
            if ($path.StartsWith($w, [System.StringComparison]::OrdinalIgnoreCase)) { $allowed = $true; break }
            if ($path -match [regex]::Escape($w)) { $allowed = $true; break }
        }
        if ($allowed) { continue }
        foreach ($a in @($t.Actions)) {
            if ($a.CimClass.CimClassName -ne 'MSFT_TaskComHandlerAction') { continue }
            $classId = ''
            if ($a.PSObject.Properties['ClassId']) { $classId = [string]$a.ClassId }
            $found += [pscustomobject]@{
                RuleId   = 'PS-012'
                Domain   = 'persistence'
                Severity = 5
                Subject  = $path
                Evidence = ('COM ' + $classId)
            }
        }
    }
    return $found
}

function Get-WinlogonNotifyFindings {
    $found = @()
    $root = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify'
    if (-not (Test-Path -LiteralPath $root)) { return $found }
    foreach ($sub in (Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
        $props = Get-ItemProperty -LiteralPath $sub.PSPath -ErrorAction SilentlyContinue
        $dll = ''
        if ($props -and $props.PSObject.Properties['DllName']) { $dll = [string]$props.DllName }
        $found += [pscustomobject]@{
            RuleId   = 'PS-013'
            Domain   = 'persistence'
            Severity = 5
            Subject  = $sub.PSChildName
            Evidence = ('DllName=' + $dll)
        }
    }
    return $found
}

function Get-ActiveSetupFindings {
    param($Whitelist)

    $found = @()
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components'
    )
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($sub in (Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
            $props = Get-ItemProperty -LiteralPath $sub.PSPath -ErrorAction SilentlyContinue
            if (-not $props -or -not $props.PSObject.Properties['StubPath']) { continue }
            $stub = [string]$props.StubPath
            $exe = Get-ExeFromCommandLine $stub
            if (-not $exe) { continue }
            if (-not (Test-PathUserWritable -ExePath $exe -Whitelist $Whitelist)) { continue }
            $found += [pscustomobject]@{
                RuleId   = 'PS-014'
                Domain   = 'persistence'
                Severity = 4
                Subject  = $sub.PSChildName
                Evidence = $stub
            }
        }
    }
    return $found
}

function Get-ShellLoadPointFindings {
    $found = @()
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad'
    if (-not (Test-Path -LiteralPath $key)) { return $found }
    $props = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
    if (-not $props) { return $found }
    foreach ($p in $props.PSObject.Properties) {
        if ($p.Name -in @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) { continue }
        # WebCheck is a stock Windows entry, everything else here is worth a look.
        if ($p.Name -eq 'WebCheck') { continue }
        $found += [pscustomobject]@{
            RuleId   = 'PS-015'
            Domain   = 'persistence'
            Severity = 4
            Subject  = $p.Name
            Evidence = [string]$p.Value
        }
    }
    return $found
}

function Get-BhoFindings {
    param($Whitelist)

    $found = @()
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects'
    )
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($sub in (Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
            $clsid = $sub.PSChildName
            # Resolve the CLSID to its DLL. A BHO living in Program Files is a normal plugin,
            # one pointing at a user profile is not.
            $dll = ''
            $inproc = Join-Path $sub.PSPath 'InprocServer32'
            $item = Get-Item -LiteralPath $inproc -ErrorAction SilentlyContinue
            if ($item) { $dll = [string]$item.GetValue('') }
            # Uninstallers routinely leave the CLSID key behind with nothing in it,
            # and a key pointing at a deleted DLL loads nothing either. Both are noise.
            if (-not $dll) { continue }
            $resolved = [System.Environment]::ExpandEnvironmentVariables($dll)
            if (-not (Test-Path -LiteralPath $resolved)) { continue }
            $trusted = $false
            foreach ($prefix in @($Whitelist.path_prefixes)) {
                if ($resolved.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) { $trusted = $true; break }
            }
            if ($trusted) { continue }
            $found += [pscustomobject]@{
                RuleId   = 'PS-016'
                Domain   = 'persistence'
                Severity = 3
                Subject  = $clsid
                Evidence = $resolved
            }
        }
    }
    return $found
}

function Get-NetshHelperFindings {
    $found = @()
    $key = 'HKLM:\SOFTWARE\Microsoft\NetSh'
    if (-not (Test-Path -LiteralPath $key)) { return $found }
    $props = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
    if (-not $props) { return $found }
    $system32 = Join-Path $env:SystemRoot 'System32'
    foreach ($p in $props.PSObject.Properties) {
        if ($p.Name -in @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) { continue }
        $dll = [string]$p.Value
        if (-not $dll) { continue }
        # Values are written as %SystemRoot%\system32\... (or a bare name netsh resolves
        # there), so expand first; the raw string never starts with the System32 prefix.
        $expanded = [System.Environment]::ExpandEnvironmentVariables($dll)
        if ($expanded -notmatch '\\') { continue }
        if ($expanded.StartsWith($system32, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        $found += [pscustomobject]@{
            RuleId   = 'PS-017'
            Domain   = 'persistence'
            Severity = 4
            Subject  = $p.Name
            Evidence = $expanded
        }
    }
    return $found
}

function Get-LsaPackageFindings {
    $found = @()
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $props = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
    if (-not $props -or -not $props.PSObject.Properties['Notification Packages']) { return $found }
    $known = @('scecli', 'rassfm', 'kdcsvc', 'kdssvc')
    foreach ($pkg in @($props.'Notification Packages')) {
        $name = ([string]$pkg).Trim()
        if (-not $name) { continue }
        if ($known -contains $name.ToLowerInvariant()) { continue }
        $found += [pscustomobject]@{
            RuleId   = 'PS-018'
            Domain   = 'persistence'
            Severity = 5
            Subject  = $name
            Evidence = ('Notification Packages: ' + (@($props.'Notification Packages') -join ', '))
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
    $all += @(Get-PrintProcessorFindings)
    $all += @(Get-AppCertDllFindings)
    $all += @(Get-ServiceFailureFindings)
    $all += @(Get-ComHandlerFindings $wl)
    $all += @(Get-WinlogonNotifyFindings)
    $all += @(Get-ActiveSetupFindings $wl)
    $all += @(Get-ShellLoadPointFindings)
    $all += @(Get-BhoFindings $wl)
    $all += @(Get-NetshHelperFindings)
    $all += @(Get-LsaPackageFindings)
    return $all
}
