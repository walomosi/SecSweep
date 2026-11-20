# Event log surface. Reading Security needs admin; when it cannot be read, the check stays silent instead of pretending all is well.

function Test-InternalAddress {
    param([string]$Address)

    if (-not $Address) { return $true }
    if ($Address -eq '-' -or $Address -eq '127.0.0.1' -or $Address -eq '::1') { return $true }
    if ($Address -match '^10\.') { return $true }
    if ($Address -match '^192\.168\.') { return $true }
    if ($Address -match '^172\.(1[6-9]|2[0-9]|3[01])\.') { return $true }
    return $false
}

function Get-RemoteLogonEvents {
    param([int]$Hours = 24, [int]$MaxEvents = 200)

    $rows = @()
    try {
        $evts = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4624
            StartTime = (Get-Date).AddHours(-$Hours)
        } -MaxEvents $MaxEvents -ErrorAction Stop
    }
    catch {
        # No admin or the log service is off. Return nothing and let the caller decide.
        return $rows
    }

    foreach ($e in $evts) {
        try {
            $xml = [xml]$e.ToXml()
            $ip = ''
            $logonType = ''
            foreach ($d in $xml.Event.EventData.Data) {
                $attr = $d.GetAttribute('Name')
                if ($attr -eq 'IpAddress') { $ip = $d.InnerText }
                if ($attr -eq 'LogonType') { $logonType = $d.InnerText }
            }
            if ($logonType -ne '3') { continue }
            if (Test-InternalAddress $ip) { continue }
            $rows += [pscustomobject]@{ Address = $ip; When = $e.TimeCreated }
        }
        catch {
            # One malformed record should not kill the loop.
            continue
        }
    }
    return $rows
}

function Invoke-CheckEvents {
    param($Ctx)

    $found = @()

    $cleared = 0
    try {
        $cleared = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 1102 } -MaxEvents 5 -ErrorAction Stop).Count
    }
    catch {
        # -1 means "could not read". Reporting that as intrusion would be wrong.
        $cleared = -1
    }
    if ($cleared -gt 0) {
        $found += [pscustomobject]@{
            RuleId   = 'EV-001'
            Domain   = 'events'
            Severity = 5
            Subject  = 'Security log cleared'
            Evidence = ("event 1102 x $cleared")
        }
    }

    foreach ($row in (Get-RemoteLogonEvents 24 200)) {
        $found += [pscustomobject]@{
            RuleId   = 'EV-002'
            Domain   = 'events'
            Severity = 3
            Subject  = [string]$row.Address
            Evidence = ("4624 type 3 at " + $row.When.ToString('yyyy-MM-dd HH:mm'))
        }
    }

    $found += @(Get-EventTraceFindings)

    return $found
}

function Get-EventTraceFindings {
    $f = @()

    # A single 4625 is a typo. Twenty in a day is someone working through a list.
    try {
        $failed = @(Get-WinEvent -FilterHashtable @{
            LogName = 'Security'; Id = 4625; StartTime = (Get-Date).AddDays(-1)
        } -ErrorAction Stop).Count
        if ($failed -gt 20) {
            $f += [pscustomobject]@{
                RuleId   = 'EV-003'
                Domain   = 'events'
                Severity = 3
                Subject  = 'Failed logons'
                Evidence = ($failed.ToString() + ' x 4625 in the last 24h')
            }
        }
    }
    catch {
        # No read access to Security means no numbers, not zero failures.
    }

    # Task and account creation in the recent past are worth naming even without context.
    try {
        foreach ($e in @(Get-WinEvent -FilterHashtable @{
            LogName = 'Security'; Id = 4698; StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 5 -ErrorAction Stop)) {
            $f += [pscustomobject]@{
                RuleId   = 'EV-004'
                Domain   = 'events'
                Severity = 3
                Subject  = 'Scheduled task created'
                Evidence = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm')
            }
        }
    }
    catch { }

    try {
        foreach ($e in @(Get-WinEvent -FilterHashtable @{
            LogName = 'Security'; Id = 4720; StartTime = (Get-Date).AddDays(-30)
        } -MaxEvents 5 -ErrorAction Stop)) {
            $f += [pscustomobject]@{
                RuleId   = 'EV-005'
                Domain   = 'events'
                Severity = 4
                Subject  = 'Local account created'
                Evidence = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm')
            }
        }
    }
    catch { }

    $props = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog' -ErrorAction SilentlyContinue
    $start = $null
    if ($props -and $props.PSObject.Properties['Start']) { $start = [int]$props.Start }
    if ($null -ne $start -and $start -ne 2) {
        $f += [pscustomobject]@{
            RuleId   = 'EV-006'
            Domain   = 'events'
            Severity = 4
            Subject  = 'EventLog service'
            Evidence = ('Start=' + $start + ' (not automatic)')
        }
    }
    return $f
}
