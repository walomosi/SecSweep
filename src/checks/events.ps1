# 日志面。读安全日志要管理员，读不到就说读不到，不装作没问题。

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
        # 权限不足或日志服务没开，返回空，由调用方决定怎么说
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
            # 单条 XML 解析失败不影响其它条，跳过即可
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
        # -1 留给"读不了"，这里不报，避免把权限问题说成入侵
        $cleared = -1
    }
    if ($cleared -gt 0) {
        $found += [pscustomobject]@{
            RuleId   = 'EV-001'
            Domain   = 'events'
            Severity = 5
            Subject  = '安全日志被清空'
            Evidence = ("1102 事件 $cleared 条")
        }
    }

    foreach ($row in (Get-RemoteLogonEvents 24 200)) {
        $found += [pscustomobject]@{
            RuleId   = 'EV-002'
            Domain   = 'events'
            Severity = 3
            Subject  = [string]$row.Address
            Evidence = ("网络登录 4624 Type 3，时间 " + $row.When.ToString('yyyy-MM-dd HH:mm'))
        }
    }

    return $found
}
