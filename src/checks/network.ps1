# 网络暴露面：绑在哪、开了什么协议、防火墙是不是形同虚设。

function Get-ListeningRows {
    $rows = @()
    foreach ($c in (Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)) {
        $rows += [pscustomobject]@{
            Address = [string]$c.LocalAddress
            Port    = [int]$c.LocalPort
            Owner   = [int]$c.OwningProcess
        }
    }
    return $rows
}

function Get-ProcessNameByPid {
    param([int]$ProcessId)

    if ($ProcessId -le 0) { return '' }
    $p = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if (-not $p) { return '' }
    return [string]$p.ProcessName
}

function Get-ListenerFindings {
    param($Whitelist)

    $found = @()
    $seenPort = @{}
    foreach ($l in (Get-ListeningRows)) {
        $exposed = ($l.Address -eq '0.0.0.0' -or $l.Address -eq '::' -or $l.Address -eq '[::]')
        if (-not $exposed) { continue }
        # 双栈会把同一个端口报两遍，按端口去重
        if ($seenPort.ContainsKey($l.Port)) { continue }
        $seenPort[$l.Port] = $true
        $owner = Get-ProcessNameByPid $l.Owner

        if ($l.Port -eq 3389) {
            $found += [pscustomobject]@{
                RuleId   = 'NW-001'
                Domain   = 'network'
                Severity = 4
                Subject  = 'RDP'
                Evidence = ("$($l.Address):$($l.Port) ⇒ $owner")
                FixAction = 'Set-ItemProperty fDenyTSConnections=1（关闭远程桌面）'
            }
            continue
        }

        if (@($Whitelist.known_listen_ports) -notcontains $l.Port) {
            $found += [pscustomobject]@{
                RuleId   = 'NW-004'
                Domain   = 'network'
                Severity = 2
                Subject  = ("port " + $l.Port)
                Evidence = ("$($l.Address):$($l.Port) ⇒ $owner")
            }
        }
    }
    return $found
}

function Invoke-CheckNetwork {
    param($Ctx)

    $found = @()
    $wl = $Ctx.Whitelist
    $found += @(Get-ListenerFindings $wl)

    $smb = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    if ($smb -and $smb.EnableSMB1Protocol) {
        $found += [pscustomobject]@{
            RuleId   = 'NW-002'
            Domain   = 'network'
            Severity = 4
            Subject  = 'SMBv1'
            Evidence = 'EnableSMB1Protocol=True'
            FixAction = 'Set-SmbServerConfiguration -EnableSMB1Protocol $false'
        }
    }

    $nfsRunning = @()
    foreach ($svcName in @('NfsService', 'NfsClnt')) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') { $nfsRunning += $svcName }
    }
    if ($nfsRunning.Count -gt 0) {
        $found += [pscustomobject]@{
            RuleId   = 'NW-003'
            Domain   = 'network'
            Severity = 3
            Subject  = ($nfsRunning -join ', ')
            Evidence = 'Running（2049/111 在监听就是它）'
            FixAction = 'Stop-Service NfsService,NfsClnt -Force; Set-Service NfsService,NfsClnt -StartupType Disabled'
        }
    }

    foreach ($fw in (Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
        if (-not $fw.Enabled) {
            $found += [pscustomobject]@{
                RuleId   = 'NW-005'
                Domain   = 'network'
                Severity = 4
                Subject  = [string]$fw.Name
                Evidence = 'Enabled=False'
                FixAction = "Set-NetFirewallProfile -Name $($fw.Name) -Enabled True"
            }
        }
    }

    return $found
}
