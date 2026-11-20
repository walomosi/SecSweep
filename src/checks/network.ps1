# Network exposure: what is bound where, which protocols are on, whether the firewall is doing anything.

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
        # Dual stack reports the same port twice; dedupe by port.
        if ($seenPort.ContainsKey($l.Port)) { continue }
        $seenPort[$l.Port] = $true
        $owner = Get-ProcessNameByPid $l.Owner

        if ($l.Port -eq 3389) {
            $found += [pscustomobject]@{
                RuleId    = 'NW-001'
                Domain    = 'network'
                Severity  = 4
                Subject   = 'RDP'
                Evidence  = ("$($l.Address):$($l.Port) => $owner")
                FixAction = 'Set-ItemProperty fDenyTSConnections=1 (turns Remote Desktop off)'
            }
            continue
        }

        if (@($Whitelist.known_listen_ports) -notcontains $l.Port) {
            $found += [pscustomobject]@{
                RuleId   = 'NW-004'
                Domain   = 'network'
                Severity = 2
                Subject  = ("port " + $l.Port)
                Evidence = ("$($l.Address):$($l.Port) => $owner")
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
            RuleId    = 'NW-002'
            Domain    = 'network'
            Severity  = 4
            Subject   = 'SMBv1'
            Evidence  = 'EnableSMB1Protocol=True'
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
            RuleId    = 'NW-003'
            Domain    = 'network'
            Severity  = 3
            Subject   = ($nfsRunning -join ', ')
            Evidence  = 'Running (listening on 2049/111)'
            FixAction = 'Stop-Service NfsService,NfsClnt -Force; Set-Service NfsService,NfsClnt -StartupType Disabled'
        }
    }

    foreach ($fw in (Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
        if (-not $fw.Enabled) {
            $found += [pscustomobject]@{
                RuleId    = 'NW-005'
                Domain    = 'network'
                Severity  = 4
                Subject   = [string]$fw.Name
                Evidence  = 'Enabled=False'
                FixAction = "Set-NetFirewallProfile -Name $($fw.Name) -Enabled True"
            }
        }
    }

    $found += @(Get-ExposedPortFindings)

    return $found
}

function Get-ExposedPortFindings {
    $f = @()
    $ports = @{}
    foreach ($l in @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)) {
        $ports[[int]$l.LocalPort] = $true
    }

    # None of these should be listening on a general-purpose Windows host.
    $watch = @(
        @('NW-006', 22, 4, 'SSH'),
        @('NW-007', 23, 4, 'Telnet'),
        @('NW-008', 21, 3, 'FTP')
    )
    foreach ($w in $watch) {
        if (-not $ports.ContainsKey($w[1])) { continue }
        $f += [pscustomobject]@{
            RuleId   = $w[0]
            Domain   = 'network'
            Severity = $w[2]
            Subject  = ($w[3] + ' on port ' + $w[1])
            Evidence = 'listening'
        }
    }

    if ($ports.ContainsKey(5985) -or $ports.ContainsKey(5986)) {
        $f += [pscustomobject]@{
            RuleId   = 'NW-009'
            Domain   = 'network'
            Severity = 3
            Subject  = 'WinRM'
            Evidence = $(if ($ports.ContainsKey(5986)) { 'HTTPS 5986 listening' } else { 'HTTP 5985 listening' })
        }
    }

    foreach ($port in @(1433, 3306, 5432, 6379, 27017)) {
        if (-not $ports.ContainsKey($port)) { continue }
        $f += [pscustomobject]@{
            RuleId   = 'NW-010'
            Domain   = 'network'
            Severity = 3
            Subject  = ('database port ' + $port)
            Evidence = 'listening'
        }
    }
    return $f
}
