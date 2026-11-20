# Service surface: missing binaries, binaries sitting in writable paths, odd svchost groups.

# Group names come from the registry, not a hand-written list — MS adds groups every release and you miss them all.
function Get-LegitSvchostGroups {
    $groups = @{}
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Svchost'
    )
    foreach ($key in $keys) {
        if (-not (Test-Path -LiteralPath $key)) { continue }
        $props = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
        if (-not $props) { continue }
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -in @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) { continue }
            $groups[$p.Name] = $true
        }
    }
    return $groups
}

function Get-ServiceExePath {
    param([string]$PathName)

    if (-not $PathName) { return '' }
    if ($PathName -match '^"([^"]+\.exe)"') { return $matches[1] }
    if ($PathName -match '^(.+?\.exe)') { return $matches[1].Trim() }
    return ($PathName -split ' ')[0]
}

function Get-SvchostGroup {
    param([string]$PathName)

    if (-not $PathName) { return '' }
    if ($PathName -match '(?i)svchost(?:\.exe)?\s+-k\s+([A-Za-z0-9_]+)') { return $matches[1] }
    return ''
}

function Invoke-CheckServices {
    param($Ctx)

    $found = @()
    $wl = $Ctx.Whitelist
    $legitGroups = Get-LegitSvchostGroups
    $services = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)

    foreach ($s in $services) {
        $pathName = [string]$s.PathName
        if (-not $pathName) { continue }

        $group = Get-SvchostGroup $pathName
        if ($group -and -not $legitGroups.ContainsKey($group)) {
            $found += [pscustomobject]@{
                RuleId   = 'SV-003'
                Domain   = 'services'
                Severity = 4
                Subject  = [string]$s.Name
                Evidence = $pathName
            }
        }

        if (@($wl.service_names) -contains $s.Name) { continue }

        $exe = Get-ServiceExePath $pathName
        # Writable path first. A service pointing into a user profile is the louder finding
        # even when the file is not there yet, which is exactly the staged case.
        if ((Test-PathUserWritable -ExePath $exe -Whitelist $wl)) {
            $found += [pscustomobject]@{
                RuleId   = 'SV-002'
                Domain   = 'services'
                Severity = 5
                Subject  = [string]$s.Name
                Evidence = ("$($s.State)/$($s.StartMode) => " + $exe)
            }
            continue
        }

        if ($exe -and -not (Test-Path -LiteralPath $exe)) {
            $found += [pscustomobject]@{
                RuleId   = 'SV-001'
                Domain   = 'services'
                Severity = 2
                Subject  = [string]$s.Name
                Evidence = ("$($s.State)/$($s.StartMode) => " + $exe)
            }
        }
    }

    $found += @(Get-HighRiskServiceFindings)

    return $found
}

function Get-HighRiskServiceFindings {
    # Services that ship with Windows, are off by default, and are still the first thing
    # anyone turns on when they want a remote foothold.
    $f = @()
    $watch = @(
        @('SV-006', 'RemoteRegistry', 3, 'remote registry editing'),
        @('SV-007', 'TlntSvr', 4, 'telnet server'),
        @('SV-008', 'RemoteAccess', 3, 'routing and remote access'),
        @('SV-009', 'WinRM', 3, 'WinRM'),
        @('SV-010', 'SSDPSRV', 2, 'SSDP discovery'),
        @('SV-011', 'Spooler', 3, 'print spooler'),
        @('SV-012', 'SNMP', 3, 'SNMP')
    )
    foreach ($w in $watch) {
        $svc = Get-Service -Name $w[1] -ErrorAction SilentlyContinue
        if (-not $svc) { continue }
        if ([string]$svc.Status -ne 'Running') { continue }
        $f += [pscustomobject]@{
            RuleId   = $w[0]
            Domain   = 'services'
            Severity = $w[2]
            Subject  = $w[1]
            Evidence = ('Running (' + $w[3] + ')')
        }
    }
    return $f
}
