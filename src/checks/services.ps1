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
        if ($exe -and -not (Test-Path -LiteralPath $exe)) {
            $found += [pscustomobject]@{
                RuleId   = 'SV-001'
                Domain   = 'services'
                Severity = 2
                Subject  = [string]$s.Name
                Evidence = ("$($s.State)/$($s.StartMode) => " + $exe)
            }
            continue
        }

        if ((Test-PathUserWritable -ExePath $exe -Whitelist $wl)) {
            $found += [pscustomobject]@{
                RuleId   = 'SV-002'
                Domain   = 'services'
                Severity = 5
                Subject  = [string]$s.Name
                Evidence = ("$($s.State)/$($s.StartMode) => " + $exe)
            }
        }
    }

    return $found
}
