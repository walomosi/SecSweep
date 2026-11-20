# Kernel drivers. They load before anything else on the box, which is why a signature
# coming back Invalid here matters more than any single registry setting.

function Resolve-DriverPath {
    param([string]$Raw)

    if (-not $Raw) { return '' }
    $p = $Raw.Trim().Trim('"')
    if ($p -eq '*') { return '' }
    # Drivers register themselves as \SystemRoot\... or \??\C:\..., neither of which the
    # filesystem APIs accept as-is. Strip both by hand; a regex for the double-question
    # prefix is too easy to get wrong.
    if ($p.StartsWith('\SystemRoot\', [System.StringComparison]::OrdinalIgnoreCase)) {
        $p = Join-Path $env:SystemRoot $p.Substring(12)
    }
    if ($p.StartsWith('\??\')) { $p = $p.Substring(4) }
    $p = [System.Environment]::ExpandEnvironmentVariables($p)
    if ($p -notmatch '^[A-Za-z]:\\' -and -not $p.StartsWith('\')) {
        $p = Join-Path (Join-Path $env:SystemRoot 'System32\drivers') $p
    }
    return $p
}

function Get-DriverFindings {
    param($Whitelist)

    $found = @()
    $driversRoot = Join-Path $env:SystemRoot 'System32\drivers'

    foreach ($d in @(Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction SilentlyContinue)) {
        $path = Resolve-DriverPath ([string]$d.PathName)
        if (-not $path) { continue }
        if ($path.StartsWith('\')) {
            # Still a NT-style path nothing can open; treat it as missing rather than guess.
            $found += [pscustomobject]@{
                RuleId   = 'DR-002'
                Domain   = 'drivers'
                Severity = 2
                Subject  = [string]$d.Name
                Evidence = ('PathName unreadable: ' + [string]$d.PathName)
            }
            continue
        }

        if (-not (Test-Path -LiteralPath $path)) {
            $found += [pscustomobject]@{
                RuleId   = 'DR-002'
                Domain   = 'drivers'
                Severity = 2
                Subject  = [string]$d.Name
                Evidence = ('Missing file: ' + $path)
            }
            continue
        }

        if ($path.StartsWith($driversRoot, [System.StringComparison]::OrdinalIgnoreCase)) { continue }

        # Anything under System32, Program Files or Windows is where drivers are expected to
        # live, even when it is not the drivers subdirectory itself.
        $trusted = $false
        foreach ($prefix in @($Whitelist.path_prefixes)) {
            if ($path.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) { $trusted = $true; break }
        }
        if ($trusted) { continue }

        # Loading out of the stock directory is legitimate for some vendor drivers, so the
        # signature decides whether this is a third-party product or something that got dropped.
        $sig = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction SilentlyContinue
        if ($sig -and $sig.Status -eq 'Valid') {
            $found += [pscustomobject]@{
                RuleId   = 'DR-001'
                Domain   = 'drivers'
                Severity = 4
                Subject  = [string]$d.Name
                Evidence = ($path + ' signed by ' + $sig.SignerCertificate.Subject)
            }
        } else {
            $status = 'Unknown'
            if ($sig) { $status = $sig.Status }
            $found += [pscustomobject]@{
                RuleId   = 'DR-003'
                Domain   = 'drivers'
                Severity = 4
                Subject  = [string]$d.Name
                Evidence = ($path + ' signature ' + $status)
            }
        }
    }
    return $found
}

function Get-DriverPolicyFindings {
    $found = @()

    # The blocklist that catches the drivers used by real-world BYOVD attacks.
    $ciKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'
    $ci = Get-ItemProperty -LiteralPath $ciKey -ErrorAction SilentlyContinue
    $block = $null
    if ($ci -and $ci.PSObject.Properties['VulnerableDriverBlocklistEnable']) { $block = $ci.VulnerableDriverBlocklistEnable }
    if ($null -eq $block -or [int]$block -ne 1) {
        $found += [pscustomobject]@{
            RuleId   = 'DR-004'
            Domain   = 'drivers'
            Severity = 2
            Subject  = 'VulnerableDriverBlocklist'
            Evidence = $(if ($null -eq $block) { 'not configured' } else { 'set to ' + $block })
        }
    }

    $hvciKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
    $hvci = Get-ItemProperty -LiteralPath $hvciKey -ErrorAction SilentlyContinue
    $hv = $null
    if ($hvci -and $hvci.PSObject.Properties['Enabled']) { $hv = $hvci.Enabled }
    if ($null -eq $hv -or [int]$hv -ne 1) {
        $found += [pscustomobject]@{
            RuleId   = 'DR-007'
            Domain   = 'drivers'
            Severity = 2
            Subject  = 'HVCI'
            Evidence = $(if ($null -eq $hv) { 'not configured' } else { 'set to ' + $hv })
        }
    }

    # Test signing and kernel debug both mean any signed-at-all driver will load.
    $bcd = Join-Path $env:SystemRoot 'System32\bcdedit.exe'
    if (-not (Test-Path -LiteralPath $bcd)) { return $found }
    $out = & $bcd /enum '{current}' 2>$null
    $joined = ($out -join "`n")
    if ($joined -match '(?im)^\s*testsigning\s+Yes') {
        $found += [pscustomobject]@{
            RuleId   = 'DR-005'
            Domain   = 'drivers'
            Severity = 4
            Subject  = 'bcdedit testsigning'
            Evidence = 'Driver signature enforcement relaxed'
        }
    }
    if ($joined -match '(?im)^\s*debug\s+Yes') {
        $found += [pscustomobject]@{
            RuleId   = 'DR-006'
            Domain   = 'drivers'
            Severity = 3
            Subject  = 'bcdedit debug'
            Evidence = 'Kernel debugger enabled'
        }
    }
    return $found
}

function Invoke-CheckDrivers {
    param($Ctx)

    $findings = @()
    $findings += @(Get-DriverFindings $Ctx.Whitelist)
    $findings += @(Get-DriverPolicyFindings)
    return $findings
}
