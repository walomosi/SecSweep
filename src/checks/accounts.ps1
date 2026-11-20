# Account surface: unknown local accounts, Guest, Administrators membership, UAC. Read-only.

function Get-PasswordPolicy {
    # secedit exports an INI whose section and key names stay English regardless of the
    # OS language, which is why this beats scraping net accounts output.
    $sec = Join-Path $env:SystemRoot 'System32\secedit.exe'
    if (-not (Test-Path -LiteralPath $sec)) { return $null }

    $tmp = Join-Path $env:TEMP ('secsweep-policy-' + [guid]::NewGuid().ToString('N') + '.inf')
    try {
        & $sec /export /areas SECURITYPOLICY /cfg $tmp /quiet 2>$null | Out-Null
        if (-not (Test-Path -LiteralPath $tmp)) { return $null }

        $vals = @{}
        $inSection = $false
        foreach ($line in [IO.File]::ReadAllLines($tmp)) {
            $t = $line.Trim()
            if ($t -match '^\[System Access\]$') { $inSection = $true; continue }
            if ($t -match '^\[') { $inSection = $false; continue }
            if (-not $inSection) { continue }
            if ($t -match '^([^=]+?)\s*=\s*(.+)$') { $vals[$matches[1].Trim()] = $matches[2].Trim() }
        }
        return $vals
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
}

function Get-PolicyNumber {
    param($Policy, [string]$Name)

    if (-not $Policy -or -not $Policy.ContainsKey($Name)) { return $null }
    return [int]$Policy[$Name]
}

function Get-PolicyFindings {
    $f = @()
    $pol = Get-PasswordPolicy
    if (-not $pol) { return $f }

    $minLen = Get-PolicyNumber $pol 'MinimumPasswordLength'
    if ($null -ne $minLen -and $minLen -lt 8) {
        $f += [pscustomobject]@{
            RuleId='AC-006'; Domain='accounts'; Severity=2
            Subject='Minimum password length'
            Evidence=('MinimumPasswordLength=' + $minLen)
        }
    }

    $badCount = Get-PolicyNumber $pol 'LockoutBadCount'
    if ($null -ne $badCount -and $badCount -eq 0) {
        $f += [pscustomobject]@{
            RuleId='AC-007'; Domain='accounts'; Severity=3
            Subject='Account lockout threshold'
            Evidence='LockoutBadCount=0 (accounts never lock)'
        }
    }

    # Zero means "until an admin unlocks", which is stricter than 15, not weaker.
    $lockDur = Get-PolicyNumber $pol 'LockoutDuration'
    if ($null -ne $lockDur -and $lockDur -ne 0 -and $lockDur -lt 15) {
        $f += [pscustomobject]@{
            RuleId='AC-008'; Domain='accounts'; Severity=2
            Subject='Lockout duration'
            Evidence=('LockoutDuration=' + $lockDur + ' min')
        }
    }

    $hist = Get-PolicyNumber $pol 'PasswordHistorySize'
    if ($null -ne $hist -and $hist -lt 5) {
        $f += [pscustomobject]@{
            RuleId='AC-009'; Domain='accounts'; Severity=2
            Subject='Password history'
            Evidence=('PasswordHistorySize=' + $hist)
        }
    }

    $maxAge = Get-PolicyNumber $pol 'MaxPasswordAge'
    if ($null -ne $maxAge -and $maxAge -eq 0) {
        $f += [pscustomobject]@{
            RuleId='AC-010'; Domain='accounts'; Severity=2
            Subject='Password never expires'
            Evidence='MaxPasswordAge=0'
        }
    }

    $complex = Get-PolicyNumber $pol 'PasswordComplexity'
    if ($null -ne $complex -and $complex -eq 0) {
        $f += [pscustomobject]@{
            RuleId='AC-011'; Domain='accounts'; Severity=3
            Subject='Password complexity'
            Evidence='PasswordComplexity=0'
        }
    }

    $window = Get-PolicyNumber $pol 'ResetLockoutCount'
    if ($null -ne $window -and $badCount -and $window -lt 15) {
        $f += [pscustomobject]@{
            RuleId='AC-012'; Domain='accounts'; Severity=2
            Subject='Lockout counter reset window'
            Evidence=('ResetLockoutCount=' + $window + ' min')
        }
    }

    $blank = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $props = Get-ItemProperty -LiteralPath $blank -ErrorAction SilentlyContinue
    $v = $null
    if ($props -and $props.PSObject.Properties['LimitBlankPasswordUse']) { $v = [int]$props.LimitBlankPasswordUse }
    if ($v -ne 1) {
        $f += [pscustomobject]@{
            RuleId='AC-013'; Domain='accounts'; Severity=3
            Subject='Blank password use'
            Evidence=$(if ($null -eq $v) { 'not configured' } else { 'LimitBlankPasswordUse=' + $v })
        }
    }

    return $f
}

function Invoke-CheckAccounts {
    param($Ctx)

    $found = @()
    $wl = $Ctx.Whitelist

    $locals = @(Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue)
    foreach ($u in $locals) {
        if (@($wl.accounts) -notcontains $u.Name) {
            $found += [pscustomobject]@{
                RuleId   = 'AC-001'
                Domain   = 'accounts'
                Severity = 4
                Subject  = [string]$u.Name
                Evidence = ('SID=' + $u.SID + ' disabled=' + $u.Disabled)
            }
        }
    }

    $guest = $locals | Where-Object { $_.Name -eq 'Guest' } | Select-Object -First 1
    if ($guest -and -not $guest.Disabled) {
        $found += [pscustomobject]@{
            RuleId    = 'AC-002'
            Domain    = 'accounts'
            Severity  = 3
            Subject   = 'Guest'
            Evidence  = 'enabled=True'
            FixAction = 'net user Guest /active:no'
        }
    }

    $adminNames = @()
    $members = @(Get-CimInstance Win32_GroupUser -ErrorAction SilentlyContinue)
    foreach ($m in $members) {
        if ($m.GroupComponent -notmatch 'Administrators') { continue }
        if ($m.PartComponent -match 'Name\s*=\s*"([^"]+)"') {
            $adminNames += $matches[1]
        }
    }
    $strangers = @()
    foreach ($name in $adminNames) {
        if (@($wl.accounts) -notcontains $name) { $strangers += $name }
    }
    if ($strangers.Count -gt 0) {
        # One admin is normal. Every extra member needs a name attached to it.
        $found += [pscustomobject]@{
            RuleId   = 'AC-003'
            Domain   = 'accounts'
            Severity = 4
            Subject  = ($strangers -join ', ')
            Evidence = ('Administrators: ' + ($strangers -join ', '))
        }
    }

    $policyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $uac = Get-ItemProperty -LiteralPath $policyPath -ErrorAction SilentlyContinue
    if ($uac -and $uac.PSObject.Properties['EnableLUA']) {
        if ([int]$uac.EnableLUA -eq 0) {
            $found += [pscustomobject]@{
                RuleId    = 'AC-004'
                Domain    = 'accounts'
                Severity  = 2
                Subject   = 'UAC'
                Evidence  = 'EnableLUA=0'
                FixAction = 'Set-ItemProperty EnableLUA=1 (needs a reboot)'
            }
        }
    }

    $found += @(Get-PolicyFindings)

    return $found
}
