# 账户面：陌生账户、Guest、管理员组、UAC。都是读而不改。

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
            RuleId   = 'AC-002'
            Domain   = 'accounts'
            Severity = 3
            Subject  = 'Guest'
            Evidence = 'enabled=True'
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
        # 只有一个管理员是常态，多出来的每一个都要能说出是谁加的
        $found += [pscustomobject]@{
            RuleId   = 'AC-003'
            Domain   = 'accounts'
            Severity = 4
            Subject  = ($strangers -join ', ')
            Evidence = ('Administrators 组里不在白名单的成员: ' + ($strangers -join ', '))
        }
    }

    $policyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $uac = Get-ItemProperty -LiteralPath $policyPath -ErrorAction SilentlyContinue
    if ($uac -and $uac.PSObject.Properties['EnableLUA']) {
        if ([int]$uac.EnableLUA -eq 0) {
            $found += [pscustomobject]@{
                RuleId   = 'AC-004'
                Domain   = 'accounts'
                Severity = 2
                Subject  = 'UAC'
                Evidence = 'EnableLUA=0'
                FixAction = 'Set-ItemProperty EnableLUA=1（需重启）'
            }
        }
    }

    return $found
}
