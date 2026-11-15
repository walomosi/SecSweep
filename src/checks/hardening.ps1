# 加固面：该开的审计、该关的广播。这三项都是默认没配好的。

function Get-ScriptBlockLogState {
    $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    $props = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
    if (-not $props -or -not $props.PSObject.Properties['EnableScriptBlockLogging']) { return 0 }
    return [int]$props.EnableScriptBlockLogging
}

function Test-LogonAuditFailure {
    # auditpol 不在 PATH，只能拼全路径；读不出来时不报，避免把权限问题说成配置问题
    $exe = Join-Path $env:SystemRoot 'System32\auditpol.exe'
    if (-not (Test-Path -LiteralPath $exe)) { return $false }
    $raw = & $exe /get /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" 2>$null
    if (-not $raw) { return $false }
    $joined = ($raw -join "`n")
    return ($joined -match 'Failure|失败')
}

function Test-LlmnrEnabled {
    $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    $props = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
    if (-not $props -or -not $props.PSObject.Properties['EnableMulticast']) { return $true }
    return ([int]$props.EnableMulticast -ne 0)
}

function Invoke-CheckHardening {
    param($Ctx)

    $found = @()

    if ((Get-ScriptBlockLogState) -ne 1) {
        $found += [pscustomobject]@{
            RuleId   = 'HD-001'
            Domain   = 'hardening'
            Severity = 2
            Subject  = 'ScriptBlockLogging'
            Evidence = 'EnableScriptBlockLogging 未开启'
        }
    }

    if (-not (Test-LogonAuditFailure)) {
        $found += [pscustomobject]@{
            RuleId   = 'HD-002'
            Domain   = 'hardening'
            Severity = 2
            Subject  = '登录失败审计'
            Evidence = '4625 不会记录（审计策略没开失败项）'
        }
    }

    if (Test-LlmnrEnabled) {
        $found += [pscustomobject]@{
            RuleId   = 'HD-003'
            Domain   = 'hardening'
            Severity = 2
            Subject  = 'LLMNR'
            Evidence = 'EnableMulticast 未设为 0'
        }
    }

    return $found
}
