# Hardening surface: audits that should be on, broadcasts that should be off. All three are off by default on a fresh box.

function Get-ScriptBlockLogState {
    $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    $props = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
    if (-not $props -or -not $props.PSObject.Properties['EnableScriptBlockLogging']) { return 0 }
    return [int]$props.EnableScriptBlockLogging
}

function Test-LogonAuditFailure {
    # auditpol is not on PATH. And if it cannot be read, say nothing rather than guess.
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
            Evidence = 'EnableScriptBlockLogging not set'
        }
    }

    if (-not (Test-LogonAuditFailure)) {
        $found += [pscustomobject]@{
            RuleId   = 'HD-002'
            Domain   = 'hardening'
            Severity = 2
            Subject  = 'Logon failure audit'
            Evidence = '4625 will not be recorded (failure auditing is off)'
        }
    }

    if (Test-LlmnrEnabled) {
        $found += [pscustomobject]@{
            RuleId   = 'HD-003'
            Domain   = 'hardening'
            Severity = 2
            Subject  = 'LLMNR'
            Evidence = 'EnableMulticast not set to 0'
        }
    }

    return $found
}
