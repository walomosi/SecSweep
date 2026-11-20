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

function Get-RegistryNumber {
    param([string]$Path, [string]$Name)

    $props = Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $props -or -not $props.PSObject.Properties[$Name]) { return $null }
    return [int]$props.$Name
}

function Get-AuditText {
    param([string]$Guid)

    $exe = Join-Path $env:SystemRoot 'System32\auditpol.exe'
    if (-not (Test-Path -LiteralPath $exe)) { return '' }
    $raw = & $exe /get /subcategory:"$Guid" 2>$null
    if (-not $raw) { return '' }
    return ($raw -join "`n")
}

function Get-HardeningBaselineFindings {
    $f = @()
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $rdp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'

    # SMB signing off means anyone on the segment can relay credentials without touching a
    # password. It is the single most common finding on an internal network host.
    $v = Get-RegistryNumber 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature'
    if ($v -ne 1) {
        $f += [pscustomobject]@{
            RuleId   = 'HD-004'
            Domain   = 'hardening'
            Severity = 3
            Subject  = 'SMB server signing'
            Evidence = $(if ($null -eq $v) { 'not configured' } else { 'set to ' + $v })
        }
    }

    $v = Get-RegistryNumber 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature'
    if ($v -ne 1) {
        $f += [pscustomobject]@{
            RuleId   = 'HD-005'
            Domain   = 'hardening'
            Severity = 3
            Subject  = 'SMB client signing'
            Evidence = $(if ($null -eq $v) { 'not configured' } else { 'set to ' + $v })
        }
    }

    $v = Get-RegistryNumber 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'EncryptData'
    if ($v -ne 1) {
        $f += [pscustomobject]@{
            RuleId   = 'HD-006'
            Domain   = 'hardening'
            Severity = 2
            Subject  = 'SMB encryption'
            Evidence = $(if ($null -eq $v) { 'not configured' } else { 'set to ' + $v })
        }
    }

    # Absent means the OS default, which is 3 on this build. Only a stored lower value counts.
    $v = Get-RegistryNumber $lsa 'LmCompatibilityLevel'
    if ($null -ne $v -and $v -lt 3) {
        $f += [pscustomobject]@{
            RuleId   = 'HD-007'
            Domain   = 'hardening'
            Severity = 4
            Subject  = 'LM compatibility'
            Evidence = ('LmCompatibilityLevel=' + $v + ' (NTLMv1 or LM allowed)')
        }
    }

    $v = Get-RegistryNumber $lsa 'RestrictAnonymous'
    if ($v -ne 1) {
        $f += [pscustomobject]@{
            RuleId   = 'HD-008'
            Domain   = 'hardening'
            Severity = 3
            Subject  = 'Anonymous enumeration'
            Evidence = $(if ($null -eq $v) { 'not configured' } else { 'set to ' + $v })
        }
    }

    # 0x20080000 is SEC_INTEGRITY | SEC_ENCRYPT; anything weaker lets NTLM be downgraded.
    $client = Get-RegistryNumber "$lsa\MSV1_0" 'NTLMMinClientSec'
    $server = Get-RegistryNumber "$lsa\MSV1_0" 'NTLMMinServerSec'
    if (($null -ne $client -and $client -lt 537395200) -or ($null -ne $server -and $server -lt 537395200)) {
        $f += [pscustomobject]@{
            RuleId   = 'HD-009'
            Domain   = 'hardening'
            Severity = 2
            Subject  = 'NTLM session security'
            Evidence = ('client=' + $client + ' server=' + $server)
        }
    }

    # Without PPL lsass can be opened by any admin-level process, which is how most
    # credential dumping works.
    $v = Get-RegistryNumber $lsa 'RunAsPPL'
    if ($null -eq $v -or $v -ne 2) {
        $f += [pscustomobject]@{
            RuleId   = 'HD-010'
            Domain   = 'hardening'
            Severity = 3
            Subject  = 'LSASS protection'
            Evidence = $(if ($null -eq $v) { 'not configured' } else { 'set to ' + $v })
        }
    }

    $v = Get-RegistryNumber $rdp 'MinEncryptionLevel'
    if ($null -ne $v -and $v -lt 3) {
        $f += [pscustomobject]@{
            RuleId   = 'HD-011'
            Domain   = 'hardening'
            Severity = 2
            Subject  = 'RDP encryption level'
            Evidence = ('MinEncryptionLevel=' + $v + ' (below High)')
        }
    }

    $clip = Get-RegistryNumber $rdp 'fDisableClip'
    $drive = Get-RegistryNumber $rdp 'fDisableCdm'
    if (($null -ne $clip -and $clip -eq 0) -or ($null -ne $drive -and $drive -eq 0)) {
        $f += [pscustomobject]@{
            RuleId   = 'HD-012'
            Domain   = 'hardening'
            Severity = 3
            Subject  = 'RDP redirection'
            Evidence = ('clipboard=' + $clip + ' drives=' + $drive)
        }
    }

    $v = Get-RegistryNumber 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
    if ($v -ne 255) {
        $f += [pscustomobject]@{
            RuleId   = 'HD-013'
            Domain   = 'hardening'
            Severity = 3
            Subject  = 'AutoRun'
            Evidence = $(if ($null -eq $v) { 'not configured, removable media autoplays' } else { 'set to ' + $v })
        }
    }

    $v = Get-RegistryNumber 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'PromptOnSecureDesktop'
    if ($v -ne 1) {
        $f += [pscustomobject]@{
            RuleId   = 'HD-014'
            Domain   = 'hardening'
            Severity = 2
            Subject  = 'UAC secure desktop'
            Evidence = $(if ($null -eq $v) { 'not configured' } else { 'set to ' + $v })
        }
    }

    $v = Get-RegistryNumber 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting'
    if ($v -ne 1) {
        $f += [pscustomobject]@{
            RuleId   = 'HD-015'
            Domain   = 'hardening'
            Severity = 2
            Subject  = 'PowerShell transcription'
            Evidence = $(if ($null -eq $v) { 'not configured, no transcript of script sessions' } else { 'set to ' + $v })
        }
    }

    # Enabled=1 is an explicit opt-in; absence leaves WSH available, which is not unusual
    # but is how most macro-free script droppers start.
    $v = Get-RegistryNumber 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' 'Enabled'
    if ($v -ne 0) {
        $f += [pscustomobject]@{
            RuleId   = 'HD-016'
            Domain   = 'hardening'
            Severity = 2
            Subject  = 'Windows Script Host'
            Evidence = $(if ($null -eq $v) { 'enabled by default' } else { 'set to ' + $v })
        }
    }

    $v = Get-RegistryNumber 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security' 'Retention'
    if ($v -ne 1) {
        $f += [pscustomobject]@{
            RuleId   = 'HD-017'
            Domain   = 'hardening'
            Severity = 2
            Subject  = 'Security log retention'
            Evidence = $(if ($null -eq $v) { 'not configured' } else { 'set to ' + $v })
        }
    }

    $v = Get-RegistryNumber 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security' 'MaxSize'
    if ($null -ne $v -and $v -lt 20971520) {
        $f += [pscustomobject]@{
            RuleId   = 'HD-018'
            Domain   = 'hardening'
            Severity = 2
            Subject  = 'Security log size'
            Evidence = ('MaxSize=' + $v + ' (under 20 MB)')
        }
    }

    $v = Get-RegistryNumber $lsa 'RestrictAnonymousSAM'
    if ($null -ne $v -and $v -eq 0) {
        $f += [pscustomobject]@{
            RuleId   = 'HD-019'
            Domain   = 'hardening'
            Severity = 3
            Subject  = 'Anonymous SAM enumeration'
            Evidence = 'RestrictAnonymousSAM=0'
        }
    }

    $v = Get-RegistryNumber $lsa 'EveryoneIncludesAnonymous'
    if ($null -ne $v -and $v -eq 1) {
        $f += [pscustomobject]@{
            RuleId   = 'HD-020'
            Domain   = 'hardening'
            Severity = 4
            Subject  = 'Everyone includes anonymous'
            Evidence = 'EveryoneIncludesAnonymous=1'
        }
    }

    $v = Get-RegistryNumber 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
    if ($null -ne $v -and $v -eq 1) {
        $f += [pscustomobject]@{
            RuleId   = 'HD-021'
            Domain   = 'hardening'
            Severity = 5
            Subject  = 'WDigest plaintext logon cache'
            Evidence = 'UseLogonCredential=1'
        }
    }

    $aie = Get-RegistryNumber 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
    $aieUser = Get-RegistryNumber 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
    if (($null -ne $aie -and $aie -eq 1) -or ($null -ne $aieUser -and $aieUser -eq 1)) {
        $f += [pscustomobject]@{
            RuleId   = 'HD-022'
            Domain   = 'hardening'
            Severity = 4
            Subject  = 'AlwaysInstallElevated'
            Evidence = ('machine=' + $aie + ' user=' + $aieUser)
        }
    }

    $v = Get-RegistryNumber 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' 'DisableExceptionChainValidation'
    if ($null -ne $v -and $v -eq 1) {
        $f += [pscustomobject]@{
            RuleId   = 'HD-023'
            Domain   = 'hardening'
            Severity = 3
            Subject  = 'SEHOP'
            Evidence = 'DisableExceptionChainValidation=1'
        }
    }

    $v = Get-RegistryNumber 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'SafeDllSearchMode'
    if ($null -ne $v -and $v -eq 0) {
        $f += [pscustomobject]@{
            RuleId   = 'HD-024'
            Domain   = 'hardening'
            Severity = 3
            Subject  = 'Safe DLL search'
            Evidence = 'SafeDllSearchMode=0'
        }
    }

    $sysPol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

    # An RDP session that never times out keeps an authenticated channel open indefinitely.
    $v = Get-RegistryNumber $rdp 'MaxIdleTime'
    if ($null -eq $v -or $v -eq 0) {
        $f += [pscustomobject]@{
            RuleId   = 'HD-028'
            Domain   = 'hardening'
            Severity = 2
            Subject  = 'RDP idle timeout'
            Evidence = $(if ($null -eq $v) { 'not configured' } else { 'MaxIdleTime=0' })
        }
    }

    $v = Get-RegistryNumber $sysPol 'DisableCAD'
    if ($null -ne $v -and $v -ne 0) {
        $f += [pscustomobject]@{
            RuleId   = 'HD-029'
            Domain   = 'hardening'
            Severity = 2
            Subject  = 'Ctrl+Alt+Del at logon'
            Evidence = 'DisableCAD=' + $v
        }
    }

    $v = Get-RegistryNumber $sysPol 'DontDisplayLastUserName'
    if ($v -ne 1) {
        $f += [pscustomobject]@{
            RuleId   = 'HD-030'
            Domain   = 'hardening'
            Severity = 2
            Subject  = 'Last username on logon screen'
            Evidence = $(if ($null -eq $v) { 'not configured' } else { 'set to ' + $v })
        }
    }

    # Without this the pagefile keeps whatever was in memory at shutdown.
    $v = Get-RegistryNumber 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' 'ClearPageFileAtShutdown'
    if ($v -ne 1) {
        $f += [pscustomobject]@{
            RuleId   = 'HD-031'
            Domain   = 'hardening'
            Severity = 2
            Subject  = 'Pagefile cleared at shutdown'
            Evidence = $(if ($null -eq $v) { 'not configured' } else { 'set to ' + $v })
        }
    }

    # Account logon and process creation are the two subcategories an intrusion review
    # leans on; policy change catches anyone rewriting the audit rules themselves.
    $auditChecks = @(
        @('HD-025', 'Account logon audit', '{0CCE9217-69AE-11D9-BED3-505054503030}'),
        @('HD-026', 'Process creation audit', '{0CCE922B-69AE-11D9-BED3-505054503030}'),
        @('HD-027', 'Audit policy change audit', '{0CCE922F-69AE-11D9-BED3-505054503030}')
    )
    foreach ($check in $auditChecks) {
        $text = Get-AuditText $check[2]
        # If auditpol cannot answer, stay quiet instead of inventing a finding.
        if (-not $text) { continue }
        if ($text -match 'Success|成功') { continue }
        $f += [pscustomobject]@{
            RuleId   = $check[0]
            Domain   = 'hardening'
            Severity = 3
            Subject  = $check[1]
            Evidence = 'success auditing not enabled'
        }
    }

    return $f
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

    $found += @(Get-HardeningBaselineFindings)

    return $found
}
