# Credential surface: filenames and sizes only. Never opens the file — reading it would break the privacy premise.

function Get-SuspectCredentialFiles {
    $roots = @(
        (Join-Path $env:USERPROFILE 'Desktop'),
        (Join-Path $env:USERPROFILE 'Documents'),
        (Join-Path $env:USERPROFILE 'Downloads')
    )
    $namePattern = '(?i)(password|passwd|pwd|cred|token|secret|apikey|api_key|access_key)'
    $extPattern = '(?i)\.(txt|ini|json|csv|xml|yml|yaml|conf|env|log)$'
    # One level only. Recursing drags node_modules and similar into the scan for no benefit.
    $rows = @()
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($f in (Get-ChildItem -LiteralPath $root -File -ErrorAction SilentlyContinue)) {
            if ($f.Name -notmatch $namePattern) { continue }
            if ($f.Name -notmatch $extPattern) { continue }
            $rows += $f
        }
    }
    return $rows
}

function Invoke-CheckCredentials {
    param($Ctx)

    $found = @()
    foreach ($f in (Get-SuspectCredentialFiles)) {
        $sizeKb = [math]::Round($f.Length / 1KB, 1)
        $found += [pscustomobject]@{
            RuleId   = 'CR-001'
            Domain   = 'credentials'
            Severity = 4
            Subject  = $f.Name
            Evidence = ("{0} KB => {1} (name match only, file not read)" -f $sizeKb, $f.FullName)
        }
    }

    $found += @(Get-AutoLogonFindings)

    return $found
}

function Get-AutoLogonFindings {
    $f = @()
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $props = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
    if (-not $props) { return $f }

    $pw = ''
    if ($props.PSObject.Properties['DefaultPassword']) { $pw = [string]$props.DefaultPassword }
    # The value only exists when someone set autologon with a stored password; it is
    # plaintext by design.
    if (-not $pw) { return $f }

    $user = ''
    if ($props.PSObject.Properties['DefaultUserName']) { $user = [string]$props.DefaultUserName }
    $f += [pscustomobject]@{
        RuleId   = 'CR-002'
        Domain   = 'credentials'
        Severity = 5
        Subject  = ('AutoLogon ' + $user)
        Evidence = 'DefaultPassword stored in plaintext under Winlogon'
    }
    return $f
}
