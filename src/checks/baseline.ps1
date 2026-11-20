# Baseline diff. Stores key/value pairs for a handful of locations, never file contents — the baseline should not become a privacy leak of its own.

function Get-SweepSnapshot {
    $snap = [ordered]@{}

    foreach ($u in (Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue)) {
        # Enabled is $null on some built-in accounts; .ToString() throws on that.
        $snap['account:' + $u.Name] = [string]$u.Enabled
    }

    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    )
    foreach ($k in $runKeys) {
        if (-not (Test-Path -LiteralPath $k)) { continue }
        $props = Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -in @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) { continue }
            $snap['run:' + $p.Name] = [string]$p.Value
        }
    }

    foreach ($s in (Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
        $snap['service:' + $s.Name] = [string]$s.PathName
    }

    foreach ($c in (Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)) {
        $snap['listen:' + $c.LocalAddress + ':' + $c.LocalPort] = '1'
    }

    return $snap
}

function Save-SweepBaseline {
    param([string]$RootDir)

    $snap = Get-SweepSnapshot
    $doc = [pscustomobject]@{
        created = (Get-Date).ToString('s')
        items   = $snap
    }
    $path = Join-Path (Join-Path $RootDir 'rules') 'baseline.json'
    $text = $doc | ConvertTo-Json -Depth 4
    [System.IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding($false)))
    return $path
}

function Invoke-CheckBaseline {
    param($Ctx)

    $found = @()
    $path = Join-Path (Join-Path $Ctx.RootDir 'rules') 'baseline.json'
    if (-not (Test-Path -LiteralPath $path)) {
        # No baseline, nothing to compare against. Guessing here would be worse than silence.
        return $found
    }

    $raw = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)
    $doc = $raw | ConvertFrom-Json
    $old = @{}
    foreach ($p in $doc.items.PSObject.Properties) { $old[$p.Name] = [string]$p.Value }

    # The +/-/~ prefixes keep Subject language-neutral on both report languages.
    $new = Get-SweepSnapshot
    foreach ($key in $new.Keys) {
        if (-not $old.ContainsKey($key)) {
            $found += [pscustomobject]@{
                RuleId   = 'BL-001'
                Domain   = 'baseline'
                Severity = 3
                Subject  = ('+ ' + $key)
                Evidence = [string]$new[$key]
            }
            continue
        }
        if ($old[$key] -ne [string]$new[$key]) {
            $found += [pscustomobject]@{
                RuleId   = 'BL-001'
                Domain   = 'baseline'
                Severity = 3
                Subject  = ('~ ' + $key)
                Evidence = ('old: ' + $old[$key] + ' -> new: ' + $new[$key])
            }
        }
    }
    foreach ($key in $old.Keys) {
        if (-not $new.Contains($key)) {
            $found += [pscustomobject]@{
                RuleId   = 'BL-001'
                Domain   = 'baseline'
                Severity = 3
                Subject  = ('- ' + $key)
                Evidence = ('baseline: ' + $old[$key])
            }
        }
    }

    return $found
}
