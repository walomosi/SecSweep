# Process surface: where it runs from, whether it is signed, whether the file is still there.

function Test-SuspiciousProcessPath {
    param([string]$Path)

    if (-not $Path) { return $false }
    if ($Path -match '(?i)\\Temp\\') { return $true }
    if ($Path -match '(?i)\\Desktop\\') { return $true }
    if ($Path -match '(?i)\\Downloads\\') { return $true }
    return $false
}

function Invoke-CheckProcesses {
    param($Ctx)

    $found = @()
    $wl = $Ctx.Whitelist
    $unsignedOk = @($wl.unsigned_ok)
    $seen = @{}

    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
        $path = ''
        try { $path = $p.Path } catch { $path = '' }
        if (-not $path) { continue }
        if ($seen.ContainsKey($path)) { continue }
        $seen[$path] = $true

        if (Test-SuspiciousProcessPath $path) {
            $found += [pscustomobject]@{
                RuleId   = 'PR-002'
                Domain   = 'processes'
                Severity = 3
                Subject  = [string]$p.ProcessName
                Evidence = $path
            }
        }

        # Signature checks are slow; system dirs would add hundreds of them and buy nothing.
        if ($path -match '(?i)^[A-Z]:\\Users\\') {
            if (@($wl.process_names) -contains $p.ProcessName) { continue }
            if ($unsignedOk -contains $p.ProcessName) { continue }
            $sig = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction SilentlyContinue
            if ($sig -and $sig.Status -ne 'Valid') {
                $found += [pscustomobject]@{
                    RuleId   = 'PR-001'
                    Domain   = 'processes'
                    Severity = 3
                    Subject  = [string]$p.ProcessName
                    Evidence = ($sig.Status.ToString() + ' => ' + $path)
                }
            }
        }
    }

    return $found
}
