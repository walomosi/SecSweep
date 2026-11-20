# Shared path helpers. These used to sit inside persistence.ps1, which worked only as
# long as persistence loaded first; a scan of services on its own threw a missing
# command. Loading them here makes every domain usable by itself.

function Test-PathUserWritable {
    param([string]$ExePath, $Whitelist)

    if (-not $ExePath) { return $false }
    foreach ($prefix in @($Whitelist.path_prefixes)) {
        if ($ExePath.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
    }
    # Prefix matching, not an ACL read. See the README for why.
    if ($ExePath -match '(?i)^[A-Z]:\\Users\\') { return $true }
    if ($ExePath -match '(?i)\\Desktop\\') { return $true }
    if ($ExePath -match '(?i)\\Temp\\') { return $true }
    if ($ExePath -match '(?i)^[A-Z]:\\ProgramData\\') { return $true }
    return $false
}
