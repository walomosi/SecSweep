# Language packs live under lang/. Adding one is dropping a json file there, no code change.

function Resolve-UiLanguage {
    param(
        [string]$Requested,
        [string]$LangDir
    )

    if (-not (Test-Path -LiteralPath $LangDir)) {
        throw "Language directory not found: $LangDir"
    }
    $available = @(Get-ChildItem -LiteralPath $LangDir -Filter '*.json' -File |
        ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_.Name) })
    if ($available.Count -eq 0) {
        throw "No language pack json in: $LangDir"
    }

    if (-not $Requested -or $Requested -eq 'auto') {
        # System culture only picks the default; an explicit request is never silently overridden.
        $culture = ''
        try { $culture = (Get-UICulture).Name } catch { $culture = '' }
        if ($culture -match '^zh') { $pick = 'zh-CN' } else { $pick = 'en-US' }
        if ($available -contains $pick) { return $pick }
        return $available[0]
    }

    if ($available -notcontains $Requested) {
        throw "Unknown language pack: $Requested (available: $($available -join ', '))"
    }
    return $Requested
}

function Import-UiText {
    param(
        [string]$Code,
        [string]$LangDir
    )

    $path = Join-Path $LangDir ($Code + '.json')
    # Read through .NET: PS5.1 decodes BOM-less UTF-8 as ANSI and eats the CJK.
    $raw = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)
    return ($raw | ConvertFrom-Json)
}
