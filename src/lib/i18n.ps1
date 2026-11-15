# 语言处理。语言包放在 lang/ 下，加一门语言只需丢一个 json 进去，不动代码。

function Resolve-UiLanguage {
    param(
        [string]$Requested,
        [string]$LangDir
    )

    if (-not (Test-Path -LiteralPath $LangDir)) {
        throw "语言目录不存在：$LangDir"
    }
    $available = @(Get-ChildItem -LiteralPath $LangDir -Filter '*.json' -File |
        ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_.Name) })
    if ($available.Count -eq 0) {
        throw "语言目录里没有 json：$LangDir"
    }

    if (-not $Requested -or $Requested -eq 'auto') {
        # 系统语言只用来挑默认值，挑不到就落到列表第一个，不静默改用户的选择
        $culture = ''
        try { $culture = (Get-UICulture).Name } catch { $culture = '' }
        if ($culture -match '^zh') { $pick = 'zh-CN' } else { $pick = 'en-US' }
        if ($available -contains $pick) { return $pick }
        return $available[0]
    }

    if ($available -notcontains $Requested) {
        throw "没有这个语言包：$Requested（可用：$($available -join ', ')）"
    }
    return $Requested
}

function Import-UiText {
    param(
        [string]$Code,
        [string]$LangDir
    )

    $path = Join-Path $LangDir ($Code + '.json')
    # 用 .NET 直读：PS5.1 会把无 BOM 的 UTF-8 当 ANSI，中文会断
    $raw = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)
    return ($raw | ConvertFrom-Json)
}
