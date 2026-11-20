# Fix engine. Every reversible finding maps to a read / apply / verify / undo set, and the undo is
# written out as a standalone script so this folder can be deleted and the box still restored.
# Only rules with a safe, actually reversible action live here; the rest stay informational.

function New-RegistryFix {
    param($RuleId, $Subject, $Path, $Name, $NewValue, $Description)

    $props = Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue
    $exists = $false
    $old = $null
    if ($props -and $props.PSObject.Properties[$Name]) { $exists = $true; $old = $props.$Name }

    return [pscustomobject]@{
        RuleId      = $RuleId
        Subject     = $Subject
        Kind        = 'Registry'
        Path        = $Path
        Name        = $Name
        OldExists   = $exists
        OldValue    = $old
        OldType     = 'DWord'
        CreatedKey  = -not (Test-Path -LiteralPath $Path)
        NewValue    = $NewValue
        Description = $Description
        PreState    = $(if ($exists) { "$Name=$old" } else { "$Name absent" })
        Verify      = [scriptblock]::Create("(Get-ItemProperty -LiteralPath '$Path' -ErrorAction SilentlyContinue).$Name -eq $NewValue")
    }
}

function New-CommandFix {
    param($RuleId, $Subject, $PreState, $ApplyCmd, $UndoCmd, $Description, $Verify)

    return [pscustomobject]@{
        RuleId      = $RuleId
        Subject     = $Subject
        Kind        = 'Command'
        PreState    = $PreState
        ApplyCmd    = $ApplyCmd
        UndoCmd     = $UndoCmd
        Description = $Description
        Verify      = $Verify
    }
}

function Get-FixTarget {
    param($Finding)

    $ruleId = [string]$Finding.RuleId
    $subject = [string]$Finding.Subject

    if ($ruleId -eq 'AC-002') {
        return New-CommandFix -RuleId $ruleId -Subject 'Guest' -PreState 'active' `
            -ApplyCmd 'net user Guest /active:no' -UndoCmd 'net user Guest /active:yes' `
            -Description 'Disable the built-in Guest account' `
            -Verify { (Get-CimInstance Win32_UserAccount -Filter "Name='Guest'" -ErrorAction SilentlyContinue).Disabled -eq $true }
    }

    if ($ruleId -eq 'AC-004') {
        return New-RegistryFix -RuleId $ruleId -Subject 'UAC' `
            -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
            -Name 'EnableLUA' -NewValue 1 -Description 'Turn UAC back on (needs a reboot)'
    }

    if ($ruleId -eq 'NW-001') {
        return New-RegistryFix -RuleId $ruleId -Subject 'RDP' `
            -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' `
            -Name 'fDenyTSConnections' -NewValue 1 -Description 'Stop Remote Desktop listening (needs a reboot)'
    }

    if ($ruleId -eq 'NW-002') {
        $on = $false
        $smb = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
        if ($smb) { $on = [bool]$smb.EnableSMB1Protocol }
        return New-CommandFix -RuleId $ruleId -Subject 'SMBv1' -PreState ("EnableSMB1Protocol=" + $on) `
            -ApplyCmd 'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force' `
            -UndoCmd 'Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force' `
            -Description 'Disable the SMBv1 protocol' `
            -Verify { (Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol -eq $false }
    }

    if ($ruleId -eq 'NW-003') {
        $svc = Get-CimInstance Win32_Service -Filter "Name='NfsService'" -ErrorAction SilentlyContinue
        $startMode = 'Automatic'
        if ($svc -and $svc.StartMode) { $startMode = [string]$svc.StartMode }
        return New-CommandFix -RuleId $ruleId -Subject $subject -PreState ("StartMode=" + $startMode) `
            -ApplyCmd 'Stop-Service NfsService,NfsClnt -Force -ErrorAction SilentlyContinue; Set-Service NfsService,NfsClnt -StartupType Disabled' `
            -UndoCmd ("Set-Service NfsService,NfsClnt -StartupType " + $startMode + '; Start-Service NfsService,NfsClnt') `
            -Description 'Stop and disable the NFS services' `
            -Verify { (Get-Service NfsService -ErrorAction SilentlyContinue).Status -eq 'Stopped' }
    }

    if ($ruleId -eq 'NW-005') {
        $profile = $subject
        return New-CommandFix -RuleId $ruleId -Subject $profile -PreState 'Enabled=False' `
            -ApplyCmd ("Set-NetFirewallProfile -Name '" + $profile + "' -Enabled True") `
            -UndoCmd ("Set-NetFirewallProfile -Name '" + $profile + "' -Enabled False") `
            -Description ("Turn the " + $profile + ' firewall profile on') `
            -Verify ([scriptblock]::Create("(Get-NetFirewallProfile -Name '$profile' -ErrorAction SilentlyContinue).Enabled -eq `$true"))
    }

    if ($ruleId -eq 'HD-001') {
        return New-RegistryFix -RuleId $ruleId -Subject 'ScriptBlockLogging' `
            -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
            -Name 'EnableScriptBlockLogging' -NewValue 1 -Description 'Turn on PowerShell script block logging'
    }

    if ($ruleId -eq 'HD-003') {
        return New-RegistryFix -RuleId $ruleId -Subject 'LLMNR' `
            -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' `
            -Name 'EnableMulticast' -NewValue 0 -Description 'Turn LLMNR off (needs a reboot)'
    }

    return $null
}

function New-FixPlan {
    param($Findings)

    $plan = @()
    foreach ($f in @($Findings)) {
        $target = Get-FixTarget -Finding $f
        if ($target) { $plan += $target }
    }
    return $plan
}

function Test-FixResult {
    param($Item)

    try { $ok = & $Item.Verify } catch { return $false }
    return [bool]$ok
}

function Undo-FixList {
    param($Items)

    foreach ($item in @($Items)) {
        try {
            if ($item.Kind -eq 'Registry') {
                if ($item.OldExists) {
                    Set-ItemProperty -LiteralPath $item.Path -Name $item.Name -Value $item.OldValue -Type $item.OldType -ErrorAction Stop
                }
                elseif ($item.CreatedKey) {
                    # The key did not exist before this run, so removing just the value leaves litter behind.
                    Remove-Item -LiteralPath $item.Path -Recurse -Force -ErrorAction SilentlyContinue
                }
                else {
                    Remove-ItemProperty -LiteralPath $item.Path -Name $item.Name -ErrorAction SilentlyContinue
                }
            }
            else {
                Invoke-Expression $item.UndoCmd
            }
            Write-Host ("  rolled back " + $item.RuleId)
        }
        catch {
            # A failed rollback is the one thing you must not swallow silently.
            Write-Host ("  ROLLBACK FAILED {0}: {1}" -f $item.RuleId, $_.Exception.Message)
        }
    }
}

function Invoke-FixApply {
    param($Plan)

    $applied = @()
    foreach ($item in @($Plan)) {
        Write-Host ("  applying [{0}] {1}" -f $item.RuleId, $item.Description)
        try {
            if ($item.Kind -eq 'Registry') {
                # Set-ItemProperty does not create a missing key. Group Policy keys are often absent.
                if (-not (Test-Path -LiteralPath $item.Path)) {
                    New-Item -Path $item.Path -Force | Out-Null
                }
                Set-ItemProperty -LiteralPath $item.Path -Name $item.Name -Value $item.NewValue -Type $item.OldType -ErrorAction Stop
            }
            else {
                Invoke-Expression $item.ApplyCmd
            }
        }
        catch {
            Write-Host ("  FAILED {0}: {1}" -f $item.RuleId, $_.Exception.Message)
            Write-Host '  rolling back everything applied so far'
            Undo-FixList -Items $applied
            throw
        }
        $applied += $item
    }

    foreach ($item in $applied) {
        $ok = Test-FixResult -Item $item
        if ($ok) { Write-Host ("  verified " + $item.RuleId) }
        else { Write-Host ("  applied but NOT verified: " + $item.RuleId) }
    }

    return $applied
}

function New-UndoScript {
    param($Applied, [string]$OutDir, [string]$Stamp)

    $path = Join-Path $OutDir ('undo-' + $Stamp + '.ps1')
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('# Generated by SecSweep at ' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))
    $lines.Add('# Puts this machine back the way it was before the fixes.')
    $lines.Add('# Run: powershell -ExecutionPolicy Bypass -File "' + $path + '"')
    $lines.Add('')

    foreach ($item in @($Applied)) {
        if ($item.Kind -eq 'Registry') {
            if ($item.OldExists) {
                $lines.Add("Set-ItemProperty -LiteralPath '$($item.Path)' -Name '$($item.Name)' -Value $($item.OldValue) -Type $($item.OldType)")
            }
            elseif ($item.CreatedKey) {
                $lines.Add("Remove-Item -LiteralPath '$($item.Path)' -Recurse -Force -ErrorAction SilentlyContinue")
            }
            else {
                $lines.Add("Remove-ItemProperty -LiteralPath '$($item.Path)' -Name '$($item.Name)' -ErrorAction SilentlyContinue")
            }
        }
        else {
            $lines.Add($item.UndoCmd)
        }
    }

    $text = ($lines -join "`r`n") + "`r`n"
    [System.IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding($true)))
    return $path
}
