# Adversary simulation against a live box. Every technique plants something real and
# removes it again in a finally block, so a failed scan never leaves debris behind.
# Run this from PowerShell 5.1, not pwsh 7: the WMI subscription probe needs
# Set-WmiInstance, which ships only with the older shell.

[CmdletBinding()]
param(
    [string]$OutFile
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$sweep = Join-Path $repoRoot 'src\SecSweep.ps1'
$netExe = Join-Path $env:SystemRoot 'System32\net.exe'

if (-not (Test-Path -LiteralPath $sweep)) { throw "SecSweep not found at $sweep" }

$probes = @(
    @{
        Id = 'T1547.001'
        Name = 'Registry Run key'
        Domain = 'persistence'
        Expect = 'PS-001'
        Plant = {
            Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' `
                -Name 'SecSweepProbe' -Value 'C:\Users\Public\secsweep-probe.exe'
        }
        Clear = {
            Remove-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' `
                -Name 'SecSweepProbe' -ErrorAction SilentlyContinue
        }
    },
    @{
        Id = 'T1053.005'
        Name = 'Scheduled task from a writable path'
        Domain = 'persistence'
        Expect = 'PS-003'
        Plant = {
            $action = New-ScheduledTaskAction -Execute 'C:\Users\Public\secsweep-probe.exe'
            $trigger = New-ScheduledTaskTrigger -AtLogOn
            Register-ScheduledTask -TaskName 'SecSweepProbe' -Action $action -Trigger $trigger -Force | Out-Null
        }
        Clear = {
            Unregister-ScheduledTask -TaskName 'SecSweepProbe' -Confirm:$false -ErrorAction SilentlyContinue
        }
    },
    @{
        Id = 'T1546.003'
        Name = 'WMI event subscription'
        Domain = 'persistence'
        Expect = 'PS-004'
        Plant = {
            $filter = Set-WmiInstance -Namespace 'root\subscription' -Class '__EventFilter' -Arguments @{
                Name = 'SecSweepProbeFilter'
                EventNameSpace = 'root\cimv2'
                QueryLanguage = 'WQL'
                Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_OperatingSystem'"
            }
            $consumer = Set-WmiInstance -Namespace 'root\subscription' -Class 'CommandLineEventConsumer' -Arguments @{
                Name = 'SecSweepProbeConsumer'
                CommandLineTemplate = 'cmd.exe /c exit'
            }
            Set-WmiInstance -Namespace 'root\subscription' -Class '__FilterToConsumerBinding' -Arguments @{
                Filter = $filter
                Consumer = $consumer
            } | Out-Null
        }
        Clear = {
            $binding = Get-WmiObject -Namespace 'root\subscription' -Class '__FilterToConsumerBinding' -ErrorAction SilentlyContinue |
                Where-Object { [string]$_.Filter -match 'SecSweepProbe' }
            if ($binding) { $binding | Remove-WmiObject }
            $consumer = Get-WmiObject -Namespace 'root\subscription' -Class 'CommandLineEventConsumer' -Filter "Name='SecSweepProbeConsumer'" -ErrorAction SilentlyContinue
            if ($consumer) { $consumer | Remove-WmiObject }
            $filter = Get-WmiObject -Namespace 'root\subscription' -Class '__EventFilter' -Filter "Name='SecSweepProbeFilter'" -ErrorAction SilentlyContinue
            if ($filter) { $filter | Remove-WmiObject }
        }
    },
    @{
        Id = 'T1543.003'
        Name = 'Service from a writable path'
        Domain = 'services'
        Expect = 'SV-002'
        Plant = {
            New-Service -Name 'SecSweepProbe' -BinaryPathName 'C:\Users\Public\secsweep-probe.exe' -StartupType Manual | Out-Null
        }
        Clear = {
            & (Join-Path $env:SystemRoot 'System32\sc.exe') delete SecSweepProbe | Out-Null
        }
    },
    @{
        Id = 'T1136.001'
        Name = 'Local account creation'
        Domain = 'accounts'
        Expect = 'AC-001'
        Plant = {
            & $netExe user secsweep_probe 'P@ssw0rd-probe' /add | Out-Null
        }
        Clear = {
            & $netExe user secsweep_probe /delete | Out-Null
        }
    }
)

function Invoke-Probe {
    param($Probe)

    $hit = $false
    $tmpDir = Join-Path $env:TEMP ('secsweep-bench-' + [guid]::NewGuid().ToString('N'))
    try {
        & $Probe.Plant
        # Give the plant a moment to become visible to CIM and the registry APIs.
        Start-Sleep -Milliseconds 700

        & $sweep -Domains $Probe.Domain -Lang 'en-US' -OutDir $tmpDir *> $null

        $reportFile = Get-ChildItem -LiteralPath $tmpDir -Filter 'sweep-*.json' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime | Select-Object -Last 1
        if ($reportFile) {
            $r = [System.IO.File]::ReadAllText($reportFile.FullName, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
            $ids = @($r.findings | ForEach-Object { $_.rule })
            $hit = ($ids -contains $Probe.Expect)
        }
    }
    finally {
        try { & $Probe.Clear } catch { Write-Warning ("cleanup failed for " + $Probe.Id + ": " + $_.Exception.Message) }
        Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    return [pscustomobject]@{
        Ttp    = $Probe.Id
        Name   = $Probe.Name
        Domain = $Probe.Domain
        Expect = $Probe.Expect
        Hit    = $hit
    }
}

$results = @()
foreach ($p in $probes) {
    Write-Host ("[" + $p.Id + "] " + $p.Name)
    $results += Invoke-Probe $p
}

$out = $OutFile
if (-not $out) { $out = Join-Path $repoRoot 'benchmark.md' }

$lines = @(
    '# Detection benchmark',
    '',
    ("Run " + (Get-Date -Format 'yyyy-MM-dd HH:mm') + " on " + $env:COMPUTERNAME),
    '',
    'Each technique is planted, scanned, then removed. A miss means the rule set did not',
    'see it, not that the plant failed.',
    '',
    '| TTP | Technique | Domain | Expected | Detected |',
    '|---|---|---|---|---|'
)
foreach ($r in $results) {
    $lines += ('| {0} | {1} | {2} | {3} | {4} |' -f $r.Ttp, $r.Name, $r.Domain, $r.Expect, $(if ($r.Hit) { 'yes' } else { 'MISS' }))
}
$hits = @($results | Where-Object { $_.Hit }).Count
$lines += ''
$lines += ("Detected " + $hits + " of " + $results.Count + ".")

[System.IO.File]::WriteAllLines($out, $lines, (New-Object System.Text.UTF8Encoding($true)))
Write-Host ("Written: " + $out)
Write-Host ("Detected " + $hits + "/" + $results.Count)
