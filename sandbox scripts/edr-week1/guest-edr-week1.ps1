param (
    [switch]$Install,
    [switch]$Export
)

$ErrorActionPreference = 'Continue'
$EdrScriptRoot = 'C:\Sample\edr-week1'
$ToolsRoot     = 'C:\EdrTools'
$OutDir        = 'C:\Telemetry\edr-week1'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$script:Errors = New-Object System.Collections.ArrayList
function Add-Err { param([string]$m) [void]$script:Errors.Add(("{0} {1}" -f (Get-Date).ToUniversalTime().ToString('o'), $m)) }

function Find-Tool {
    param([string[]]$Names)
    foreach ($n in $Names) { $p = Join-Path $ToolsRoot $n; if (Test-Path -LiteralPath $p) { return $p } }
    return $null
}

function Invoke-Install {
    $result = [ordered]@{ utc = (Get-Date).ToUniversalTime().ToString('o'); sysmonBinary = $false; sysmonRunning = $false; appLockerAudit = $false }
    $sysmon = Find-Tool @('Sysmon64.exe', 'Sysmon.exe')
    $result.sysmonBinary = [bool]$sysmon
    if ($sysmon) {
        try {
            $cfg = Join-Path $EdrScriptRoot 'sysmonconfig-week1.xml'
            $out = & $sysmon -accepteula -i $cfg 2>&1 | Out-String
            $result.sysmonInstallOutput = $out.Trim().Substring(0, [Math]::Min(500, $out.Trim().Length))
            Start-Sleep -Seconds 2
            $svc = Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' } | Select-Object -First 1
            $result.sysmonRunning = [bool]$svc
            if (-not $svc) { Add-Err 'Sysmon installed but the service is not running.' }
        } catch { Add-Err "Sysmon install failed: $($_.Exception.Message)" }
    } else {
        Add-Err 'Sysmon64.exe not found in C:\EdrTools (run edr-week1\Install-EdrWeek1Tools.ps1 on the host first).'
    }

    try {
        $policy = Join-Path $EdrScriptRoot 'applocker-audit-week1.xml'
        & sc.exe config AppIDSvc start= demand | Out-Null
        Set-AppLockerPolicy -XmlPolicy $policy -ErrorAction Stop
        Start-Service -Name AppIDSvc -ErrorAction Stop
        $result.appLockerAudit = $true
    } catch { Add-Err "AppLocker audit policy was not applied: $($_.Exception.Message)" }

    $result.errors = @($script:Errors)
    try { [IO.File]::WriteAllText((Join-Path $OutDir 'install-status.json'), ($result | ConvertTo-Json -Compress -Depth 4), (New-Object Text.UTF8Encoding($false))) } catch {}
}

function ConvertTo-EventRecord {
    param($Ev)
    $f = [ordered]@{}
    try {
        $xml = [xml]$Ev.ToXml()
        foreach ($d in @($xml.Event.EventData.Data)) { if ($d -and $d.Name) { $f[[string]$d.Name] = [string]$d.'#text' } }
    } catch {}
    return [ordered]@{ id = [int]$Ev.Id; ts = $Ev.TimeCreated.ToUniversalTime().ToString('o'); d = $f }
}

function Invoke-Export {
    $summary = [ordered]@{
        utc = (Get-Date).ToUniversalTime().ToString('o')
        categories = [ordered]@{
            process_create     = [ordered]@{ count = 0; samples = @() }
            network_connect    = [ordered]@{ count = 0; samples = @() }
            remote_thread      = [ordered]@{ count = 0; samples = @() }
            lsass_access       = [ordered]@{ count = 0; samples = @() }
            registry_persist   = [ordered]@{ count = 0; samples = @() }
            file_delete        = [ordered]@{ count = 0; samples = @() }
            applocker_audit    = [ordered]@{ count = 0; samples = @() }
        }
        errors = @()
    }

    $sysmonEvents = @()
    try {
        $sysmonEvents = @(Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop)
    } catch { Add-Err "Could not read the Sysmon channel: $($_.Exception.Message)" }

    foreach ($ev in $sysmonEvents) {
        $rec = ConvertTo-EventRecord -Ev $ev
        switch ([int]$rec.id) {
            1  { $key = 'process_create' }
            3  { $key = 'network_connect' }
            8  { $key = 'remote_thread' }
            10 { $key = 'lsass_access' }
            { $_ -in 12, 13, 14 } { $key = 'registry_persist' }
            26 { $key = 'file_delete' }
            default { $key = $null }
        }
        if (-not $key) { continue }
        $summary.categories.$key.count++
        if (@($summary.categories.$key.samples).Count -lt 10) { $summary.categories.$key.samples += $rec }
    }

    try {
        $alEvents = @(Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/EXE and DLL', 'Microsoft-Windows-AppLocker/MSI and Script' -ErrorAction Stop |
            Where-Object { $_.Id -in 8003, 8004, 8006, 8007 })
        foreach ($ev in $alEvents) {
            $rec = ConvertTo-EventRecord -Ev $ev
            $rec['message'] = [string]$ev.Message
            $summary.categories.applocker_audit.count++
            if (@($summary.categories.applocker_audit.samples).Count -lt 10) { $summary.categories.applocker_audit.samples += $rec }
        }
    } catch { Add-Err "Could not read the AppLocker channels: $($_.Exception.Message)" }
    try { & wevtutil.exe epl 'Microsoft-Windows-Sysmon/Operational' (Join-Path $OutDir 'sysmon.evtx') /ow:true 2>&1 | Out-Null } catch { Add-Err "wevtutil export of Sysmon failed: $($_.Exception.Message)" }
    try { & wevtutil.exe epl 'Microsoft-Windows-AppLocker/EXE and DLL' (Join-Path $OutDir 'applocker-exe-dll.evtx') /ow:true 2>&1 | Out-Null } catch {}
    try { & wevtutil.exe epl 'Microsoft-Windows-AppLocker/MSI and Script' (Join-Path $OutDir 'applocker-msi-script.evtx') /ow:true 2>&1 | Out-Null } catch {}

    $svc = Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue | Select-Object -First 1
    $summary.sysmonServiceState = if ($svc) { [string]$svc.Status } else { 'missing' }
    $summary.errors = @($script:Errors)

    try {
        [IO.File]::WriteAllText((Join-Path $OutDir 'summary.json'), ($summary | ConvertTo-Json -Compress -Depth 6), (New-Object Text.UTF8Encoding($false)))
    } catch { Add-Err "Could not write summary.json: $($_.Exception.Message)" }
    try { [IO.File]::WriteAllText((Join-Path $OutDir 'export-complete.flag'), 'DONE', (New-Object Text.UTF8Encoding($false))) } catch {}
}

if ($Install) { Invoke-Install; exit 0 }
if ($Export)  { Invoke-Export;  exit 0 }
Write-Output 'Specify -Install or -Export.'
exit 1
