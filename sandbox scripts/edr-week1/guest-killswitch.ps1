param(
    [string]$CacheRoot = 'C:\HashCache',
    [string]$LogDir    = 'C:\Telemetry\killswitch',
    [int]$PollSec      = 2
)

$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$LogFile       = Join-Path $LogDir 'killswitch.log'
$HeartbeatFile = Join-Path $LogDir 'heartbeat.txt'
$SelfPid       = $PID

function Write-KsLog {
    param([string]$Msg)
    Add-Content -LiteralPath $LogFile -Encoding UTF8 -Value ("{0} {1}" -f (Get-Date).ToUniversalTime().ToString('o'), $Msg)
}

function Write-Heartbeat {
    try { [IO.File]::WriteAllText($HeartbeatFile, (Get-Date).ToUniversalTime().ToString('o')) } catch {}
}

function Get-CachePath {
    param([string]$Sha256)
    $h = $Sha256.ToLower()
    $levels = $h.ToCharArray()[0..7] | ForEach-Object { [string]$_ }
    return (Join-Path (Join-Path $CacheRoot ($levels -join '\')) "$h.json")
}

function Get-Verdict {
    param([string]$Sha256)
    $p = Get-CachePath $Sha256
    if (-not (Test-Path -LiteralPath $p)) { return 'UNKNOWN' }
    try { return [string](Get-Content -LiteralPath $p -Raw | ConvertFrom-Json).verdict }
    catch { return 'INCONCLUSIVE' }
}

function Get-EventFields {
    param($Ev)
    $f = @{}
    try {
        $x = [xml]$Ev.ToXml()
        foreach ($d in @($x.Event.EventData.Data)) { if ($d.Name) { $f[[string]$d.Name] = [string]$d.'#text' } }
    } catch {}
    return $f
}

$script:SigCache = @{}
function Get-SystemClass {
    param([string]$Image, [string]$Sha256)
    $key = ($Image.ToLower() + '|' + $Sha256.ToLower())
    if ($script:SigCache.ContainsKey($key)) { return $script:SigCache[$key] }
    $cls = 'UNSIGNED'
    $stText = 'NoCheck'
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Image -ErrorAction Stop
        $stText = [string]$sig.Status
        $isMs = ($stText -eq 'Valid') -and $sig.SignerCertificate -and ($sig.SignerCertificate.Subject -match 'O=Microsoft Corporation')
        if (-not $isMs) { $cls = "UNSIGNED:$stText" }
        if ($isMs) {
            $inBaselineScope = $false
            foreach ($root in @("$env:SystemRoot\System32\", "$env:SystemRoot\SysWOW64\", "$env:SystemRoot\Microsoft.NET\")) {
                if ($Image.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { $inBaselineScope = $true }
            }
            $inOtherSystem = $false
            foreach ($root in @("$env:SystemRoot\", "$env:ProgramFiles\", "${env:ProgramFiles(x86)}\")) {
                if ($Image.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { $inOtherSystem = $true }
            }
            if ($inBaselineScope) {
                if ($script:BaselineOk -and $script:Baseline.ContainsKey(($Image.ToLower() + '|' + $Sha256.ToLower()))) {
                    $cls = 'SIGNED-SYSTEM'
                } else {
                    $cls = 'SIGNED-NOTBASELINE'
                }
            } elseif ($inOtherSystem) {
                $cls = 'SIGNED-OTHER-SYSTEM'
            } else { $cls = 'SIGNED-OUTOFPLACE' }
        }
    } catch {
        $cls = "UNKNOWN-SIG:$($_.Exception.GetType().Name)"
    }
    $script:SigCache[$key] = $cls
    return $cls
}

function Invoke-ProcessCheck {
    param($Ev)
    $d = Get-EventFields $Ev
    $procId = [int]$d['ProcessId']
    $image  = $d['Image']
    if ($procId -eq $SelfPid -or -not $image) { return }
    $hash = $null
    $hashSrc = 'sysmon'
    if ([string]$d['Hashes'] -match '(?i)SHA256=([0-9a-f]{64})') { $hash = $Matches[1].ToUpper() }

    if (-not $hash) {
        $hashSrc = 'disk'
        if (-not (Test-Path -LiteralPath $image)) {
            Write-KsLog "SKIP pid=$procId no Sysmon hash and image no longer exists: $image"
            return
        }
        try {
            $hash = (Get-FileHash -LiteralPath $image -Algorithm SHA256 -ErrorAction Stop).Hash
        } catch {
            Write-KsLog "INCONCLUSIVE pid=$procId hash failed: $image ($($_.Exception.Message))"
            return
        }
    }

    switch (Get-Verdict $hash) {
        'MALICIOUS' {
            try {
                Stop-Process -Id $procId -Force -ErrorAction Stop
                Write-KsLog "KILLED pid=$procId verdict=MALICIOUS sha256=$hash image=$image hashsrc=$hashSrc"
            } catch {
                Write-KsLog "KILL FAILED pid=$procId sha256=$hash image=$image hashsrc=$hashSrc ($($_.Exception.Message))"
            }
        }
        'CLEAN'   { Write-KsLog "ALLOW pid=$procId verdict=CLEAN sha256=$hash image=$image hashsrc=$hashSrc" }
        'UNKNOWN' {
            $cls = Get-SystemClass $image $hash
            switch ($cls) {
                'SIGNED-SYSTEM'     { Write-KsLog "ALLOW-SIGNED pid=$procId class=MicrosoftSigned-SystemPath sha256=$hash image=$image hashsrc=$hashSrc" }
                'SIGNED-NOTBASELINE' { Write-KsLog "SUSPICIOUS-BASELINE pid=$procId Microsoft-signed system-path binary NOT in baseline (replaced or new file), not killed, needs review sha256=$hash image=$image hashsrc=$hashSrc" }
                'SIGNED-OTHER-SYSTEM' { Write-KsLog "OTHER-SIGNED pid=$procId class=MicrosoftSigned-OutsideBaselineScope (signature only, not baseline-verified), not killed sha256=$hash image=$image hashsrc=$hashSrc" }
                'SIGNED-OUTOFPLACE' { Write-KsLog "SUSPICIOUS-PATH pid=$procId Microsoft-signed binary outside system folders, not killed, needs review sha256=$hash image=$image hashsrc=$hashSrc" }
                default             { Write-KsLog "UNKNOWN pid=$procId not killed, needs analysis class=$cls sha256=$hash image=$image hashsrc=$hashSrc" }
            }
        }
        default   { Write-KsLog "INCONCLUSIVE pid=$procId cache unreadable sha256=$hash image=$image hashsrc=$hashSrc" }
    }
}

$script:Baseline = @{}
$script:BaselineOk = $false
$baselineCsv = 'C:\Baseline\baseline.csv'
if (Test-Path -LiteralPath $baselineCsv) {
    try {
        foreach ($row in (Import-Csv -LiteralPath $baselineCsv)) {
            if ($row.Sha256 -and $row.Path) { $script:Baseline[($row.Path.ToLower() + '|' + $row.Sha256.ToLower())] = $true }
        }
        $script:BaselineOk = ($script:Baseline.Count -gt 0)
    } catch { $script:BaselineOk = $false }
}
Write-KsLog ("BASELINE loaded={0} entries={1} path={2}" -f $script:BaselineOk, $script:Baseline.Count, $baselineCsv)

$last = 0
$existing = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1 } -MaxEvents 1 -ErrorAction SilentlyContinue
if ($existing) { $last = [long]$existing.RecordId }
Write-KsLog "START killswitch, cache=$CacheRoot, from RecordId=$last"
Write-Heartbeat

while ($true) {
    try {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1 } -MaxEvents 200 -ErrorAction SilentlyContinue |
            Where-Object { $_.RecordId -gt $last } | Sort-Object RecordId)
        foreach ($ev in $events) {
            $last = [long]$ev.RecordId
            Invoke-ProcessCheck $ev
        }
    } catch {
        Write-KsLog "LOOP ERROR $($_.Exception.Message)"
    }
    Write-Heartbeat
    Start-Sleep -Seconds $PollSec
}
