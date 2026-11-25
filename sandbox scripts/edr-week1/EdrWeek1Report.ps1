function Copy-EdrWeek1ToStaging {
    param([string]$StagingFolder)
    $src = $PSScriptRoot
    $dest = Join-Path $StagingFolder 'edr-week1'
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    foreach ($f in @('guest-edr-week1.ps1', 'guest-killswitch.ps1', 'sysmonconfig-week1.xml', 'applocker-audit-week1.xml')) {
        Copy-Item -LiteralPath (Join-Path $src $f) -Destination (Join-Path $dest $f) -Force -ErrorAction Stop
    }
}

function Wait-EdrWeek1Export {
    param([string]$TelemetryDir, [int]$TimeoutSeconds = 25)
    $flag = Join-Path $TelemetryDir 'edr-week1\export-complete.flag'
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path -LiteralPath $flag) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return (Test-Path -LiteralPath $flag)
}

function Write-EdrWeek1ReportLines {
    param([Parameter(Mandatory)][string]$TelemetryDir, [Parameter(Mandatory)][string]$ReportFile, [bool]$ExportConfirmed)

    $dir = Join-Path $TelemetryDir 'edr-week1'
    $summaryPath = Join-Path $dir 'summary.json'
    if (-not $ExportConfirmed) {
        Add-Content -Path $ReportFile -Value "[EDR WEEK1] The guest did not confirm its export within the wait; telemetry below (if any) may be partial or missing."
    }
    if (-not (Test-Path -LiteralPath $summaryPath)) {
        Add-Content -Path $ReportFile -Value "[EDR WEEK1] No summary.json was found; Sysmon/AppLocker telemetry is unavailable for this run."
        return
    }

    $s = $null
    try { $s = Get-Content -LiteralPath $summaryPath -Raw -Encoding UTF8 | ConvertFrom-Json } catch {
        Add-Content -Path $ReportFile -Value "[EDR WEEK1] summary.json could not be parsed: $($_.Exception.Message)"
        return
    }

    $labels = [ordered]@{
        process_create   = 'Process create (Sysmon 1)'
        network_connect  = 'Network connect (Sysmon 3)'
        remote_thread    = 'Remote thread (Sysmon 8)'
        lsass_access     = 'LSASS access (Sysmon 10)'
        registry_persist = 'Registry persistence (Sysmon 12/13/14)'
        file_delete      = 'File delete (Sysmon 26)'
        applocker_audit  = 'AppLocker audit hits (8003/8004/8006/8007)'
    }

    Add-Content -Path $ReportFile -Value "[EDR WEEK1] Sysmon service state at export: $($s.sysmonServiceState)"
    foreach ($key in $labels.Keys) {
        $cat = $s.categories.$key
        if (-not $cat) { continue }
        Add-Content -Path $ReportFile -Value ("[EDR WEEK1] {0}: {1} event(s)" -f $labels[$key], [int]$cat.count)
        $shown = 0
        foreach ($sample in @($cat.samples)) {
            if ($shown -ge 3) { break }
            $shown++
            $detail = switch ($key) {
                'process_create'   { "{0} (PID {1}) <- {2}" -f $sample.d.Image, $sample.d.ProcessId, $sample.d.ParentImage }
                'network_connect'  { "{0} -> {1}:{2}" -f $sample.d.Image, $sample.d.DestinationIp, $sample.d.DestinationPort }
                'remote_thread'    { "{0} -> {1}" -f $sample.d.SourceImage, $sample.d.TargetImage }
                'lsass_access'     { "{0} accessed lsass.exe (GrantedAccess {1})" -f $sample.d.SourceImage, $sample.d.GrantedAccess }
                'registry_persist' { "{0}: {1}" -f $sample.d.Image, $sample.d.TargetObject }
                'file_delete'      { "{0} deleted {1}" -f $sample.d.Image, $sample.d.TargetFilename }
                'applocker_audit'  { [string]$sample.message }
                default            { '' }
            }
            Add-Content -Path $ReportFile -Value ("    - {0}" -f $detail)
        }
    }
    if ($s.errors -and @($s.errors).Count -gt 0) {
        Add-Content -Path $ReportFile -Value ("[EDR WEEK1] Guest-reported errors: " + ((@($s.errors) | Select-Object -First 5) -join ' | '))
    }
    Add-Content -Path $ReportFile -Value "[EDR WEEK1 LIMIT] This is read-only telemetry from a folder the sample can also write to, and it does not affect the verdict above. It can only be used as a lead for manual review (see sysmon.evtx / applocker-*.evtx in the same folder)."
}

