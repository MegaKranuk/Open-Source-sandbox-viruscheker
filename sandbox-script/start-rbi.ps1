try {
    $sig = '[DllImport("kernel32.dll")] public static extern IntPtr GetStdHandle(int nStdHandle); [DllImport("kernel32.dll")] public static extern bool GetConsoleMode(IntPtr hConsoleHandle, out int lpMode); [DllImport("kernel32.dll")] public static extern bool SetConsoleMode(IntPtr hConsoleHandle, int dwMode); [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow(); [DllImport("user32.dll")] public static extern IntPtr GetSystemMenu(IntPtr hWnd, bool bRevert); [DllImport("user32.dll")] public static extern uint EnableMenuItem(IntPtr hMenu, uint uIDEnableItem, uint uEnable); [DllImport("user32.dll")] public static extern bool DrawMenuBar(IntPtr hWnd);'
    $type = Add-Type -MemberDefinition $sig -Name 'ConsoleUtils' -Namespace 'Win32' -PassThru -ErrorAction SilentlyContinue
    $handle = $type::GetStdHandle(-10)
    $mode = 0
    if ($handle -ne [IntPtr]::Zero -and $type::GetConsoleMode($handle, [ref]$mode)) {
        $mode = ($mode -band (-bnot 0x0040)) -bor 0x0080
        $modeSet = $type::SetConsoleMode($handle, $mode)
        if (-not $modeSet) {
            Write-Host "[!] Could not disable console Quick Edit; clicking the console may pause the pipeline." -ForegroundColor Yellow
        }
    }

    $consoleWindow = $type::GetConsoleWindow()
    if ($consoleWindow -ne [IntPtr]::Zero) {
        $systemMenu = $type::GetSystemMenu($consoleWindow, $false)
        if ($systemMenu -ne [IntPtr]::Zero) {
            $null = $type::EnableMenuItem($systemMenu, 0xF060, 0x0001)
            $null = $type::DrawMenuBar($consoleWindow)
        }
    }
} catch {}

$DownloadsFolder = "$env:USERPROFILE\Downloads"
$SafeFilesFolder = "$env:USERPROFILE\Desktop\Safe_Files"
$ReviewFilesFolder = "$env:USERPROFILE\Desktop\Review_Files"
$ThreatFilesFolder = "$env:USERPROFILE\Desktop\Threat_Files"
$pipelineMutex = [System.Threading.Mutex]::new($false, "Local\AutomatedMalwareAnalysisPipeline")
$pipelineMutexOwned = $false
try {
    $pipelineMutexOwned = $pipelineMutex.WaitOne(0)
} catch [System.Threading.AbandonedMutexException] {
    $pipelineMutexOwned = $true
}
if (-not $pipelineMutexOwned) {
    Write-Host "[!] The analysis queue is already running in another window." -ForegroundColor Yellow
    exit 1
}

$QuarantineFolder = "C:\Quarantine_Zone"
$StagingFolder = Join-Path $QuarantineFolder "Staging"
$PayloadFolder = Join-Path $StagingFolder "payload"
$HoneypotFolder = Join-Path $QuarantineFolder "Honeypot"
$TelemetryFolder = Join-Path $QuarantineFolder "Telemetry"
$FeatureSourceFolder = "C:\RBI_FeatureSource"
$WsbFile = Join-Path -Path $PSScriptRoot -ChildPath "sandbox.wsb"
$SandboxRunnerFile = Join-Path -Path $PSScriptRoot -ChildPath "sandbox-runner.ps1"
$ReportFile = Join-Path -Path $PSScriptRoot -ChildPath "analysis_report.txt"
$SandboxStartupTimeoutSeconds = 300
$RuntimeSetupTimeoutSeconds = 900
$GuestObservationSeconds = 120
$MaxAnalysisSeconds = 180
$DemoLaunchSettleSeconds = 8
$MaxHoneypotFiles = 20000
$SandboxCliCommand = Get-Command -Name "wsb.exe" -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
$SandboxCliPath = if ($SandboxCliCommand) { $SandboxCliCommand.Source } else { $null }
$SkippedQueuePaths = @{}
$DefenderDetectionLookbackHours = 24
$DefenderPollIntervalSeconds = 15
$DefenderDetectionCache = @{}
$DefenderAnnouncedResources = @{}
$LastDefenderPollUtc = [DateTime]::MinValue
$DefenderUnavailableReported = $false
$DefenderQueryFailureReported = $false
$GuestRunnerInstanceId = $null
$LastGuestRunnerState = ""
$GuestRunnerHistoryInstanceIds = @()
$script:HoneypotWatcher = $null
$script:HoneypotEventSourceIds = @()
$script:HoneypotRecentChanges = @()
$script:HoneypotKnownDirectories = @{}
$script:HoneypotVirusBurstReason = $null

function Get-QueueFileKey {
    param ([System.IO.FileInfo]$File)

    return "{0}|{1}|{2}" -f $File.FullName, $File.Length, $File.LastWriteTimeUtc.Ticks
}

function Restore-InterruptedQueueFiles {
    $interruptedFiles = @(Get-ChildItem -LiteralPath $DownloadsFolder -File -Filter "*.processing" -Recurse -Force -ErrorAction SilentlyContinue)
    foreach ($interruptedFile in $interruptedFiles) {
        $restoredName = $interruptedFile.Name.Substring(0, $interruptedFile.Name.Length - ".processing".Length)
        if ([string]::IsNullOrWhiteSpace($restoredName)) { continue }

        $parentFolder = Split-Path -Parent $interruptedFile.FullName
        $destination = Join-Path $parentFolder $restoredName
        if (Test-Path -LiteralPath $destination) {
            $baseName = [IO.Path]::GetFileNameWithoutExtension($restoredName)
            $extension = [IO.Path]::GetExtension($restoredName)
            $suffix = Get-Date -Format "yyyyMMdd-HHmmss"
            $destination = Join-Path $parentFolder ("{0}.recovered-{1}{2}" -f $baseName, $suffix, $extension)
            $counter = 1
            while (Test-Path -LiteralPath $destination) {
                $destination = Join-Path $parentFolder ("{0}.recovered-{1}-{2}{3}" -f $baseName, $suffix, $counter, $extension)
                $counter++
            }
        }

        try {
            Move-Item -LiteralPath $interruptedFile.FullName -Destination $destination -ErrorAction Stop
            Write-Host "[*] Restored an interrupted queue item for analysis: $(Split-Path -Leaf $destination)" -ForegroundColor Yellow
        } catch {
            Write-Host "[!] Could not restore interrupted queue item '$($interruptedFile.Name)': $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

if (-Not (Test-Path $WsbFile)) {
    Write-Host "ERROR: File sandbox.wsb not found!" -ForegroundColor Red
    Start-Sleep -Seconds 10
    exit
}

if (-Not (Test-Path $SandboxRunnerFile)) {
    Write-Host "ERROR: File sandbox-runner.ps1 not found!" -ForegroundColor Red
    Start-Sleep -Seconds 10
    exit
}

if (-Not (Test-Path $SafeFilesFolder)) {
    New-Item -ItemType Directory -Force -Path $SafeFilesFolder | Out-Null
}

if (-Not (Test-Path $ReviewFilesFolder)) {
    New-Item -ItemType Directory -Force -Path $ReviewFilesFolder | Out-Null
}

if (-Not (Test-Path $ThreatFilesFolder)) {
    New-Item -ItemType Directory -Force -Path $ThreatFilesFolder | Out-Null
}

Restore-InterruptedQueueFiles

function Invoke-StaticAnalysis {
    param ([string]$FilePath, [string]$RealName)
    
    Write-Host ([Environment]::NewLine + "[--- STATIC ANALYSIS ---]") -ForegroundColor Cyan
    $fileInfo = Get-Item $FilePath -ErrorAction SilentlyContinue
    if (-not $fileInfo) { return }

    $reportLines = @(
        "=== STATIC ANALYSIS REPORT ==="
        "File Name : $RealName"
        "Size (KB) : $([Math]::Round($fileInfo.Length / 1KB, 2))"
        "Created   : $($fileInfo.CreationTime)"
    )

    try {
        $hash = (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
        $reportLines += "SHA-256   : $hash"
        Write-Host "SHA-256: $hash" -ForegroundColor DarkGray
    } catch {
        $reportLines += "SHA-256   : unavailable ($($_.Exception.Message))"
        Write-Host "[!] Could not calculate SHA-256: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    Add-Content -Path $ReportFile -Value ($reportLines -join [Environment]::NewLine)
}

function Invoke-VirusTotalRequest {
    param (
        [string]$ApiKey,
        [string]$Url,
        [ValidateSet("GET", "POST")]
        [string]$Method = "GET",
        [string]$FilePath,
        [string]$UploadFileName,
        [int]$TimeoutSeconds = 90
    )

    $curlExe = Join-Path $env:SystemRoot "System32\curl.exe"
    if (-not (Test-Path -LiteralPath $curlExe)) {
        return [pscustomobject]@{ Success = $false; HttpCode = 0; Json = $null; Error = "Windows curl.exe is unavailable." }
    }
    if ($ApiKey -match '["\r\n]') {
        return [pscustomobject]@{ Success = $false; HttpCode = 0; Json = $null; Error = "VirusTotal API key contains unsupported characters." }
    }

    $curlConfig = 'header = "x-apikey: ' + $ApiKey + '"'
    $curlConfigPath = Join-Path ([IO.Path]::GetTempPath()) ("vt-curl-{0}.conf" -f [Guid]::NewGuid().ToString("N"))
    $responseLines = @()
    $curlExitCode = -1
    try {
        [IO.File]::WriteAllText($curlConfigPath, $curlConfig, [Text.Encoding]::ASCII)
        $curlArgs = @(
            "--disable", "--silent", "--show-error", "--connect-timeout", "15", "--max-time", [string]$TimeoutSeconds,
            "--proto", "=https", "--write-out", "`n%{http_code}", "--request", $Method,
            "--url", $Url, "--config", $curlConfigPath
        )
        if ($Method -eq "POST") {
            if (-not $FilePath -or -not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
                return [pscustomobject]@{ Success = $false; HttpCode = 0; Json = $null; Error = "VirusTotal upload file is unavailable." }
            }
            $safeUploadName = if ($UploadFileName) { [IO.Path]::GetFileName($UploadFileName) -replace '[^A-Za-z0-9._ -]', '_' } else { [IO.Path]::GetFileName($FilePath) }
            $curlArgs += @("--form", "file=@$FilePath;filename=$safeUploadName")
        }
        $responseLines = @(& $curlExe @curlArgs 2>&1)
        $curlExitCode = $LASTEXITCODE
    } catch {
        $responseLines = @($_.Exception.Message)
    } finally {
        Remove-Item -LiteralPath $curlConfigPath -Force -ErrorAction SilentlyContinue
    }
    $responseText = @($responseLines | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
    $statusMatch = [regex]::Match($responseText, '(?:\r?\n)(\d{3})\s*$')
    $httpCode = if ($statusMatch.Success) { [int]$statusMatch.Groups[1].Value } else { 0 }
    if (-not $statusMatch.Success -or $httpCode -eq 0 -or $curlExitCode -ne 0) {
        $reason = if ($curlExitCode -ne 0) { "VirusTotal transport failed (curl exit $curlExitCode)." } else { "VirusTotal returned no HTTP status." }
        $diagnostic = @($responseLines | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -and $_ -notmatch '^\d{3}$' }) -join " "
        if ($ApiKey) { $diagnostic = $diagnostic.Replace($ApiKey, "[redacted]") }
        if ($diagnostic.Length -gt 350) { $diagnostic = $diagnostic.Substring(0, 350) }
        if ($diagnostic) { $reason += " Details: $diagnostic" }
        return [pscustomobject]@{ Success = $false; HttpCode = 0; Json = $null; Error = $reason }
    }

    $body = $responseText.Substring(0, $statusMatch.Index).Trim()
    $json = $null
    if (-not [string]::IsNullOrWhiteSpace($body)) {
        try { $json = $body | ConvertFrom-Json -ErrorAction Stop } catch {}
    }
    $errorText = if ($json.error.message) { [string]$json.error.message } elseif ($json.error.code) { [string]$json.error.code } else { "HTTP $httpCode" }
    $success = ($curlExitCode -eq 0) -and ($httpCode -ge 200) -and ($httpCode -lt 300) -and ($null -ne $json)
    return [pscustomobject]@{ Success = $success; HttpCode = $httpCode; Json = $json; Error = $errorText }
}

function ConvertFrom-VirusTotalStats {
    param ([object]$Stats)

    if (-not $Stats) { return $null }
    $requiredNames = @("malicious", "suspicious", "undetected", "harmless", "timeout", "confirmed-timeout", "failure", "type-unsupported")
    $counts = @{}
    foreach ($name in $requiredNames) {
        $property = $Stats.PSObject.Properties | Where-Object { $_.Name -ieq $name } | Select-Object -First 1
        if (-not $property -or $null -eq $property.Value) { return $null }
        $parsed = 0
        if (-not [int]::TryParse([string]$property.Value, [ref]$parsed) -or $parsed -lt 0) { return $null }
        $counts[$name] = $parsed
    }

    $total = 0
    foreach ($property in $Stats.PSObject.Properties) {
        $count = 0
        if ([int]::TryParse([string]$property.Value, [ref]$count) -and $count -ge 0) { $total += $count }
    }
    if ($total -le 0) { return $null }

    $classified = [int]$counts.malicious + [int]$counts.suspicious + [int]$counts.undetected + [int]$counts.harmless
    $coveragePercent = if ($total -gt 0) { [Math]::Round(($classified / $total) * 100, 1) } else { 0 }

    return [pscustomobject]@{
        Malicious = [int]$counts.malicious
        Suspicious = [int]$counts.suspicious
        Undetected = [int]$counts.undetected
        Harmless = [int]$counts.harmless
        Timeout = [int]$counts.timeout
        ConfirmedTimeout = [int]$counts["confirmed-timeout"]
        Failure = [int]$counts.failure
        Unsupported = [int]$counts["type-unsupported"]
        CoverageComplete = (($counts.timeout + $counts["confirmed-timeout"] + $counts.failure + $counts["type-unsupported"]) -eq 0)
        CoveragePercent = $coveragePercent
        CoverageSufficient = ($coveragePercent -ge 70)
        Total = $total
    }
}

function Get-VirusTotalReport {
    param ([string]$FilePath)

    $apiKey = [System.Environment]::GetEnvironmentVariable("VT_API_KEY", "User")
    $sha256 = $null
    try { $sha256 = (Get-FileHash -LiteralPath $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() } catch {}
    $guiUrl = if ($sha256) { "https://www.virustotal.com/gui/file/$sha256" } else { "unavailable" }
    $result = [pscustomobject]@{
        Complete = $false; CoverageComplete = $false; Malicious = $null; Suspicious = $null; Undetected = $null; Harmless = $null
        Timeout = $null; ConfirmedTimeout = $null; Failure = $null; Unsupported = $null; Total = 0
        Status = "unavailable"; Source = "none"; LastAnalysis = "not reported"; Error = $null; Sha256 = $sha256; Url = $guiUrl
        Uploaded = $false; CoveragePercent = 0; CoverageSufficient = $false
    }

    if (-not $apiKey) {
        $result.Error = "VT_API_KEY is not configured for this user."
    } elseif (-not $sha256) {
        $result.Error = "Could not calculate SHA-256 for the VirusTotal lookup."
    } else {
        try {
            $lookup = Invoke-VirusTotalRequest -ApiKey $apiKey -Url "https://www.virustotal.com/api/v3/files/$sha256"
            $shouldUpload = $false
            if ($lookup.Success) {
                $attributes = $lookup.Json.data.attributes
                $cached = ConvertFrom-VirusTotalStats -Stats $attributes.last_analysis_stats
                $cachedDate = $null
                if ($attributes.last_analysis_date) {
                    try { $cachedDate = [DateTimeOffset]::FromUnixTimeSeconds([long]$attributes.last_analysis_date).UtcDateTime } catch {}
                }
                $cachedIsFresh = $cachedDate -and $cachedDate -le [DateTime]::UtcNow.AddMinutes(5) -and $cachedDate -ge [DateTime]::UtcNow.AddHours(-24)
                $cachedHasDetection = $cached -and ($cached.Malicious -gt 0 -or $cached.Suspicious -gt 0)
                if ($cached -and ($cachedHasDetection -or ($cachedIsFresh -and $cached.CoverageSufficient))) {
                    $result.Complete = $true
                    $result.Malicious = $cached.Malicious
                    $result.Suspicious = $cached.Suspicious
                    $result.Undetected = $cached.Undetected
                    $result.Harmless = $cached.Harmless
                    $result.Timeout = $cached.Timeout
                    $result.ConfirmedTimeout = $cached.ConfirmedTimeout
                    $result.Failure = $cached.Failure
                    $result.Unsupported = $cached.Unsupported
                    $result.CoverageComplete = $cached.CoverageComplete
                    $result.CoveragePercent = $cached.CoveragePercent
                    $result.CoverageSufficient = $cached.CoverageSufficient
                    $result.Total = $cached.Total
                    $result.Status = "completed"
                    $result.Source = "existing VirusTotal file report"
                    $result.LastAnalysis = if ($cachedDate) { $cachedDate.ToString("yyyy-MM-dd HH:mm:ss 'UTC'") } else { "date unavailable" }
                } else {
                    $shouldUpload = $true
                }
            } elseif ($lookup.HttpCode -eq 404) {
                $shouldUpload = $true
            } else {
                $result.Error = "VirusTotal file lookup failed: $($lookup.Error)."
            }

            if ($shouldUpload) {
                $fileInfo = Get-Item -LiteralPath $FilePath -ErrorAction Stop
                $maxUploadBytes = 650MB
                if ($fileInfo.Length -gt $maxUploadBytes) {
                    $result.Status = "too-large"
                    $result.Error = "The file is larger than VirusTotal's documented 650 MB upload limit; it was not uploaded."
                } else {
                    $uploadEndpoint = "https://www.virustotal.com/api/v3/files"
                    if ($fileInfo.Length -gt 32MB) {
                        $uploadUrlResponse = Invoke-VirusTotalRequest -ApiKey $apiKey -Url "https://www.virustotal.com/api/v3/files/upload_url"
                        if (-not $uploadUrlResponse.Success -or -not $uploadUrlResponse.Json.data) {
                            throw "Could not obtain VirusTotal's large-file upload URL: $($uploadUrlResponse.Error)."
                        }
                        $uploadEndpoint = [string]$uploadUrlResponse.Json.data
                        $uploadUri = [Uri]$uploadEndpoint
                        if ($uploadUri.Scheme -notin @("https", "http") -or ($uploadUri.Host -ne "virustotal.com" -and -not $uploadUri.Host.EndsWith(".virustotal.com", [StringComparison]::OrdinalIgnoreCase))) {
                            throw "VirusTotal returned an upload URL outside its HTTPS domain."
                        }
                        $uploadUriBuilder = [UriBuilder]$uploadUri
                        $uploadUriBuilder.Scheme = "https"
                        $uploadUriBuilder.Port = -1
                        $uploadEndpoint = $uploadUriBuilder.Uri.AbsoluteUri
                    }

                    $uploadResult = Invoke-VirusTotalRequest -ApiKey $apiKey -Url $uploadEndpoint -Method "POST" -FilePath $FilePath -UploadFileName ([IO.Path]::GetFileName($FilePath) -replace '\.processing$', '') -TimeoutSeconds 600
                    if (-not $uploadResult.Success -or -not $uploadResult.Json.data.id) {
                        throw "VirusTotal sample upload failed: $($uploadResult.Error)."
                    }

                    $result.Uploaded = $true
                    $result.Status = "analysis-pending"
                    $result.Source = "uploaded sample; awaiting VirusTotal analysis"
                    $result.Error = $null
                    Add-Content -Path $ReportFile -Value "[VIRUSTOTAL] Physical sample upload accepted. VirusTotal says submitted samples may be shared with its community."
                    Write-Host "[!] VirusTotal accepted the physical sample upload; it may be shared with the community." -ForegroundColor Yellow
                    $analysisId = [string]$uploadResult.Json.data.id
                    $escapedAnalysisId = [Uri]::EscapeDataString($analysisId)
                    $analysisEndpoint = "https://www.virustotal.com/api/v3/analyses/$escapedAnalysisId"
                    $analysisDeadline = [DateTime]::UtcNow.AddMinutes(5)
                    do {
                        Start-Sleep -Seconds 30
                        $analysisResponse = Invoke-VirusTotalRequest -ApiKey $apiKey -Url $analysisEndpoint
                        if (-not $analysisResponse.Success) {
                            throw "VirusTotal analysis status request failed: $($analysisResponse.Error)."
                        }
                        $analysisAttributes = $analysisResponse.Json.data.attributes
                        if ([string]$analysisAttributes.status -eq "completed") {
                            $submittedStats = ConvertFrom-VirusTotalStats -Stats $analysisAttributes.stats
                            if (-not $submittedStats) {
                                throw "VirusTotal marked the uploaded analysis complete but returned no usable engine statistics."
                            }
                            $result.Complete = $true
                            $result.Malicious = $submittedStats.Malicious
                            $result.Suspicious = $submittedStats.Suspicious
                            $result.Undetected = $submittedStats.Undetected
                            $result.Harmless = $submittedStats.Harmless
                            $result.Timeout = $submittedStats.Timeout
                            $result.ConfirmedTimeout = $submittedStats.ConfirmedTimeout
                            $result.Failure = $submittedStats.Failure
                            $result.Unsupported = $submittedStats.Unsupported
                            $result.CoverageComplete = $submittedStats.CoverageComplete
                            $result.CoveragePercent = $submittedStats.CoveragePercent
                            $result.CoverageSufficient = $submittedStats.CoverageSufficient
                            $result.Total = $submittedStats.Total
                            $result.Status = "completed"
                            $result.Source = "uploaded sample and completed VirusTotal analysis"
                            if ($analysisAttributes.date) {
                                try { $result.LastAnalysis = [DateTimeOffset]::FromUnixTimeSeconds([long]$analysisAttributes.date).UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss 'UTC'") } catch {}
                            }
                            break
                        }
                        $result.Status = [string]$analysisAttributes.status
                        Write-Host "[*] VirusTotal analysis status: $($result.Status). Waiting for engine results..." -ForegroundColor Magenta
                    } while ([DateTime]::UtcNow -lt $analysisDeadline)
                    if (-not $result.Complete) {
                        $result.Status = "analysis-pending"
                        $result.Error = "The sample was uploaded, but VirusTotal analysis had not completed within five minutes."
                    }
                }
            }
        } catch {
            if ($result.Uploaded) {
                $result.Status = "analysis-pending"
            } else {
                $result.Status = "unavailable"
            }
            $result.Error = "VirusTotal query failed: $($_.Exception.Message)"
        }
    }

    $vtReportLines = @("[--- VIRUSTOTAL ---]", "SHA-256    : $($result.Sha256)", "Status     : $($result.Status)", "Source     : $($result.Source)")
    if ($result.Complete) {
        $vtReportLines += "Malicious  : $($result.Malicious) / $($result.Total) engines"
        $vtReportLines += "Suspicious : $($result.Suspicious)"
        $vtReportLines += "Undetected : $($result.Undetected)"
        $vtReportLines += "Harmless   : $($result.Harmless)"
        $vtReportLines += "Timeouts   : $($result.Timeout + $result.ConfirmedTimeout)"
        $vtReportLines += "Failures   : $($result.Failure)"
        $vtReportLines += "Unsupported: $($result.Unsupported)"
        $coverageText = if ($result.CoverageComplete) { "complete" } else { "incomplete; $($result.CoveragePercent)% engines returned a classification" }
        $vtReportLines += "Coverage   : $coverageText"
        $vtReportLines += "Last scan  : $($result.LastAnalysis)"
    } else {
        $vtReportLines += "Malicious  : not available (analysis is not complete)"
        $vtReportLines += "Suspicious : not available (analysis is not complete)"
        $vtReportLines += "Undetected : not available (analysis is not complete)"
        if ($result.Error) { $vtReportLines += "Detail     : $($result.Error)" }
    }
    $vtReportLines += "Report URL : $($result.Url)"
    if ($result.Uploaded) {
        $vtReportLines += "Privacy    : Physical sample uploaded; VirusTotal says submitted samples may be shared with its community."
    }
    Add-Content -Path $ReportFile -Value ($vtReportLines -join [Environment]::NewLine)

    if ($result.Complete -and $result.CoverageSufficient) {
        Write-Host "[*] VirusTotal completed: $($result.Malicious)/$($result.Total) malicious, $($result.Suspicious) suspicious. Report: $($result.Url)" -ForegroundColor Magenta
    } elseif ($result.Complete) {
        Write-Host "[!] VirusTotal returned a report with low engine coverage ($($result.CoveragePercent)% classified). It cannot contribute a no-detections result." -ForegroundColor Yellow
    } else {
        Write-Host "[!] VirusTotal is not conclusive ($($result.Status)); the sample cannot be moved to Safe_Files. $($result.Error)" -ForegroundColor Yellow
    }
    return $result
}

function Get-HoneypotSnapshot {
    $snapshot = @{}
    Get-ChildItem -LiteralPath $HoneypotFolder -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $snapshot[$_.FullName] = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
        } catch {
            $snapshot[$_.FullName] = "UNREADABLE"
        }
    }
    return ,$snapshot
}

function Start-HoneypotActivityMonitor {
    Stop-HoneypotActivityMonitor
    if (-not (Test-Path -LiteralPath $HoneypotFolder)) { return }

    $watcher = New-Object System.IO.FileSystemWatcher
    $watcher.Path = $HoneypotFolder
    $watcher.Filter = "*"
    $watcher.IncludeSubdirectories = $true
    $watcher.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::DirectoryName -bor [System.IO.NotifyFilters]::LastWrite -bor [System.IO.NotifyFilters]::Size
    $watcher.InternalBufferSize = 65536

    $knownDirectories = @{}
    Get-ChildItem -LiteralPath $HoneypotFolder -Recurse -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $knownDirectories[$_.FullName.ToLowerInvariant()] = $true
    }
    $script:HoneypotKnownDirectories = $knownDirectories
    $script:HoneypotRecentChanges = @()
    $script:HoneypotVirusBurstReason = $null

    $sourceIds = @()
    try {
        foreach ($eventName in @("Created", "Changed", "Deleted", "Renamed")) {
            $sourceId = "RbiHoneypot_$([Guid]::NewGuid().ToString('N'))_$eventName"
            Register-ObjectEvent -InputObject $watcher -EventName $eventName -SourceIdentifier $sourceId -ErrorAction Stop | Out-Null
            $sourceIds += $sourceId
        }
    } catch {
        foreach ($sourceId in $sourceIds) { Unregister-Event -SourceIdentifier $sourceId -ErrorAction SilentlyContinue }
        $watcher.Dispose()
        throw
    }

    $script:HoneypotWatcher = $watcher
    $script:HoneypotEventSourceIds = $sourceIds
    $watcher.EnableRaisingEvents = $true
}

function Stop-HoneypotActivityMonitor {
    foreach ($sourceId in @($script:HoneypotEventSourceIds)) {
        Get-Event -SourceIdentifier $sourceId -ErrorAction SilentlyContinue | Remove-Event -ErrorAction SilentlyContinue
        Unregister-Event -SourceIdentifier $sourceId -ErrorAction SilentlyContinue
    }
    if ($script:HoneypotWatcher) {
        try { $script:HoneypotWatcher.EnableRaisingEvents = $false } catch {}
        try { $script:HoneypotWatcher.Dispose() } catch {}
    }
    $script:HoneypotWatcher = $null
    $script:HoneypotEventSourceIds = @()
    $script:HoneypotRecentChanges = @()
    $script:HoneypotKnownDirectories = @{}
}

function Get-HoneypotFileBurstSignal {
    if ($script:HoneypotVirusBurstReason) { return $script:HoneypotVirusBurstReason }

    foreach ($sourceId in @($script:HoneypotEventSourceIds)) {
        $queuedEvents = @(Get-Event -SourceIdentifier $sourceId -ErrorAction SilentlyContinue | Sort-Object EventIdentifier)
        foreach ($queuedEvent in $queuedEvents) {
            $eventArgs = $queuedEvent.SourceEventArgs
            $eventTime = $queuedEvent.TimeGenerated.ToUniversalTime()
            $eventPaths = @()
            if ($eventArgs -is [System.IO.RenamedEventArgs]) {
                $eventPaths += [string]$eventArgs.FullPath
            } elseif ($eventArgs -and $eventArgs.FullPath) {
                $eventPaths += [string]$eventArgs.FullPath
            }

            foreach ($eventPath in $eventPaths) {
                if ([string]::IsNullOrWhiteSpace($eventPath)) { continue }
                $normalizedPath = $eventPath.ToLowerInvariant()
                $isKnownDirectory = $script:HoneypotKnownDirectories.ContainsKey($normalizedPath)
                $currentlyDirectory = Test-Path -LiteralPath $eventPath -PathType Container
                if ($currentlyDirectory) {
                    $script:HoneypotKnownDirectories[$normalizedPath] = $true
                    continue
                }
                if ($isKnownDirectory) {
                    continue
                }
                $script:HoneypotRecentChanges += [pscustomobject]@{ Path = $normalizedPath; At = $eventTime }
            }
            Remove-Event -EventIdentifier $queuedEvent.EventIdentifier -ErrorAction SilentlyContinue
        }
    }

    $now = [DateTime]::UtcNow
    $oldestRetained = $now.AddSeconds(-5)
    $events = @($script:HoneypotRecentChanges | Where-Object { $_.At -ge $oldestRetained } | Sort-Object At)
    $script:HoneypotRecentChanges = $events

    $pathCounts = @{}
    $left = 0
    for ($right = 0; $right -lt $events.Count; $right++) {
        $rightPath = [string]$events[$right].Path
        if (-not $pathCounts.ContainsKey($rightPath)) { $pathCounts[$rightPath] = 0 }
        $pathCounts[$rightPath]++

        while (($events[$right].At - $events[$left].At).TotalSeconds -gt 1.0) {
            $leftPath = [string]$events[$left].Path
            $pathCounts[$leftPath]--
            if ($pathCounts[$leftPath] -le 0) { $pathCounts.Remove($leftPath) }
            $left++
        }

        if ($pathCounts.Count -gt 10) {
            $script:HoneypotVirusBurstReason = "VIRUS: More than 10 distinct files changed within one second ($($pathCounts.Count) files); rapid mass file modification is consistent with ransomware or a file-bomber."
            return $script:HoneypotVirusBurstReason
        }
    }

    return $null
}

function Get-HoneypotSignal {
    param ([hashtable]$Baseline)

    $burstSignal = Get-HoneypotFileBurstSignal
    if ($burstSignal) { return $burstSignal }

    $files = @(Get-ChildItem -LiteralPath $HoneypotFolder -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First $MaxHoneypotFiles)

    $artifacts = @($files | Where-Object {
        $_.Name -match "(?i)(read.?me|decrypt|recover|restore|how.?to|ransom|help)" -or
        $_.Extension -match "(?i)^\.(lock|locked|encrypted|crypted|crypto|wnry|wncry|fun|pay|demons)$"
    })
    if ($artifacts.Count -gt 0) {
        return "Ransom note or encrypted-file marker found in the honeypot: $($artifacts[0].Name)"
    }

    foreach ($path in $Baseline.Keys) {
        if (-not (Test-Path -LiteralPath $path)) {
            return "A honeypot canary file was deleted: $(Split-Path -Leaf $path)"
        }

        try {
            $currentHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
        } catch {
            return "A honeypot canary file became unreadable: $(Split-Path -Leaf $path)"
        }
        if ($currentHash -ne $Baseline[$path]) {
            return "A honeypot canary file was modified: $(Split-Path -Leaf $path)"
        }
    }

    return $null
}

function Get-RunnerStatus {
    $statusPath = Join-Path $TelemetryFolder "runner-status.json"
    if (-not (Test-Path -LiteralPath $statusPath)) { return $null }
    try {
        return Get-Content -LiteralPath $statusPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return $null
    }
}

function ConvertTo-DefenderResourcePath {
    param ([object]$Resource)

    if ($null -eq $Resource) { return $null }
    $value = [string]$Resource
    if ([string]::IsNullOrWhiteSpace($value)) { return $null }
    $value = [Uri]::UnescapeDataString($value.Trim().Trim('"'))
    $value = $value -replace '^(?i)file:', ''
    if ($value -match '^_[A-Za-z]:\\') { $value = $value.Substring(1) }
    if ($value -notmatch '^(?:[A-Za-z]:\\|\\\\)') {
        if ($value -match '(?i)([A-Z]:\\.*)$') { $value = $matches[1] }
    }
    if ($value -notmatch '^(?:[A-Za-z]:\\|\\\\)') { return $null }

    try {
        return [IO.Path]::GetFullPath($value).TrimEnd('\')
    } catch {
        return $null
    }
}

function Sync-DefenderDetectionLog {
    param (
        [string[]]$RelatedPaths = @(),
        [switch]$Force
    )

    $nowUtc = [DateTime]::UtcNow
    if (-not $Force -and ($nowUtc - $script:LastDefenderPollUtc).TotalSeconds -lt $script:DefenderPollIntervalSeconds) { return }
    $script:LastDefenderPollUtc = $nowUtc

    if (-not (Get-Command -Name Get-MpThreatDetection -ErrorAction SilentlyContinue)) {
        if (-not $script:DefenderUnavailableReported) {
            Add-Content -Path $script:ReportFile -Value "[DEFENDER] Defender threat history is unavailable on this system; files already removed by another antivirus cannot be correlated here."
            $script:DefenderUnavailableReported = $true
        }
        return
    }

    try {
        $detections = @(Get-MpThreatDetection -ErrorAction Stop)
    } catch {
        if (-not $script:DefenderQueryFailureReported) {
            Add-Content -Path $script:ReportFile -Value "[DEFENDER] Could not read Defender threat history: $($_.Exception.Message)"
            $script:DefenderQueryFailureReported = $true
        }
        return
    }

    $normalizedRelatedPaths = @($RelatedPaths | ForEach-Object { ConvertTo-DefenderResourcePath -Resource $_ } | Where-Object { $_ })
    $downloadsRoot = [IO.Path]::GetFullPath($script:DownloadsFolder).TrimEnd('\') + '\'
    foreach ($detection in $detections) {
        $rawResources = @()
        if ($detection.Resources) { $rawResources += @($detection.Resources) }
        if ($detection.Resource) { $rawResources += @($detection.Resource) }
        $resourcePaths = @($rawResources | ForEach-Object { ConvertTo-DefenderResourcePath -Resource $_ } | Where-Object { $_ } | Select-Object -Unique)
        if ($resourcePaths.Count -eq 0) { continue }

        $isRelatedToDownloads = $false
        $isRelatedToCurrentSample = $false
        foreach ($resourcePath in $resourcePaths) {
            if ($resourcePath.StartsWith($downloadsRoot, [StringComparison]::OrdinalIgnoreCase)) { $isRelatedToDownloads = $true }
            if ($normalizedRelatedPaths -contains $resourcePath) { $isRelatedToCurrentSample = $true }
        }
        if (-not $isRelatedToDownloads -and -not $isRelatedToCurrentSample) { continue }

        $detectionTimeUtc = $null
        try {
            if ($detection.InitialDetectionTime) { $detectionTimeUtc = ([DateTime]$detection.InitialDetectionTime).ToUniversalTime() }
        } catch {}
        if ($detectionTimeUtc -and $detectionTimeUtc -lt $nowUtc.AddHours(-$script:DefenderDetectionLookbackHours) -and -not $isRelatedToCurrentSample) { continue }

        $resourceKey = ($resourcePaths | Sort-Object) -join ';'
        $detectionKey = '{0}|{1}|{2}|{3}' -f $detection.ThreatID, $detection.DetectionID, $detection.InitialDetectionTime, $resourceKey
        if ($script:DefenderDetectionCache.ContainsKey($detectionKey)) { continue }
        $script:DefenderDetectionCache[$detectionKey] = $true

        $threatName = if ($detection.ThreatName) { [string]$detection.ThreatName } else { "Threat ID $($detection.ThreatID)" }
        $actionResult = if ($null -ne $detection.ActionSuccess) { [string]$detection.ActionSuccess } else { "not reported" }
        $reportedResources = $resourcePaths -join '; '
        Add-Content -Path $script:ReportFile -Value "[DEFENDER] $threatName detected for exact resource path(s): $reportedResources. Defender action success: $actionResult. The pipeline did not restore or recreate the file."
        if (-not $script:DefenderAnnouncedResources.ContainsKey($resourceKey)) {
            $script:DefenderAnnouncedResources[$resourceKey] = $true
            Write-Host "[!] Defender threat record found for a Downloads resource; no file was restored or recreated. See the report for its full path." -ForegroundColor Yellow
        }
    }
}

function Test-GuestRunnerRestart {
    param ([object]$Status)

    $instanceId = if ($Status) { [string]$Status.instanceId } else { "" }
    $state = if ($Status) { [string]$Status.state } else { "" }
    if ($instanceId -and -not $script:FirstGuestRunnerInstanceId) {
        $script:FirstGuestRunnerInstanceId = $instanceId
    }
    $historyPath = Join-Path $TelemetryFolder "runner-start-history.log"
    $historyIds = @()
    if (Test-Path -LiteralPath $historyPath) {
        try {
            $historyIds = @(Get-Content -LiteralPath $historyPath -ErrorAction Stop | ForEach-Object {
                $line = ([string]$_).TrimStart([char]0xFEFF)
                if ($line -match '^([0-9a-f]{32})\|') { $matches[1] }
            } | Select-Object -Unique)
        } catch {}
    }

    $priorIds = @($script:GuestRunnerHistoryInstanceIds)
    $currentIds = @($historyIds)
    if ($instanceId -match '^(?i)[0-9a-f]{32}$' -and $instanceId -notin $currentIds) { $currentIds += $instanceId }
    $newIds = @($currentIds | Where-Object { $_ -notin $priorIds })
    $restarted = (($priorIds.Count -gt 0) -and ($newIds.Count -gt 0)) -or (($priorIds.Count -eq 0) -and ($currentIds | Select-Object -Unique).Count -gt 1)
    if ($instanceId -and $script:GuestRunnerInstanceId -and $instanceId -ne $script:GuestRunnerInstanceId) { $restarted = $true }

    $script:GuestRunnerHistoryInstanceIds = @(@($priorIds + $currentIds) | Select-Object -Unique)
    if ($instanceId) { $script:GuestRunnerInstanceId = $instanceId }
    if ($state) { $script:LastGuestRunnerState = $state }
    return [bool]$restarted
}

function Get-WindowsSandboxProcesses {
    $processes = @()
    foreach ($processName in @("WindowsSandboxClient", "WindowsSandboxRemoteSession")) {
        $processes += @(Get-Process -Name $processName -ErrorAction SilentlyContinue)
    }
    return @($processes | Sort-Object -Property Id -Unique)
}

function Get-WindowsSandboxSessionRecords {
    param ([object]$InputObject)

    if ($null -eq $InputObject -or $InputObject -is [string]) { return }
    if ($InputObject -is [System.Collections.IDictionary]) {
        $id = $InputObject['id']
        if (-not $id) { $id = $InputObject['ID'] }
        if ($id) {
            $state = $InputObject['status']
            if (-not $state) { $state = $InputObject['state'] }
            if (-not $state) { $state = $InputObject['State'] }
            [pscustomobject]@{ Id = [string]$id; State = [string]$state }
        }
        foreach ($value in $InputObject.Values) { Get-WindowsSandboxSessionRecords -InputObject $value }
        return
    }
    if ($InputObject -is [System.Collections.IEnumerable]) {
        foreach ($item in $InputObject) { Get-WindowsSandboxSessionRecords -InputObject $item }
        return
    }
    if ($InputObject -isnot [pscustomobject]) { return }

    $properties = @($InputObject.PSObject.Properties)
    $idProperty = $properties | Where-Object { $_.Name -ieq 'id' } | Select-Object -First 1
    if ($idProperty -and $idProperty.Value) {
        $stateProperty = $properties | Where-Object { $_.Name -ieq 'status' -or $_.Name -ieq 'state' } | Select-Object -First 1
        $state = if ($stateProperty) { [string]$stateProperty.Value } else { '' }
        [pscustomobject]@{ Id = [string]$idProperty.Value; State = $state }
    }
    foreach ($property in $properties) { Get-WindowsSandboxSessionRecords -InputObject $property.Value }
}

function Get-WindowsSandboxSessionIds {
    if (-not $SandboxCliPath) { return @() }
    try {
        $raw = & $SandboxCliPath list --raw 2>$null
        if ($LASTEXITCODE -ne 0) { return @() }
        $rawText = @($raw) -join [Environment]::NewLine
        if ([string]::IsNullOrWhiteSpace($rawText)) { return @() }
        $document = $rawText | ConvertFrom-Json -ErrorAction Stop
        $records = @(Get-WindowsSandboxSessionRecords -InputObject $document)
        $activeIds = @($records | Where-Object {
            $_.Id -match '(?i)^\{?[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\}?$' -and
            (-not $_.State -or $_.State -match '(?i)^(running|started|active)$')
        } | Select-Object -ExpandProperty Id -Unique)
        return $activeIds
    } catch {
        return @()
    }
}

function Stop-AnalysisSandbox {
    param ([string]$SessionId, [int[]]$ClientProcessIds)

    $stoppedByCli = $false
    if ($SessionId -and $SandboxCliPath) {
        try {
            $null = & $SandboxCliPath stop --id $SessionId 2>&1
            if ($LASTEXITCODE -eq 0) {
                $stoppedByCli = $true
                Write-Host "[*] Windows Sandbox stopped cleanly (session $SessionId)." -ForegroundColor DarkGray
            }
        } catch {}
    }

    if (-not $stoppedByCli) {
        foreach ($processId in $ClientProcessIds) {
            Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
        }
    }
    if (-not $ClientProcessIds -or $ClientProcessIds.Count -eq 0) { return $false }

    $deadline = (Get-Date).AddSeconds(30)
    do {
        $activeIds = @(Get-WindowsSandboxProcesses | Select-Object -ExpandProperty Id)
        $processStillRunning = @($ClientProcessIds | Where-Object { $_ -in $activeIds }).Count -gt 0
        if (-not $processStillRunning) { return $true }
        Start-Sleep -Seconds 1
    } while ((Get-Date) -lt $deadline)

    return $false
}

while ($true) {
    Sync-DefenderDetectionLog
    $sample = Get-ChildItem -LiteralPath $DownloadsFolder -File -Recurse -Force -ErrorAction SilentlyContinue | Where-Object {
        $_.Extension -notin @(".crdownload", ".tmp", ".malware", ".processing", ".failed") -and
        $_.Name -notmatch "(?i)^desktop\.ini$" -and
        -not $SkippedQueuePaths.ContainsKey((Get-QueueFileKey -File $_))
    } | Select-Object -First 1

    if (-not $sample) {
        Write-Host "[!] No files found in Downloads. Waiting for the next file..." -ForegroundColor DarkGray
        Start-Sleep -Seconds 5
        continue
    }

    $originalName = $sample.Name
    $sampleQueueKey = Get-QueueFileKey -File $sample
    $sourcePath = "$($sample.FullName).processing"
    $runStatus = "INCONCLUSIVE"
    $runReason = "Analysis did not complete."
    $processingReady = $false
    $sandboxProcessId = $null
    $sandboxSessionId = $null
    $sandboxClientIds = @()
    $existingClientIds = @()
    $existingSandboxIds = @()
    $startedSandbox = $false
    $demoSeconds = 0
    $demonstrationElapsedSeconds = 0
    $sandboxRebootCount = 0
    $script:GuestRunnerInstanceId = $null
    $script:FirstGuestRunnerInstanceId = $null
    $script:LastGuestRunnerState = ""
    $script:GuestRunnerHistoryInstanceIds = @()
    $runnerCompleted = $false
    $staleHeartbeatReported = $false
    $baseline = @{}
    $virusTotalComplete = $false
    $virusTotalCoverageSufficient = $false
    $virusTotalMalicious = $null
    $virusTotalSuspicious = $null
    $runtimeRetryRequired = $false
    $runtimeInstallObserved = $false
    $deferredRuntimeSignalStatus = $null
    $deferredRuntimeSignalReason = $null

    Write-Host ([Environment]::NewLine + "[+] Processing file from queue: $originalName") -ForegroundColor Magenta
    $reportHeaderLines = @(
        "============================================================"
        "Automated Malware Analysis Report"
        "Sample: $originalName"
        "Date: $(Get-Date)"
    )
    Add-Content -Path $ReportFile -Value ([Environment]::NewLine + ($reportHeaderLines -join [Environment]::NewLine))

    try {
        Move-Item -LiteralPath $sample.FullName -Destination $sourcePath -ErrorAction Stop
        $processingReady = $true
        Write-Host "[*] Marked as .processing while it is analyzed." -ForegroundColor DarkGray
    } catch {
        $runReason = "Could not mark the sample as processing: $($_.Exception.Message)"
    }

    if ($processingReady) {
        Invoke-StaticAnalysis -FilePath $sourcePath -RealName $originalName
        Sync-DefenderDetectionLog -RelatedPaths @($sample.FullName, $sourcePath) -Force
        if (-not (Test-Path -LiteralPath $sourcePath)) {
            $runReason = "The sample disappeared during static analysis. Check Windows Security Protection History or antivirus quarantine."
        } else {
            $virusTotalResult = Get-VirusTotalReport -FilePath $sourcePath
            if ($virusTotalResult) {
                $virusTotalComplete = [bool]$virusTotalResult.Complete
                $virusTotalCoverageSufficient = [bool]$virusTotalResult.CoverageSufficient
                if ($virusTotalComplete) {
                    $virusTotalMalicious = [int]$virusTotalResult.Malicious
                    $virusTotalSuspicious = [int]$virusTotalResult.Suspicious
                }
            }

            $existingSandbox = @(Get-WindowsSandboxProcesses)
            $existingSandboxSessionIds = @(Get-WindowsSandboxSessionIds)
            if ($existingSandbox.Count -gt 0 -or $existingSandboxSessionIds.Count -gt 0) {
                $runReason = "An existing Windows Sandbox session is open; this sample was not run."
            } else {
                try {
                    foreach ($managedFolder in @($StagingFolder, $TelemetryFolder, $HoneypotFolder)) {
                        if (Test-Path -LiteralPath $managedFolder) {
                            Remove-Item -LiteralPath $managedFolder -Recurse -Force -ErrorAction Stop
                        }
                    }
                    $honeypotSubfolders = @("Desktop", "Documents", "Pictures", "Downloads") | ForEach-Object { Join-Path $HoneypotFolder $_ }
                    $foldersToCreate = @($PayloadFolder, $TelemetryFolder, $FeatureSourceFolder) + $honeypotSubfolders
                    New-Item -ItemType Directory -Force -Path $foldersToCreate | Out-Null
                    Copy-Item -LiteralPath $SandboxRunnerFile -Destination (Join-Path $StagingFolder "sandbox-runner.ps1") -Force -ErrorAction Stop
                    Copy-Item -LiteralPath $sourcePath -Destination (Join-Path $PayloadFolder $originalName) -Force -ErrorAction Stop

                    $canaryFiles = @(
                        @{ Name = "Documents\Finance_Records.xlsx"; Text = "Finance canary file. $([Guid]::NewGuid())`n$("Finance record. " * 2048)" },
                        @{ Name = "Downloads\Customer_List.csv"; Text = "Customer canary file. $([Guid]::NewGuid())`n$("Customer record. " * 2048)" },
                        @{ Name = "Documents\Project_Notes.docx"; Text = "Document canary file. $([Guid]::NewGuid())`n$("Project note. " * 2048)" },
                        @{ Name = "Pictures\Company_Photo.jpg"; Text = "Image canary file. $([Guid]::NewGuid())`n$("Image data. " * 2048)" },
                        @{ Name = "Desktop\Backup_Data.txt"; Text = "Backup canary file. $([Guid]::NewGuid())`n$("Backup record. " * 2048)" }
                    )
                    foreach ($canary in $canaryFiles) {
                        Set-Content -LiteralPath (Join-Path $HoneypotFolder $canary.Name) -Value $canary.Text -Encoding UTF8
                    }
                    $baseline = Get-HoneypotSnapshot
                    Start-HoneypotActivityMonitor
                } catch {
                    $runReason = "Could not prepare the isolated analysis folders: $($_.Exception.Message)"
                }

                if ($runReason -eq "Analysis did not complete.") {
                    $existingClientIds = @(Get-WindowsSandboxProcesses | Select-Object -ExpandProperty Id)
                    $existingSandboxIds = @(Get-WindowsSandboxSessionIds)
                    Add-Content -Path $ReportFile -Value "[SANDBOX] Networking is enabled so web installers can download components; the analyzed sample can also contact external hosts."
                    Write-Host "[*] Sandbox networking is enabled for installers; the analyzed sample can also contact external hosts." -ForegroundColor Yellow
                    Write-Host "[*] Starting Windows Sandbox and auto-running the sample..." -ForegroundColor Cyan
                    try {
                        Start-Process -FilePath $WsbFile -ErrorAction Stop | Out-Null
                        $startedSandbox = $true
                    } catch {
                        $runReason = "Windows Sandbox could not be launched: $($_.Exception.Message)"
                    }

                    if ($startedSandbox) {
                        Write-Host "[*] Waiting for the Sandbox client or the guest runner to report that it started (up to 5 minutes)..." -ForegroundColor Yellow
                        $startupSeconds = 0
                        $runnerConfirmed = $false
                        $sawSandboxDuringStartup = $false
                        $guestStatus = $null
                        while (-not $runnerConfirmed -and $startupSeconds -lt $SandboxStartupTimeoutSeconds) {
                            $sandboxClientIds = @(Get-WindowsSandboxProcesses |
                                Where-Object { $_.Id -notin $existingClientIds } |
                                Select-Object -ExpandProperty Id)
                            if ($sandboxClientIds.Count -gt 0) {
                                $sandboxProcessId = $sandboxClientIds[0]
                            }

                            $newSandboxIds = @(Get-WindowsSandboxSessionIds | Where-Object { $_ -notin $existingSandboxIds })
                            if ($newSandboxIds.Count -gt 0) { $sandboxSessionId = $newSandboxIds[0] }
                            if ($sandboxClientIds.Count -gt 0 -or $newSandboxIds.Count -gt 0) { $sawSandboxDuringStartup = $true }

                            $guestStatus = Get-RunnerStatus
                            if (Test-GuestRunnerRestart -Status $guestStatus) {
                                $sandboxRebootCount++
                                $runStatus = "INCONCLUSIVE"
                                $runReason = "The Sandbox guest rebooted during setup or analysis. The runner will monitor the restarted guest without launching the sample again; reboot alone is not treated as a threat."
                                Add-Content -Path $ReportFile -Value "[SANDBOX] Guest runner restart detected (#$sandboxRebootCount) during startup; awaiting the post-reboot observation."
                                Write-Host "[!] Sandbox guest restarted. Waiting for a post-reboot check; the restart alone is not a threat verdict." -ForegroundColor Yellow
                                $runnerConfirmed = $true
                                break
                            }
                            if ($guestStatus -and ($guestStatus.state -in @("STARTED", "LAUNCHING_PAYLOAD", "PREPARING_RUNTIME", "INSTALLING_RUNTIME", "POST_REBOOT_CHECK", "POST_REBOOT_COMPLETE", "REBOOTED", "INSPECTING_ARCHIVE", "RUNNING", "SUSPICIOUS", "VIRUS", "ZIP_BOMB", "UNSAFE_ARCHIVE", "COMPLETED", "UNSUPPORTED", "ERROR"))) {
                                $runnerConfirmed = $true
                            }
                            if ($runnerConfirmed) { break }

                            if ($sawSandboxDuringStartup -and $sandboxClientIds.Count -eq 0 -and $newSandboxIds.Count -eq 0) {
                                $runReason = "Windows Sandbox was closed during startup before the guest runner confirmed the sample launch."
                                Write-Host "[!] Sandbox closed during startup; marking this sample inconclusive and continuing the queue." -ForegroundColor Yellow
                                break
                            }

                            if ($startupSeconds -gt 0 -and $startupSeconds % 30 -eq 0) {
                                $visibleClients = @(Get-WindowsSandboxProcesses | Where-Object { $_.Id -notin $existingClientIds })
                                $clientNote = if ($visibleClients.Count -gt 0) { "Sandbox client detected" } else { "no Sandbox client process detected" }
                                $guestNote = if ($guestStatus) { "guest runner state: $($guestStatus.state)" } else { "guest runner has not reported; payload launch is unconfirmed" }
                                Write-Host "[*] Still waiting ($startupSeconds seconds): $clientNote; $guestNote." -ForegroundColor Yellow
                            }
                            Start-Sleep -Seconds 2
                            $startupSeconds += 2
                        }

                        if (-not $runnerConfirmed) {
                            if ($sandboxProcessId) {
                                $runReason = "The Sandbox window opened, but the guest runner did not confirm that the payload launched within $SandboxStartupTimeoutSeconds seconds."
                            } else {
                                $runReason = "No Sandbox client or guest-runner startup signal appeared within $SandboxStartupTimeoutSeconds seconds. The payload launch was not confirmed."
                            }
                            Write-Host "[!] $runReason" -ForegroundColor Yellow
                        }

                        if ($runnerConfirmed) {
                            if ($sandboxProcessId) {
                                Write-Host "[*] Sandbox client detected (PID $sandboxProcessId)." -ForegroundColor Green
                            }
                            if ($runnerConfirmed) {
                                if ([string]$guestStatus.state -eq "PREPARING_RUNTIME") {
                                    Write-Host "[*] Preparing a required runtime before launching the sample." -ForegroundColor Green
                                } elseif ([string]$guestStatus.state -eq "INSTALLING_RUNTIME") {
                                    Write-Host "[*] A missing-runtime prompt appeared; installing the required runtime while the sample waits." -ForegroundColor Green
                                } elseif ([string]$guestStatus.state -eq "LAUNCHING_PAYLOAD") {
                                    Write-Host "[*] Guest runner is launching the sample and checking for a missing-runtime prompt." -ForegroundColor Green
                                } elseif ([string]$guestStatus.state -eq "RUNNING") {
                                    Write-Host "[*] Guest runner confirmed startup; the sample has launched and is being monitored." -ForegroundColor Green
                                } else {
                                    Write-Host "[*] Guest runner started (state: $($guestStatus.state)); preparing the sample." -ForegroundColor Green
                                }
                            } elseif ($sandboxProcessId) {
                                Write-Host "[!] Sandbox window is open, but guest runner has not confirmed payload launch yet." -ForegroundColor Yellow
                            }
                            $analysisSeconds = 0
                            $runtimePreparationObserved = $guestStatus -and [string]$guestStatus.state -eq "PREPARING_RUNTIME"
                            $runtimeInstallObserved = $guestStatus -and [string]$guestStatus.state -eq "INSTALLING_RUNTIME"
                            $analysisDeadlineSeconds = if ($runtimePreparationObserved -or $runtimeInstallObserved) { $RuntimeSetupTimeoutSeconds } else { $SandboxStartupTimeoutSeconds }
                            $runtimeRetryRequired = [bool]$runtimeInstallObserved
                            $runtimeObservationDeadlineSet = $false
                            $previousRuntimeDetails = ""
                            $previousRuntimeActionDetails = ""
                            $deferredRuntimeSignalStatus = $null
                            $deferredRuntimeSignalReason = $null
                            $deferredRuntimeSignalReported = $false
                            while ($analysisSeconds -lt $analysisDeadlineSeconds) {
                                $liveClients = @(Get-WindowsSandboxProcesses | Where-Object { $_.Id -notin $existingClientIds })
                                $sandboxStillRunning = $liveClients.Count -gt 0
                                if ($sandboxSessionId -and $SandboxCliPath) {
                                    $sandboxStillRunning = $sandboxStillRunning -or ($sandboxSessionId -in @(Get-WindowsSandboxSessionIds))
                                }
                                if (($sandboxProcessId -or $sandboxSessionId) -and -not $sandboxStillRunning) {
                                    $exitGuestStatus = Get-RunnerStatus
                                    if (Test-GuestRunnerRestart -Status $exitGuestStatus) {
                                        $sandboxRebootCount++
                                        $runStatus = "INCONCLUSIVE"
                                        $runReason = "The Sandbox guest restarted and then exited before its post-reboot check completed. Reboot alone is not treated as a threat; the sample was not cleared as safe."
                                        Add-Content -Path $ReportFile -Value "[SANDBOX] Runner history confirms a guest restart immediately before the Sandbox session disappeared."
                                        Write-Host "[!] Guest restarted but Sandbox exited before the post-reboot check; preserving the sample for review." -ForegroundColor Yellow
                                    } else {
                                        $runReason = "Windows Sandbox exited before analysis completed. The sample is inconclusive and will not be placed in Safe_Files."
                                        Write-Host "[!] Windows Sandbox exited before analysis completed; preserving the sample for review." -ForegroundColor Yellow
                                    }
                                    break
                                }

                                $signal = Get-HoneypotSignal -Baseline $baseline
                                if ($signal) {
                                    $signalGuestStatus = Get-RunnerStatus
                                    if ($signalGuestStatus -and [string]$signalGuestStatus.state -in @("UNSUPPORTED", "ERROR")) {
                                        $runStatus = "INCONCLUSIVE"
                                        $runReason = "A behavior signal was recorded ($signal), but the guest reported $($signalGuestStatus.state) before confirming a working sample launch: $($signalGuestStatus.details) The sample will be preserved for review."
                                        Add-Content -Path $ReportFile -Value "[SANDBOX] A behavior signal was recorded, but launch/runtime setup was unsupported or failed; keeping the result inconclusive for manual review instead of starting the threat demonstration."
                                        break
                                    } elseif ($signalGuestStatus -and [string]$signalGuestStatus.state -in @("STARTED", "LAUNCHING_PAYLOAD", "PREPARING_RUNTIME", "INSTALLING_RUNTIME", "POST_REBOOT_CHECK")) {
                                        $signalStatus = if ($signal -match '^VIRUS:\s*') { "VIRUS" } else { "SUSPICIOUS" }
                                        if (-not $deferredRuntimeSignalStatus -or ($signalStatus -eq "VIRUS" -and $deferredRuntimeSignalStatus -ne "VIRUS")) {
                                            $deferredRuntimeSignalStatus = $signalStatus
                                            $deferredRuntimeSignalReason = if ($signal -match '^VIRUS:\s*(.*)$') { $matches[1] } else { $signal }
                                        }
                                        if (-not $deferredRuntimeSignalReported) {
                                            Add-Content -Path $ReportFile -Value "[SANDBOX] Behavior was detected while the guest was starting, setting up a runtime, or performing its post-reboot check; recorded it and will wait for the guest's final state before acting."
                                            Write-Host "[!] Activity detected during setup/post-reboot monitoring; waiting for the guest check to finish before the demo." -ForegroundColor Yellow
                                            $deferredRuntimeSignalReported = $true
                                        }
                                    } else {
                                        if ($signalGuestStatus -and [string]$signalGuestStatus.details -match "RUNTIME_REMEDIATION: .*relaunched exactly once") {
                                            Add-Content -Path $ReportFile -Value "[SANDBOX] Runtime installation completed and the blocked sample was relaunched once before the threat signal ended analysis."
                                            Write-Host "[*] Runtime installation and the one-time sample retry completed before the demonstration." -ForegroundColor Cyan
                                        }
                                        if ($signal -match '^VIRUS:\s*(.*)$') {
                                            $runStatus = "VIRUS"
                                            $runReason = $matches[1]
                                        } else {
                                            $runStatus = "SUSPICIOUS"
                                            $runReason = $signal
                                        }
                                        break
                                    }
                                }

                                $previousGuestState = $script:LastGuestRunnerState
                                $guestStatus = Get-RunnerStatus
                                if (Test-GuestRunnerRestart -Status $guestStatus) {
                                    $sandboxRebootCount++
                                    if ($runStatus -notin @("SUSPICIOUS", "VIRUS")) {
                                        $runStatus = "INCONCLUSIVE"
                                        $runReason = "The Sandbox guest rebooted during analysis. The restarted guest is being monitored without launching the sample again; reboot alone is not treated as a threat."
                                    }
                                    Add-Content -Path $ReportFile -Value "[SANDBOX] Guest runner restart detected (#$sandboxRebootCount) during dynamic analysis; the payload will not be relaunched automatically."
                                    Write-Host "[!] Guest restart detected. Continuing with a post-reboot observation; the restart alone is not a threat verdict." -ForegroundColor Yellow
                                }
                                if ($guestStatus) {
                                    $guestState = [string]$guestStatus.state
                                    if ($guestState -eq "PREPARING_RUNTIME" -and -not $runtimePreparationObserved) {
                                        $runtimePreparationObserved = $true
                                        $analysisDeadlineSeconds = $analysisSeconds + $RuntimeSetupTimeoutSeconds
                                        Add-Content -Path $ReportFile -Value "[SANDBOX] Guest is preparing VBScript and .NET runtimes from local read-only media; the analysis timer starts after the sample launches."
                                        Write-Host "[*] Preparing runtimes from the local offline source; the sample has not launched yet." -ForegroundColor Cyan
                                    } elseif ($guestState -eq "INSTALLING_RUNTIME" -and $previousGuestState -ne "INSTALLING_RUNTIME") {
                                        $runtimeInstallObserved = $true
                                        $runtimeRetryRequired = $true
                                        $analysisDeadlineSeconds = $analysisSeconds + $RuntimeSetupTimeoutSeconds
                                        Add-Content -Path $ReportFile -Value "[SANDBOX] A missing-runtime dialog appeared after launch; the guest is installing the requested runtime from local read-only media."
                                        Write-Host "[*] A missing-runtime prompt appeared; installing the requested runtime from local media." -ForegroundColor Cyan
                                    } elseif (-not $runtimeObservationDeadlineSet -and $guestState -eq "RUNNING") {
                                        $analysisSeconds = 0
                                        $analysisDeadlineSeconds = $MaxAnalysisSeconds
                                        $runtimeObservationDeadlineSet = $true
                                    }
                                    if ($guestState -in @("PREPARING_RUNTIME", "INSTALLING_RUNTIME")) {
                                        $runtimeDetails = [string]$guestStatus.details
                                        if ($guestState -eq "INSTALLING_RUNTIME") { $runtimeRetryRequired = $true }
                                        if ($runtimeDetails -ne $previousRuntimeDetails) {
                                            Write-Host "[*] Runtime setup: $runtimeDetails" -ForegroundColor Cyan
                                            $previousRuntimeDetails = $runtimeDetails
                                        }
                                    } elseif ($guestState -eq "RUNNING" -and [string]$guestStatus.details -match "RUNTIME_REMEDIATION:") {
                                        $runtimeRetryRequired = $true
                                        $runtimeActionDetails = [string]$guestStatus.details
                                        if ($runtimeActionDetails -ne $previousRuntimeActionDetails) {
                                            Write-Host "[*] $runtimeActionDetails" -ForegroundColor Cyan
                                            Add-Content -Path $ReportFile -Value "[SANDBOX] $runtimeActionDetails"
                                            $previousRuntimeActionDetails = $runtimeActionDetails
                                        }
                                        if ($runtimeActionDetails -match "(?i)RUNTIME_REMEDIATION: .* is installed") {
                                            $analysisSeconds = 0
                                            $analysisDeadlineSeconds = $MaxAnalysisSeconds
                                            $runtimeInstallObserved = $false
                                        }
                                    } elseif ($guestState -eq "LAUNCHING_PAYLOAD" -and [string]$guestStatus.details -match "RUNTIME_REMEDIATION:") {
                                        $runtimeRetryRequired = $true
                                        $runtimeActionDetails = [string]$guestStatus.details
                                        if ($runtimeActionDetails -ne $previousRuntimeActionDetails) {
                                            Write-Host "[*] $runtimeActionDetails" -ForegroundColor Cyan
                                            Add-Content -Path $ReportFile -Value "[SANDBOX] $runtimeActionDetails"
                                            $previousRuntimeActionDetails = $runtimeActionDetails
                                        }
                                    } elseif ($guestState -eq "POST_REBOOT_CHECK") {
                                        if ($guestState -ne $previousGuestState) {
                                            Add-Content -Path $ReportFile -Value "[SANDBOX] $($guestStatus.details)"
                                            Write-Host "[*] $($guestStatus.details)" -ForegroundColor Cyan
                                        }
                                    } elseif ($guestState -in @("POST_REBOOT_COMPLETE", "REBOOTED")) {
                                        $postRebootBehavior = [regex]::Match([string]$guestStatus.details, "(?i)behavior state (VIRUS|SUSPICIOUS)")
                                        if ($postRebootBehavior.Success -and $postRebootBehavior.Groups[1].Value -ieq "VIRUS") {
                                            $runStatus = "VIRUS"
                                            $runReason = [string]$guestStatus.details
                                        } elseif ($postRebootBehavior.Success -and $runStatus -ne "VIRUS") {
                                            $runStatus = "SUSPICIOUS"
                                            $runReason = [string]$guestStatus.details
                                        } elseif ($runStatus -notin @("SUSPICIOUS", "VIRUS")) {
                                            $runStatus = "INCONCLUSIVE"
                                            $runReason = [string]$guestStatus.details
                                        }
                                        Add-Content -Path $ReportFile -Value "[SANDBOX] $($guestStatus.details)"
                                        Write-Host "[*] Post-reboot observation finished. Reboot alone was not classified as a threat." -ForegroundColor Yellow
                                        break
                                    } elseif ($guestState -ne $previousGuestState -and (($guestState -eq "INSPECTING_ARCHIVE") -or ($guestState -eq "RUNNING"))) {
                                        Write-Host "[*] Guest analysis state: $guestState - $($guestStatus.details)" -ForegroundColor Cyan
                                    }
                                    if ($guestState -eq "RUNNING" -and $guestState -ne $previousGuestState -and [string]$guestStatus.details -match 'Runtime notices:') {
                                        Add-Content -Path $ReportFile -Value "[SANDBOX] $($guestStatus.details)"
                                    }
                                    if ($guestState -eq "RUNNING" -and $guestStatus.updated -and $guestStatus.instanceId) {
                                        try {
                                            $runnerUpdatedUtc = ([DateTime]::Parse([string]$guestStatus.updated)).ToUniversalTime()
                                            $heartbeatAgeSeconds = ([DateTime]::UtcNow - $runnerUpdatedUtc).TotalSeconds
                                            if ($heartbeatAgeSeconds -gt 20 -and -not $staleHeartbeatReported) {
                                                $staleHeartbeatReported = $true
                                                if ($runStatus -notin @("SUSPICIOUS", "VIRUS")) {
                                                    $runStatus = "INCONCLUSIVE"
                                                    $runReason = "Guest heartbeat stopped for $([Math]::Floor($heartbeatAgeSeconds)) seconds. The guest may have rebooted or stopped; no threat verdict is inferred from the missing heartbeat alone."
                                                }
                                                Add-Content -Path $ReportFile -Value "[SANDBOX] Guest heartbeat became stale while the Sandbox session remained present; waiting for a restarted runner or timing out as inconclusive."
                                                Write-Host "[!] Guest heartbeat is stale. Waiting for a post-reboot status; no threat verdict is inferred from the timeout alone." -ForegroundColor Yellow
                                            }
                                        } catch {}
                                    }
                                    if ($guestState -eq "VIRUS") {
                                        $runStatus = "VIRUS"
                                        $runReason = $guestStatus.details
                                        break
                                    }
                                    if (($guestState -eq "SUSPICIOUS") -or ($guestState -eq "ZIP_BOMB") -or ($guestState -eq "UNSAFE_ARCHIVE")) {
                                    $runStatus = "SUSPICIOUS"
                                        $runReason = $guestStatus.details
                                        break
                                    }
                                    if ($guestState -eq "COMPLETED") {
                                        if (-not $runnerCompleted) {
                                            $runnerCompleted = $true
                                            Add-Content -Path $ReportFile -Value "[SANDBOX] Guest runner completed its internal observation window. Host-side monitoring continues until the full analysis window ends."
                                            Write-Host "[*] Guest runner completed; host-side monitoring continues before a clean verdict is considered." -ForegroundColor Cyan
                                        }
                                    }
                                    if (($guestState -eq "UNSUPPORTED") -or ($guestState -eq "ERROR")) {
                                        if ($deferredRuntimeSignalStatus) {
                                            $runStatus = "INCONCLUSIVE"
                                            $runReason = "The guest could not confirm a working sample launch. Runtime/setup failure: $($guestStatus.details) Previously recorded behavior signal for manual review: $deferredRuntimeSignalReason"
                                            Add-Content -Path $ReportFile -Value "[SANDBOX] Runtime/setup failed before a working payload launch was confirmed; the saved signal remains in the report and the item will be preserved for review."
                                        } else {
                                            $runReason = $guestStatus.details
                                        }
                                        break
                                    }
                                    $requiredLaunchCount = if ($runtimeRetryRequired) { 2 } else { 1 }
                                    if ($deferredRuntimeSignalStatus -and $guestState -eq "RUNNING" -and ([int]$guestStatus.launched -ge $requiredLaunchCount)) {
                                        $runStatus = $deferredRuntimeSignalStatus
                                        $runReason = if ([string]$guestStatus.details -match "(?i)relaunched exactly once") {
                                            "$deferredRuntimeSignalReason Runtime installation completed and the sample was retried once."
                                        } else {
                                            "$deferredRuntimeSignalReason The guest confirmed that the payload launch completed."
                                        }
                                        Add-Content -Path $ReportFile -Value "[SANDBOX] Resuming the deferred threat verdict after the guest confirmed the payload launch or runtime repair and retry."
                                        break
                                    }
                                }

                                $liveClients = @(Get-WindowsSandboxProcesses | Where-Object { $_.Id -notin $existingClientIds })
                                $sandboxClientIds = @($liveClients | Select-Object -ExpandProperty Id)
                                if (-not $sandboxProcessId -and $liveClients.Count -gt 0) {
                                    $sandboxProcessId = $liveClients[0].Id
                                }
                                $sandboxStillRunning = $liveClients.Count -gt 0
                                if ($sandboxSessionId -and $SandboxCliPath) {
                                    $sandboxStillRunning = $sandboxStillRunning -or ($sandboxSessionId -in @(Get-WindowsSandboxSessionIds))
                                }
                                if (($sandboxProcessId -or $sandboxSessionId) -and -not $sandboxStillRunning) {
                                    $exitGuestStatus = Get-RunnerStatus
                                    if (Test-GuestRunnerRestart -Status $exitGuestStatus) {
                                        $sandboxRebootCount++
                                        $runStatus = "INCONCLUSIVE"
                                        $runReason = "The Sandbox guest restarted and then exited before post-reboot monitoring finished. The reboot alone is not treated as a threat; the sample was not cleared as safe."
                                        Add-Content -Path $ReportFile -Value "[SANDBOX] Runner history confirms a guest restart immediately before the Sandbox session disappeared."
                                        Write-Host "[!] Guest restarted but the Sandbox exited before its post-reboot check finished; the result is inconclusive." -ForegroundColor Yellow
                                    } elseif ($runnerCompleted -and $analysisSeconds -ge ($GuestObservationSeconds - 2) -and $exitGuestStatus -and [string]$exitGuestStatus.state -eq "COMPLETED" -and [int]$exitGuestStatus.launched -ge 1) {
                                        $runStatus = "NO DETECTION"
                                        $runReason = "The guest confirmed at least one payload launch and completed its full internal behavior observation with no monitored threat signal. The Sandbox then exited; the exit cause is unknown, but the guest observation completed. VirusTotal coverage is evaluated separately."
                                        Add-Content -Path $ReportFile -Value "[SANDBOX] Guest confirmed payload launch and completed its full internal observation before the Sandbox session exited; exit cause is unknown."
                                        Write-Host "[+] Guest observation completed without a threat signal before the Sandbox exited." -ForegroundColor Green
                                    } else {
                                        $runReason = "Windows Sandbox exited before analysis completed. The sample is inconclusive and will not be placed in Safe_Files."
                                    }
                                    break
                                }

                                if ($analysisSeconds -gt 0 -and $analysisSeconds % 30 -eq 0) {
                                    if ($guestStatus -and ([string]$guestStatus.state -in @("PREPARING_RUNTIME", "INSTALLING_RUNTIME"))) {
                                        Write-Host "[*] Runtime setup has taken $analysisSeconds seconds: $($guestStatus.details)" -ForegroundColor Yellow
                                    } elseif ($guestStatus -and [string]$guestStatus.state -eq "LAUNCHING_PAYLOAD") {
                                        Write-Host "[*] Sample startup is checking for missing-runtime prompts before dynamic analysis begins." -ForegroundColor Yellow
                                    } elseif ($guestStatus -and [string]$guestStatus.state -eq "RUNNING") {
                                        Write-Host "[*] Dynamic analysis $analysisSeconds seconds; guest state: RUNNING; no ransomware or file-bomber signal so far." -ForegroundColor Yellow
                                    } elseif ($guestStatus -and [string]$guestStatus.state -eq "COMPLETED" -and [int]$guestStatus.launched -ge 1) {
                                        Write-Host "[*] Guest completed its observation after launching $($guestStatus.launched) payload(s); waiting for the host-side check to finish." -ForegroundColor Cyan
                                    } else {
                                        $stateNote = if ($guestStatus) { "guest state: $($guestStatus.state); launched count: $($guestStatus.launched)" } else { "guest runner status is missing" }
                                        $launchNote = if ($guestStatus -and [int]$guestStatus.launched -gt 0) { "the sample has launched" } else { "the sample launch is not confirmed" }
                                        Write-Host "[*] Guest preparation has taken $analysisSeconds seconds; $stateNote; $launchNote." -ForegroundColor Yellow
                                    }
                                }

                                Sync-DefenderDetectionLog -RelatedPaths @($sample.FullName, $sourcePath, (Join-Path $PayloadFolder $originalName))
                                Start-Sleep -Seconds 2
                                if ($guestStatus -and [string]$guestStatus.state -eq "RUNNING" -and $previousGuestState -ne "RUNNING") {
                                    $analysisSeconds = 0
                                } else {
                                    $analysisSeconds += 2
                                }
                            }

                            if ($runStatus -eq "INCONCLUSIVE" -and $runnerCompleted -and $sandboxRebootCount -eq 0 -and $analysisSeconds -ge $MaxAnalysisSeconds) {
                                $liveClients = @(Get-WindowsSandboxProcesses | Where-Object { $_.Id -notin $existingClientIds })
                                $sandboxStillRunning = $liveClients.Count -gt 0
                                if ($sandboxSessionId -and $SandboxCliPath) {
                                    $sandboxStillRunning = $sandboxStillRunning -or ($sandboxSessionId -in @(Get-WindowsSandboxSessionIds))
                                }
                                if ($sandboxStillRunning -and $guestStatus -and [int]$guestStatus.launched -ge 1) {
                                    $runStatus = "NO DETECTION"
                                    $runReason = "Guest analysis completed ($($guestStatus.details)); no monitored behavior was detected during the full $MaxAnalysisSeconds-second host observation window. Launched payloads: $($guestStatus.launched)."
                                } elseif ($sandboxStillRunning) {
                                    $runReason = "The guest observation completed, but the runner never confirmed that a payload launched. The sample is inconclusive and will not be placed in Safe_Files."
                                } else {
                                    $runReason = "Windows Sandbox exited at the end of analysis. The sample is inconclusive and will not be placed in Safe_Files."
                                }
                            } elseif ($runStatus -eq "INCONCLUSIVE" -and $analysisSeconds -ge $analysisDeadlineSeconds -and $runReason -eq "Analysis did not complete.") {
                                if ($runtimeInstallObserved) {
                                    $runReason = "Automatic runtime installation did not finish within $RuntimeSetupTimeoutSeconds seconds after the missing-runtime dialog appeared."
                                } elseif ($runtimePreparationObserved -and -not $runtimeObservationDeadlineSet) {
                                    $runReason = "Guest runtime preparation did not finish within $RuntimeSetupTimeoutSeconds seconds."
                                } else {
                                    $runReason = "Guest analysis did not finish within $analysisDeadlineSeconds seconds."
                                }
                                if ($deferredRuntimeSignalStatus) {
                                    $runStatus = "INCONCLUSIVE"
                                    $runReason = "$deferredRuntimeSignalReason Runtime setup timed out before the required sample launch/retry was confirmed. The signal is preserved for manual review; it will not be treated as a completed detonation."
                                    Add-Content -Path $ReportFile -Value "[SANDBOX] Runtime setup timed out before the sample launch/retry was confirmed. Kept the result inconclusive and preserved the pre-launch behavior signal for review."
                                }
                            }

                        }
                    }
                }
            }
        }
    }

    if ($virusTotalComplete -and ($virusTotalMalicious -gt 0 -or $virusTotalSuspicious -gt 0)) {
        if ($runStatus -ne "VIRUS") {
            $runStatus = "SUSPICIOUS"
            $runReason = "VirusTotal reported detections (malicious: $virusTotalMalicious/$($virusTotalResult.Total) engines; suspicious: $virusTotalSuspicious). Any positive VirusTotal detection is treated as suspicious."
        }
    } elseif ((-not $virusTotalComplete -or -not $virusTotalCoverageSufficient) -and $runStatus -eq "NO DETECTION") {
        $runStatus = "INCONCLUSIVE"
        $runReason = "Sandbox monitoring found no behavior, but VirusTotal did not return a completed report with enough engines reporting a classification. The sample is preserved for review."
    }

    if ($startedSandbox -and $runStatus -in @("SUSPICIOUS", "VIRUS")) {
        $demoSeconds = 35
        $remainingSeconds = $demoSeconds
        $waitingForSandboxRecovery = ($sandboxRebootCount -gt 0)
        $sandboxUnavailableDuringDemo = $false
        $recoveryWaitElapsedSeconds = 0
        $sandboxMissingSeconds = 0
        $lastObservedRunnerId = if ($script:GuestRunnerInstanceId) { [string]$script:GuestRunnerInstanceId } else { "" }
        $recoveryPriorRunnerId = if ($script:FirstGuestRunnerInstanceId) { [string]$script:FirstGuestRunnerInstanceId } else { $lastObservedRunnerId }
        $demoKnownClientIds = @(Get-WindowsSandboxProcesses | Where-Object { $_.Id -notin $existingClientIds } | Select-Object -ExpandProperty Id)
        $demoKnownSessionIds = @(Get-WindowsSandboxSessionIds | Where-Object { $_ -notin $existingSandboxIds })
        $demoTimer = $null
        $demoReadySince = $null
        $lastLoggedRemaining = -1
        $readyStates = @("RUNNING", "SUSPICIOUS", "VIRUS", "ZIP_BOMB", "UNSAFE_ARCHIVE", "COMPLETED", "REBOOTED", "POST_REBOOT_COMPLETE")
        if ($waitingForSandboxRecovery) {
            Add-Content -Path $ReportFile -Value "[SANDBOX] A guest restart was already detected; waiting for the post-reboot check before the demonstration."
            Write-Host "[!] Sandbox restart detected. Waiting for the post-reboot check before starting the visible timer." -ForegroundColor Yellow
        } else {
            Write-Host "[!] Threat activity confirmed. After payload launch is confirmed, the Sandbox will settle for $DemoLaunchSettleSeconds seconds, then remain visible for 35 seconds." -ForegroundColor Yellow
        }

        while (-not $sandboxUnavailableDuringDemo) {
            if ($demoTimer) {
                $remainingMilliseconds = (35 * 1000) - $demoTimer.ElapsedMilliseconds
                if ($remainingMilliseconds -le 0) { break }
            }

            $demoSignal = Get-HoneypotFileBurstSignal
            if ($demoSignal -match '^VIRUS:\s*(.*)$') {
                $runStatus = "VIRUS"
                $runReason = $matches[1]
            }
            if ($demoTimer -and $demoTimer.ElapsedMilliseconds -ge (35 * 1000)) { break }

            $demoGuestStatus = Get-RunnerStatus
            $guestRunnerRestarted = Test-GuestRunnerRestart -Status $demoGuestStatus
            if ($demoGuestStatus -and [string]$demoGuestStatus.state -eq "VIRUS") {
                $runStatus = "VIRUS"
                $runReason = [string]$demoGuestStatus.details
            }
            $currentRunnerId = if ($demoGuestStatus -and $demoGuestStatus.instanceId) { [string]$demoGuestStatus.instanceId } else { "" }
            $currentDemoClients = @(Get-WindowsSandboxProcesses | Where-Object { $_.Id -notin $existingClientIds })
            $currentDemoClientIds = @($currentDemoClients | Select-Object -ExpandProperty Id)
            $currentDemoSessionIds = @(Get-WindowsSandboxSessionIds | Where-Object { $_ -notin $existingSandboxIds })
            $newDemoClientIds = @($currentDemoClientIds | Where-Object { $_ -notin $demoKnownClientIds })
            $newDemoSessionIds = @($currentDemoSessionIds | Where-Object { $_ -notin $demoKnownSessionIds })

            $runnerHeartbeatStale = $false
            if ($demoGuestStatus -and ([string]$demoGuestStatus.state -in @("RUNNING", "SUSPICIOUS", "VIRUS")) -and $demoGuestStatus.updated) {
                try {
                    $demoHeartbeatAge = ([DateTime]::UtcNow - ([DateTime]::Parse([string]$demoGuestStatus.updated)).ToUniversalTime()).TotalSeconds
                    $runnerHeartbeatStale = ($demoHeartbeatAge -gt 20)
                } catch {}
            }
            $sandboxRestarted = $guestRunnerRestarted -or $runnerHeartbeatStale -or ($newDemoClientIds.Count -gt 0) -or ($newDemoSessionIds.Count -gt 0)
            $sandboxCurrentlyPresent = ($currentDemoClientIds.Count -gt 0) -or ($currentDemoSessionIds.Count -gt 0)

            if ($sandboxRestarted -and -not $waitingForSandboxRecovery) {
                $sandboxRebootCount++
                $waitingForSandboxRecovery = $true
                $demoTimer = $null
                $demoReadySince = $null
                $remainingSeconds = 35
                $recoveryWaitElapsedSeconds = 0
                $recoveryPriorRunnerId = if ($lastObservedRunnerId) { $lastObservedRunnerId } else { $currentRunnerId }
                Add-Content -Path $ReportFile -Value "[SANDBOX] Guest restart or stale heartbeat detected (#$sandboxRebootCount); paused the demonstration while waiting for the post-reboot check."
                Write-Host "[!] Sandbox restart detected. Pausing the countdown for the post-reboot check." -ForegroundColor Yellow
            }

            if (-not $sandboxCurrentlyPresent) {
                if ($waitingForSandboxRecovery) {
                    $recoveryWaitElapsedSeconds++
                    $sandboxMissingSeconds++
                    if ($sandboxMissingSeconds -ge 15) {
                        $sandboxUnavailableDuringDemo = $true
                        if ($runStatus -notin @("SUSPICIOUS", "VIRUS")) { $runStatus = "INCONCLUSIVE"; $runReason = "Windows Sandbox exited during the expected guest restart and did not return. The sample was not automatically relaunched." }
                        Add-Content -Path $ReportFile -Value "[SANDBOX] Sandbox client and session disappeared during recovery; treating this as a failed restart/exit, not a clean result."
                        Write-Host "[!] Sandbox exited during restart and did not return; ending this item and continuing the queue." -ForegroundColor Red
                        break
                    }
                    if ($recoveryWaitElapsedSeconds -ge $SandboxStartupTimeoutSeconds) {
                        $sandboxUnavailableDuringDemo = $true
                        if ($runStatus -notin @("SUSPICIOUS", "VIRUS")) { $runStatus = "INCONCLUSIVE"; $runReason = "Windows Sandbox did not return with a ready guest within $SandboxStartupTimeoutSeconds seconds after a restart. The sample was not automatically relaunched." }
                        Add-Content -Path $ReportFile -Value "[SANDBOX] Recovery timeout; no live Sandbox session or ready guest runner returned."
                        Write-Host "[!] Sandbox did not return after the guest restart; ending this item and continuing the queue." -ForegroundColor Red
                        break
                    }
                    if ($recoveryWaitElapsedSeconds -eq 1 -or $recoveryWaitElapsedSeconds % 30 -eq 0) {
                        Write-Host "[*] Waiting for the restarted Sandbox ($recoveryWaitElapsedSeconds seconds)..." -ForegroundColor Yellow
                    }
                } else {
                    $sandboxMissingSeconds++
                    if ($sandboxMissingSeconds -ge 3) {
                        $sandboxUnavailableDuringDemo = $true
                        if ($runStatus -ne "VIRUS") { $runReason = "Windows Sandbox was closed during the demonstration. The suspicious sample remains classified as suspicious." }
                        Add-Content -Path $ReportFile -Value "[SANDBOX] The Sandbox client and session disappeared; ending the demonstration immediately without clearing the threat verdict."
                        Write-Host "[!] Sandbox was closed. Ending this item and continuing the queue." -ForegroundColor Red
                        break
                    }
                }

                $demoKnownClientIds = $currentDemoClientIds
                $demoKnownSessionIds = $currentDemoSessionIds
                Start-Sleep -Milliseconds 1000
                continue
            }
            $sandboxMissingSeconds = 0

            if ($currentRunnerId) { $lastObservedRunnerId = $currentRunnerId }

            if ($waitingForSandboxRecovery) {
                $historyIds = @($script:GuestRunnerHistoryInstanceIds)
                $latestHistoryId = if ($historyIds.Count -gt 0) { [string]$historyIds[$historyIds.Count - 1] } else { "" }
                $runnerIsPostRestart = ($currentRunnerId -and $currentRunnerId -ne $recoveryPriorRunnerId) -or ($historyIds.Count -gt 1 -and $currentRunnerId -and $currentRunnerId -eq $latestHistoryId)
                $runnerStateReady = $demoGuestStatus -and ([string]$demoGuestStatus.state -in $readyStates)
                if ($runnerStateReady -and ([string]$demoGuestStatus.state -in @("RUNNING", "SUSPICIOUS", "VIRUS"))) {
                    $runnerStateReady = -not $runnerHeartbeatStale
                }

                if ($runnerIsPostRestart -and $runnerStateReady) {
                    $waitingForSandboxRecovery = $false
                    $recoveryWaitElapsedSeconds = 0
                    $demoReadySince = [System.Diagnostics.Stopwatch]::StartNew()
                    $remainingSeconds = 35
                    $lastLoggedRemaining = -1
                    $demoKnownClientIds = $currentDemoClientIds
                    $demoKnownSessionIds = $currentDemoSessionIds
                    Add-Content -Path $ReportFile -Value "[SANDBOX] Restarted guest reached a ready state; allowing $DemoLaunchSettleSeconds seconds for its visible state to settle before the 35-second demonstration timer."
                    Write-Host "[*] Restarted guest is ready. Waiting $DemoLaunchSettleSeconds seconds before the visible timer." -ForegroundColor Green
                    continue
                }

                $recoveryWaitElapsedSeconds++
                if ($recoveryWaitElapsedSeconds -ge $SandboxStartupTimeoutSeconds) {
                    $sandboxUnavailableDuringDemo = $true
                    if ($runStatus -notin @("SUSPICIOUS", "VIRUS")) { $runStatus = "INCONCLUSIVE"; $runReason = "Windows Sandbox did not report a ready post-restart guest within $SandboxStartupTimeoutSeconds seconds. The sample was not automatically relaunched." }
                    Add-Content -Path $ReportFile -Value "[SANDBOX] Recovery timeout; the restarted guest runner did not reach a ready state."
                    Write-Host "[!] Restarted Sandbox guest did not become ready; ending this item and continuing the queue." -ForegroundColor Red
                    break
                }
                if ($recoveryWaitElapsedSeconds -eq 1 -or $recoveryWaitElapsedSeconds % 30 -eq 0) {
                    Write-Host "[*] Waiting for the restarted guest runner ($recoveryWaitElapsedSeconds seconds)..." -ForegroundColor Yellow
                }
                $demoKnownClientIds = $currentDemoClientIds
                $demoKnownSessionIds = $currentDemoSessionIds
                Start-Sleep -Milliseconds 1000
                continue
            }

            if (-not $demoTimer) {
                $demoGuestState = if ($demoGuestStatus) { [string]$demoGuestStatus.state } else { "" }
                $demoLaunchCount = if ($demoGuestStatus) { [int]$demoGuestStatus.launched } else { 0 }
                if ($demoGuestState -eq "INSTALLING_RUNTIME" -or
                    ($demoGuestStatus -and [string]$demoGuestStatus.details -match "(?i)RUNTIME_REMEDIATION:")) {
                    $runtimeRetryRequired = $true
                }
                $requiredLaunchCount = if ($runtimeRetryRequired) { 2 } else { 1 }
                $postRebootReviewReady = ($sandboxRebootCount -gt 0) -and ($demoGuestState -in @("REBOOTED", "POST_REBOOT_COMPLETE"))
                $demoPayloadReady = $postRebootReviewReady -or (($demoGuestState -in @("RUNNING", "SUSPICIOUS", "VIRUS", "COMPLETED")) -and ($demoLaunchCount -ge $requiredLaunchCount))

                if ($demoPayloadReady) {
                    if (-not $demoReadySince) {
                        $demoReadySince = [System.Diagnostics.Stopwatch]::StartNew()
                        Add-Content -Path $ReportFile -Value "[SANDBOX] Payload launch is confirmed; allowing $DemoLaunchSettleSeconds seconds for the visible application/files to appear before starting the 35-second demonstration timer."
                        Write-Host "[*] Payload launch is confirmed. Giving $DemoLaunchSettleSeconds seconds for its window and files to appear before the visible timer." -ForegroundColor Green
                    }
                    if ($demoReadySince.Elapsed.TotalSeconds -ge $DemoLaunchSettleSeconds) {
                        $demoTimer = [System.Diagnostics.Stopwatch]::StartNew()
                        $demoReadySince = $null
                        $remainingSeconds = 35
                        $lastLoggedRemaining = -1
                        Add-Content -Path $ReportFile -Value "[SANDBOX] The $DemoLaunchSettleSeconds-second appearance grace ended; started the fixed 35-second demonstration timer."
                        Write-Host "[*] The visible 35-second demonstration starts now." -ForegroundColor Green
                    } else {
                        $demoKnownClientIds = $currentDemoClientIds
                        $demoKnownSessionIds = $currentDemoSessionIds
                        Start-Sleep -Milliseconds 1000
                        continue
                    }
                } elseif ($demoGuestState -in @("UNSUPPORTED", "ERROR")) {
                    $demoReadySince = $null
                    Add-Content -Path $ReportFile -Value "[SANDBOX] Guest setup ended in $demoGuestState before the demonstration readiness conditions were met; skipped the demonstration timer."
                    Write-Host "[!] Guest setup ended in $demoGuestState before the payload launch was confirmed; skipping the demonstration timer." -ForegroundColor Yellow
                    if ($deferredRuntimeSignalStatus) {
                        $runStatus = "INCONCLUSIVE"
                        $runReason = "Runtime setup failed before the required sample retry was confirmed: $($demoGuestStatus.details) Previously recorded behavior signal for manual review: $deferredRuntimeSignalReason"
                    }
                    break
                } else {
                    $demoReadySince = $null
                    $recoveryWaitElapsedSeconds++
                    if ($recoveryWaitElapsedSeconds -ge $SandboxStartupTimeoutSeconds) {
                        $sandboxUnavailableDuringDemo = $true
                        Add-Content -Path $ReportFile -Value "[SANDBOX] Guest did not report a ready state before the demonstration timeout."
                        Write-Host "[!] Guest did not become ready for the demonstration; continuing the queue." -ForegroundColor Yellow
                        break
                    }
                    Start-Sleep -Milliseconds 1000
                    continue
                }
            }

            $remainingMilliseconds = [Math]::Max(0, (35 * 1000) - $demoTimer.ElapsedMilliseconds)
            if ($remainingMilliseconds -le 0) { break }
            $remainingSeconds = [int][Math]::Ceiling($remainingMilliseconds / 1000.0)
            if (($remainingSeconds % 5 -eq 0 -or $remainingSeconds -eq 1) -and $remainingSeconds -ne $lastLoggedRemaining) {
                Write-Host "[*] Demonstration time remaining: $remainingSeconds seconds. The sample stays inside Windows Sandbox." -ForegroundColor Cyan
                $lastLoggedRemaining = $remainingSeconds
            }
            $demoKnownClientIds = $currentDemoClientIds
            $demoKnownSessionIds = $currentDemoSessionIds
            Start-Sleep -Milliseconds ([int][Math]::Min(1000, $remainingMilliseconds))
        }

        if ($demoTimer -and -not $sandboxUnavailableDuringDemo -and $demoTimer.ElapsedMilliseconds -ge (35 * 1000)) {
            $demonstrationElapsedSeconds = 35
            Add-Content -Path $ReportFile -Value "[SANDBOX] The fixed 35-second demonstration ended; shutting down Windows Sandbox immediately."
            Write-Host "[*] The 35-second demonstration is complete; shutting down Windows Sandbox now." -ForegroundColor Green
        }
    }

    Stop-HoneypotActivityMonitor

    if ($startedSandbox) {
        $sandboxClientIds = @(Get-WindowsSandboxProcesses |
            Where-Object { $_.Id -notin $existingClientIds } |
            Select-Object -ExpandProperty Id)
        if ($sandboxProcessId -and $sandboxProcessId -notin $sandboxClientIds) {
            $sandboxClientIds += $sandboxProcessId
        }

        $sandboxStopped = Stop-AnalysisSandbox -SessionId $sandboxSessionId -ClientProcessIds $sandboxClientIds
        if (-not $sandboxStopped) {
            $clientsStillOpen = @(Get-WindowsSandboxProcesses | Where-Object { $_.Id -in $sandboxClientIds })
            $sessionStillOpenNow = $false
            if ($sandboxSessionId -and $SandboxCliPath) {
                $sessionStillOpenNow = $sandboxSessionId -in @(Get-WindowsSandboxSessionIds)
            }
            if ($clientsStillOpen.Count -eq 0 -and -not $sessionStillOpenNow) {
                $sandboxStopped = $true
                Add-Content -Path $ReportFile -Value "[SANDBOX] Session had already exited; no live Sandbox client or session remained to stop."
                Write-Host "[*] Sandbox session has already exited. Finalizing this file and continuing the queue." -ForegroundColor DarkGray
            }
        }
        if ($sandboxStopped) {
            if ($sandboxUnavailableDuringDemo) {
                Add-Content -Path $ReportFile -Value "[SANDBOX] No live session remained after the recovery wait; continuing the queue."
            } elseif ($demonstrationElapsedSeconds -ge 35) {
                Add-Content -Path $ReportFile -Value "[SANDBOX] Completed the fixed 35-second demonstration interval after the latest ready state, then stopped."
            } else {
                Add-Content -Path $ReportFile -Value "[SANDBOX] Stopped after analysis."
            }
            Write-Host "[*] Sandbox closed. Finalizing this file, then continuing the queue." -ForegroundColor DarkGray
        }
        if (-not $sandboxStopped) {
            Write-Host "[!] Automatic Sandbox shutdown was not confirmed. Close this session manually; the queue will wait before processing the next file." -ForegroundColor Yellow
            do {
                Start-Sleep -Seconds 2
                $remainingClients = @(Get-WindowsSandboxProcesses |
                    Where-Object { $_.Id -in $sandboxClientIds })
                $sessionStillOpen = $false
                if ($sandboxSessionId -and $SandboxCliPath) {
                    $sessionStillOpen = $sandboxSessionId -in @(Get-WindowsSandboxSessionIds)
                }
                if ($remainingClients.Count -gt 0 -or $sessionStillOpen) {
                    Write-Host "[*] Waiting for the current Sandbox session to close..." -ForegroundColor DarkGray
                }
            } while ($remainingClients.Count -gt 0 -or $sessionStillOpen)
            Add-Content -Path $ReportFile -Value "[SANDBOX] Closed manually after automatic shutdown could not be confirmed."
        }
    }

    $verdictText = "[VERDICT] " + $runStatus + [Environment]::NewLine + "[DETAIL] " + $runReason
    Add-Content -Path $ReportFile -Value $verdictText

    if (-not $processingReady) {
        $SkippedQueuePaths[$sampleQueueKey] = $true
        Add-Content -Path $ReportFile -Value "[ACTION] Original file was left unchanged at $($sample.FullName)."
        Write-Host "[!] $runReason" -ForegroundColor Yellow
        Write-Host "[!] Original file left unchanged and skipped for this run: $($sample.FullName)" -ForegroundColor Yellow
    } elseif (-not (Test-Path -LiteralPath $sourcePath)) {
        Add-Content -Path $ReportFile -Value "[ACTION] Source file disappeared during analysis; check Windows Security Protection History or antivirus quarantine."
        Write-Host "[!] Source file disappeared during analysis. Check Windows Security Protection History or antivirus quarantine." -ForegroundColor Yellow
    } elseif ($runStatus -in @("SUSPICIOUS", "VIRUS")) {
        $threatDest = Join-Path $ThreatFilesFolder $originalName
        if (Test-Path -LiteralPath $threatDest) {
            $threatDest = Join-Path $ThreatFilesFolder "$(Get-Date -Format 'yyyyMMdd-HHmmss')_$originalName"
        }
        Write-Host "[!] THREAT DETECTED. Moving the sample to Threat_Files for review..." -ForegroundColor Red
        try {
            Move-Item -LiteralPath $sourcePath -Destination $threatDest -ErrorAction Stop
            Add-Content -Path $ReportFile -Value "[ACTION] Threat sample retained in Threat_Files for review at $threatDest. Do not open it outside Windows Sandbox."
            Write-Host "[!] Threat detected; file retained in Threat_Files: $threatDest" -ForegroundColor Red
        } catch {
            Add-Content -Path $ReportFile -Value "[ACTION] Could not move the threat sample to Threat_Files: $($_.Exception.Message). It remains at $sourcePath."
            Write-Host "[!] Could not move the threat sample; it remains at: $sourcePath" -ForegroundColor Red
        }
    } elseif ($runStatus -eq "NO DETECTION") {
        $finalDest = Join-Path $SafeFilesFolder $originalName
        try {
            Move-Item -LiteralPath $sourcePath -Destination $finalDest -Force -ErrorAction Stop
            Add-Content -Path $ReportFile -Value "[ACTION] No alert in the completed checks; file moved to $finalDest"
            Add-Content -Path $ReportFile -Value "[LIMIT] NO DETECTION is not proof that a file is safe. The verdict reflects VirusTotal's completed scan and the bounded Sandbox behavior observation."
            Write-Host "[+] No detections in completed checks. Moved to Safe_Files: $finalDest (this is not a guarantee of safety)." -ForegroundColor Green
        } catch {
            Add-Content -Path $ReportFile -Value "[ACTION] Could not move the file to Safe_Files: $($_.Exception.Message). It remains at $sourcePath."
            Write-Host "[!] Could not move the file; it remains at: $sourcePath" -ForegroundColor Yellow
        }
    } else {
        $reviewDest = Join-Path $ReviewFilesFolder "$originalName.processing"
        if (Test-Path -LiteralPath $reviewDest) {
            $reviewDest = Join-Path $ReviewFilesFolder "$(Get-Date -Format 'yyyyMMdd-HHmmss')_$originalName.processing"
        }
        try {
            Move-Item -LiteralPath $sourcePath -Destination $reviewDest -Force -ErrorAction Stop
            Add-Content -Path $ReportFile -Value "[ACTION] Inconclusive sample preserved for review at $reviewDest"
            Write-Host "[!] INCONCLUSIVE. Preserved for review: $reviewDest" -ForegroundColor Yellow
        } catch {
            Add-Content -Path $ReportFile -Value "[ACTION] File remains at $sourcePath. Could not move to review: $($_.Exception.Message)"
            Write-Host "[!] INCONCLUSIVE. File remains at: $sourcePath" -ForegroundColor Yellow
        }
    }

    Write-Host "[+] Item finished. Continuing the queue. Report: $ReportFile" -ForegroundColor Green
    Start-Sleep -Seconds 2
}
