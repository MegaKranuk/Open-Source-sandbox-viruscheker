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
$FlaggedFilesFolder = Join-Path $ReviewFilesFolder "Flagged"
$LegacyThreatFilesFolder = "$env:USERPROFILE\Desktop\Threat_Files"
$pipelineMutex = $null
$pipelineMutexOwned = $false
try {
    $pipelineMutex = [System.Threading.Mutex]::new($false, "Global\AutomatedMalwareAnalysisPipeline")
    try {
        $pipelineMutexOwned = $pipelineMutex.WaitOne(0)
    } catch [System.Threading.AbandonedMutexException] {
        $pipelineMutexOwned = $true
    }
} catch {
    Write-Host "[!] Could not acquire the machine-wide queue lock: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
if (-not $pipelineMutexOwned) {
    Write-Host "[!] The analysis queue is already running in another Windows session or window." -ForegroundColor Yellow
    exit 1
}

$QuarantineFolder = "C:\Quarantine_Zone"
$StagingParentFolder = $QuarantineFolder
$StagingFolder = $null
$PayloadFolder = $null
$QueueRecoveryFolder = Join-Path $QuarantineFolder "QueueRecovery"
$WritableShareMountPath = Join-Path $QuarantineFolder "RBI_WritableVolume"
$WritableShareVhdPath = Join-Path $QuarantineFolder "RBI_WritableVolume.vhdx"
$WritableShareVolumeLimitMiB = 256
$MinimumHostFreeSpaceAfterShareBytes = 1GB
$HoneypotFolder = Join-Path $WritableShareMountPath "Honeypot"
$TelemetryFolder = Join-Path $WritableShareMountPath "Telemetry"
$script:WritableShareVolumeReady = $false
$FeatureSourceFolder = "C:\RBI_FeatureSource"
$NetFx3SourceFolder = "C:\RBI_NetFx3Source"
$NetFx3SxsSourceFolder = Join-Path $NetFx3SourceFolder "sources\sxs"
try {
    New-Item -ItemType Directory -Force -Path @($FeatureSourceFolder, $NetFx3SxsSourceFolder) | Out-Null
} catch {
    Write-Host "[!] Could not create the optional runtime source folders: $($_.Exception.Message)" -ForegroundColor Yellow
}
$WsbFile = Join-Path -Path $PSScriptRoot -ChildPath "sandbox.wsb"
$SandboxRunnerFile = Join-Path -Path $PSScriptRoot -ChildPath "sandbox-runner.ps1"
$SandboxBootstrapFile = Join-Path -Path $PSScriptRoot -ChildPath "sandbox-bootstrap.cmd"
$ReportFile = Join-Path -Path $PSScriptRoot -ChildPath "analysis_report.txt"
$SandboxStartupTimeoutSeconds = 60
$SandboxSessionStartupQueryTimeoutMilliseconds = 15000
$SandboxRestartWindowGraceSeconds = 12
$SandboxRestartDetectionGraceSeconds = 45
$SandboxShutdownWaitSeconds = 30
$RuntimeSetupTimeoutSeconds = 900
$GuestObservationSeconds = 35
$MaxAnalysisSeconds = 180
$DemoLaunchSettleSeconds = 8
$DemoVisibleSeconds = 35
$MaxHoneypotFiles = 20000
$MaxHoneypotDirectories = 50000
$HoneypotScanTimeoutSeconds = 5
$MaxHoneypotHashBytes = 134217728
$MaxHoneypotHashFileBytes = 16777216
$SandboxCliCommand = Get-Command -Name "wsb.exe" -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
$SandboxCliPath = if ($SandboxCliCommand) { $SandboxCliCommand.Source } else { $null }
$script:SandboxSessionIdsCache = @()
$script:SandboxSessionQueryUtc = [DateTime]::MinValue
$script:SandboxSessionQueryValid = $false
$script:SandboxSessionQueryError = "Sandbox session state has not been queried."
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
$script:HoneypotRecentChanges = New-Object System.Collections.ArrayList
$script:HoneypotKnownDirectories = @{}
$script:HoneypotVirusBurstReason = $null
$script:HoneypotMonitorIncomplete = $false
$script:HoneypotMonitorIncompleteReported = $false
$QueueFileStabilitySeconds = 3
$QueueMsiQuietSeconds = 10
$QueueDownloadProgressIntervalSeconds = 5
$QueueDownloadReportIntervalSeconds = 30
$QueueScanSliceSeconds = 2
$QueueScanSliceEntries = 10000
$MaxQueueTraversalDepth = 256
$script:QueueTraversalStack = $null
$script:QueueDownloadActivity = @{}
$ReportRotationBytes = 10MB
$MaxSampleAnalysisBytes = 650MB
$script:QueueEnumerationWarningReported = $false
$IncompleteDownloadExtensions = @('.crdownload', '.part', '.partial', '.download', '.opdownload', '.filepart')

function Get-QueueFileKey {
    param ([System.IO.FileInfo]$File)

    return "{0}|{1}|{2}" -f $File.FullName, $File.Length, $File.LastWriteTimeUtc.Ticks
}

function Write-QueueEnumerationWarning {
    param ([string]$Message)

    if ([string]::IsNullOrWhiteSpace($Message) -or $script:QueueEnumerationWarningReported) { return }
    Write-Host "[!] Queue scan note: $Message" -ForegroundColor Yellow
    try { Add-Content -Path $ReportFile -Value "[QUEUE] $Message" } catch {}
    $script:QueueEnumerationWarningReported = $true
}

function Start-QueueTraversal {
    if (-not (Test-Path -LiteralPath $DownloadsFolder -PathType Container)) { return $false }
    try {
        $rootAttributes = [IO.File]::GetAttributes($DownloadsFolder)
        if (($rootAttributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Write-QueueEnumerationWarning -Message "Downloads is a directory link; it is not followed to avoid scanning outside the configured folder."
            return $false
        }
        $enumerator = [IO.Directory]::EnumerateFileSystemEntries($DownloadsFolder).GetEnumerator()
        $script:QueueTraversalStack = [System.Collections.Generic.Stack[object]]::new()
        $script:QueueTraversalStack.Push([pscustomobject]@{ Path = $DownloadsFolder; Depth = 0; Enumerator = $enumerator })
        return $true
    } catch {
        $script:QueueTraversalStack = $null
        Write-QueueEnumerationWarning -Message "Downloads could not be enumerated: $($_.Exception.Message)"
        return $false
    }
}

function Complete-QueueTraversal {
    $script:QueueTraversalStack = $null
}

function Test-QueueFileStable {
    param ([System.IO.FileInfo]$File)

    $nowUtc = [DateTime]::UtcNow
    if ($File.LastWriteTimeUtc -le $nowUtc -and ($nowUtc - $File.LastWriteTimeUtc).TotalSeconds -lt $QueueFileStabilitySeconds) { return $false }
    $stream = $null
    try {
        $stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        return $true
    } catch {
        return $false
    } finally {
        if ($stream) { $stream.Dispose() }
    }
}

function Update-MsiDownloadProgress {
    param (
        [System.IO.FileInfo]$File,
        [switch]$Partial
    )

    $partialExtension = [IO.Path]::GetExtension($File.Name).ToLowerInvariant()
    $targetName = if ($Partial) { $File.Name.Substring(0, $File.Name.Length - $partialExtension.Length) } else { $File.Name }
    if ([IO.Path]::GetExtension($targetName) -ine '.msi') { return $null }

    $pathKey = $File.FullName.ToLowerInvariant()
    $nowUtc = [DateTime]::UtcNow
    $state = $script:QueueDownloadActivity[$pathKey]
    if (-not $state) {
        $state = [pscustomobject]@{
            Path = $File.FullName
            StartedUtc = $nowUtc
            LastObservedUtc = $nowUtc
            LastChangedUtc = if ($File.LastWriteTimeUtc -le $nowUtc) { $File.LastWriteTimeUtc } else { $nowUtc }
            LastWriteTicks = $File.LastWriteTimeUtc.Ticks
            LastLength = [long]$File.Length
            LastGrowthBytes = [long]0
            LastGrowthRate = [double]0
            LastConsoleUtc = [DateTime]::MinValue
            LastReportUtc = [DateTime]::MinValue
            ReadyReported = $false
        }
        $script:QueueDownloadActivity[$pathKey] = $state
    } else {
        $sampleSeconds = [Math]::Max(0.25, ($nowUtc - $state.LastObservedUtc).TotalSeconds)
        $lengthDelta = [long]$File.Length - [long]$state.LastLength
        $writeChanged = $File.LastWriteTimeUtc.Ticks -ne $state.LastWriteTicks
        if ($lengthDelta -ne 0 -or $writeChanged) {
            $state.LastChangedUtc = $nowUtc
            $state.LastGrowthBytes = [Math]::Max([long]0, $lengthDelta)
            $state.LastGrowthRate = [Math]::Max(0.0, $lengthDelta / $sampleSeconds)
            $state.LastLength = [long]$File.Length
            $state.LastWriteTicks = $File.LastWriteTimeUtc.Ticks
            $state.ReadyReported = $false
        }
        $state.LastObservedUtc = $nowUtc
    }

    $quietSeconds = [Math]::Max(0.0, ($nowUtc - $state.LastChangedUtc).TotalSeconds)
    $sizeMiB = [Math]::Round(([long]$File.Length / 1MB), 2)
    $growthMiB = [Math]::Round(([long]$state.LastGrowthBytes / 1MB), 2)
    $rateMiB = [Math]::Round(([double]$state.LastGrowthRate / 1MB), 2)
    $targetLabel = if ($Partial) { $targetName } else { $File.Name }
    if ($Partial) {
        $progressText = "[DOWNLOAD] $targetLabel is downloading: progress is indeterminate because the expected total size is unavailable; $sizeMiB MiB received, last growth $([Math]::Floor($quietSeconds)) sec ago."
    } elseif ($state.LastGrowthBytes -gt 0 -and $quietSeconds -lt $QueueDownloadProgressIntervalSeconds) {
        $progressText = "[DOWNLOAD] $targetLabel is changing: progress is indeterminate because the expected total size is unavailable; $sizeMiB MiB received, +$growthMiB MiB at about $rateMiB MiB/sec."
    } else {
        $progressText = "[DOWNLOAD] Tracking ${targetLabel}: progress is indeterminate until the file is stable; $sizeMiB MiB present, no size change for $([Math]::Floor($quietSeconds)) sec."
    }

    if (($nowUtc - $state.LastConsoleUtc).TotalSeconds -ge $QueueDownloadProgressIntervalSeconds) {
        Write-Host $progressText -ForegroundColor Cyan
        $state.LastConsoleUtc = $nowUtc
    }
    if (($nowUtc - $state.LastReportUtc).TotalSeconds -ge $QueueDownloadReportIntervalSeconds) {
        try { Add-Content -Path $ReportFile -Value $progressText -ErrorAction Stop } catch {}
        $state.LastReportUtc = $nowUtc
    }

    return [pscustomobject]@{
        TargetName = $targetName
        IsPartial = [bool]$Partial
        QuietSeconds = $quietSeconds
        State = $state
    }
}

function Restore-InterruptedQueueFiles {
    if (-not (Test-Path -LiteralPath $QueueRecoveryFolder -PathType Container)) { return }
    $downloadsRoot = [IO.Path]::GetFullPath($DownloadsFolder).TrimEnd('\') + '\'
    foreach ($temporaryMarker in @(Get-ChildItem -LiteralPath $QueueRecoveryFolder -File -Filter '*.tmp' -Force -ErrorAction SilentlyContinue)) {
        try {
            if ($temporaryMarker.LastWriteTimeUtc -lt [DateTime]::UtcNow.AddDays(-1)) {
                Remove-Item -LiteralPath $temporaryMarker.FullName -Force -ErrorAction Stop
            }
        } catch {}
    }
    foreach ($marker in @(Get-ChildItem -LiteralPath $QueueRecoveryFolder -File -Filter '*.json' -Force -ErrorAction SilentlyContinue)) {
        try {
            $record = Get-Content -LiteralPath $marker.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            if ([int]$record.version -ne 1) { throw 'Unsupported recovery record version.' }
            $originalPath = [IO.Path]::GetFullPath([string]$record.originalPath)
            $processingPath = [IO.Path]::GetFullPath([string]$record.processingPath)
            if (-not $originalPath.StartsWith($downloadsRoot, [StringComparison]::OrdinalIgnoreCase) -or
                -not $processingPath.StartsWith($downloadsRoot, [StringComparison]::OrdinalIgnoreCase) -or
                -not $processingPath.Equals($originalPath + '.rbi-processing', [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Recovery record paths are outside Downloads or do not match the processing suffix.'
            }

            if (Test-Path -LiteralPath $processingPath -PathType Leaf) {
                $destination = $originalPath
                if (Test-Path -LiteralPath $destination) {
                    $parentFolder = Split-Path -Parent $originalPath
                    $originalName = Split-Path -Leaf $originalPath
                    $baseName = [IO.Path]::GetFileNameWithoutExtension($originalName)
                    $extension = [IO.Path]::GetExtension($originalName)
                    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
                    $destination = Join-Path $parentFolder ("{0}.recovered-{1}{2}" -f $baseName, $stamp, $extension)
                    $counter = 1
                    while (Test-Path -LiteralPath $destination) {
                        $destination = Join-Path $parentFolder ("{0}.recovered-{1}-{2}{3}" -f $baseName, $stamp, $counter, $extension)
                        $counter++
                    }
                }
                Move-Item -LiteralPath $processingPath -Destination $destination -ErrorAction Stop
                Write-Host "[*] Restored an interrupted queue item for analysis: $(Split-Path -Leaf $destination)" -ForegroundColor Yellow
            }
            Remove-Item -LiteralPath $marker.FullName -Force -ErrorAction Stop
        } catch {
            Write-Host "[!] Could not safely recover queue record '$($marker.Name)': $($_.Exception.Message). The file and record were preserved." -ForegroundColor Yellow
        }
    }
}

function New-QueueRecoveryMarker {
    param ([string]$OriginalPath, [string]$ProcessingPath)

    New-Item -ItemType Directory -Path $QueueRecoveryFolder -Force -ErrorAction Stop | Out-Null
    $markerPath = Join-Path $QueueRecoveryFolder ("{0}.json" -f [Guid]::NewGuid().ToString('N'))
    $temporaryPath = "$markerPath.tmp"
    $record = [ordered]@{
        version = 1
        originalPath = [IO.Path]::GetFullPath($OriginalPath)
        processingPath = [IO.Path]::GetFullPath($ProcessingPath)
        createdUtc = [DateTime]::UtcNow.ToString('o')
    }
    try {
        [IO.File]::WriteAllText($temporaryPath, ($record | ConvertTo-Json -Compress), (New-Object System.Text.UTF8Encoding($false)))
        [IO.File]::Move($temporaryPath, $markerPath)
        return $markerPath
    } finally {
        if ([IO.File]::Exists($temporaryPath)) { Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue }
    }
}

function Get-StableQueueSample {
    foreach ($trackedPath in @($script:QueueDownloadActivity.Keys)) {
        $trackedState = $script:QueueDownloadActivity[$trackedPath]
        if (-not (Test-Path -LiteralPath $trackedState.Path -PathType Leaf)) {
            $script:QueueDownloadActivity.Remove($trackedPath)
        }
    }

    if (-not $script:QueueTraversalStack -or $script:QueueTraversalStack.Count -eq 0) {
        if (-not (Start-QueueTraversal)) { return $null }
    }

    $scanTimer = [Diagnostics.Stopwatch]::StartNew()
    $entriesVisited = 0
    while ($script:QueueTraversalStack.Count -gt 0 -and
        $scanTimer.Elapsed.TotalSeconds -lt $QueueScanSliceSeconds -and
        $entriesVisited -lt $QueueScanSliceEntries) {
        $frame = $script:QueueTraversalStack.Peek()
        $entryPath = $null
        try {
            if (-not $frame.Enumerator.MoveNext()) {
                $frame.Enumerator.Dispose()
                $null = $script:QueueTraversalStack.Pop()
                if ($script:QueueTraversalStack.Count -eq 0) { Complete-QueueTraversal }
                continue
            }
            $entryPath = [string]$frame.Enumerator.Current
            $entriesVisited++
            $attributes = [IO.File]::GetAttributes($entryPath)
        } catch {
            Write-QueueEnumerationWarning -Message "A Downloads entry could not be inspected: $($_.Exception.Message)"
            if ($null -ne $entryPath) { continue }
            try { $frame.Enumerator.Dispose() } catch {}
            $null = $script:QueueTraversalStack.Pop()
            if ($script:QueueTraversalStack.Count -eq 0) { Complete-QueueTraversal }
            continue
        }

        if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Write-QueueEnumerationWarning -Message "A file or directory link under Downloads was skipped; links are not followed."
            continue
        }
        if (($attributes -band [IO.FileAttributes]::Directory) -ne 0) {
            if ($frame.Depth -ge $MaxQueueTraversalDepth) {
                Write-QueueEnumerationWarning -Message "A Downloads directory deeper than $MaxQueueTraversalDepth levels was skipped."
                continue
            }
            try {
                $childEnumerator = [IO.Directory]::EnumerateFileSystemEntries($entryPath).GetEnumerator()
                $script:QueueTraversalStack.Push([pscustomobject]@{ Path = $entryPath; Depth = ($frame.Depth + 1); Enumerator = $childEnumerator })
            } catch {
                Write-QueueEnumerationWarning -Message "A Downloads subfolder could not be scanned: $($_.Exception.Message)"
            }
            continue
        }

        $file = $null
        try { $file = Get-Item -LiteralPath $entryPath -Force -ErrorAction Stop } catch {
            Write-QueueEnumerationWarning -Message "A Downloads file could not be read: $($_.Exception.Message)"
            continue
        }
        if ($file.Name -match '(?i)\.rbi-processing$' -or $file.Name -match '(?i)^desktop\.ini$') { continue }

        $isPartialDownload = $file.Extension.ToLowerInvariant() -in $IncompleteDownloadExtensions
        $downloadProgress = Update-MsiDownloadProgress -File $file -Partial:$isPartialDownload
        if ($isPartialDownload) { continue }
        if ($downloadProgress -and $downloadProgress.QuietSeconds -lt $QueueMsiQuietSeconds) { continue }

        $queueKey = Get-QueueFileKey -File $file
        if ($script:SkippedQueuePaths.ContainsKey($queueKey)) { continue }
        if (Test-QueueFileStable -File $file) {
            if ($downloadProgress -and -not $downloadProgress.State.ReadyReported) {
                $readyMessage = "[DOWNLOAD] MSI download progress: 100% (download complete and stable): $($downloadProgress.TargetName) ($([Math]::Round(($file.Length / 1MB), 2)) MiB). Added as a separate analysis-queue item."
                Write-Host $readyMessage -ForegroundColor Green
                try { Add-Content -Path $ReportFile -Value $readyMessage -ErrorAction Stop } catch {}
                $downloadProgress.State.ReadyReported = $true
            }
            return $file
        }
    }

    return $null
}

function Test-ImageFileSignature {
    param (
        [string]$Path,
        [string]$Extension
    )

    $stream = $null
    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $header = New-Object byte[] 16
        $bytesRead = $stream.Read($header, 0, $header.Length)
    } catch {
        return $false
    } finally {
        if ($stream) { $stream.Dispose() }
    }

    switch ($Extension.ToLowerInvariant()) {
        { $_ -in '.jpg', '.jpeg', '.jpe', '.jfif' } {
            return ($bytesRead -ge 3 -and $header[0] -eq 0xFF -and $header[1] -eq 0xD8 -and $header[2] -eq 0xFF)
        }
        '.png' {
            return ($bytesRead -ge 8 -and $header[0] -eq 0x89 -and $header[1] -eq 0x50 -and $header[2] -eq 0x4E -and $header[3] -eq 0x47 -and $header[4] -eq 0x0D -and $header[5] -eq 0x0A -and $header[6] -eq 0x1A -and $header[7] -eq 0x0A)
        }
        '.gif' {
            return ($bytesRead -ge 6 -and [System.Text.Encoding]::ASCII.GetString($header, 0, 6) -in @('GIF87a', 'GIF89a'))
        }
        '.bmp' {
            return ($bytesRead -ge 2 -and $header[0] -eq 0x42 -and $header[1] -eq 0x4D)
        }
        '.webp' {
            return ($bytesRead -ge 12 -and [System.Text.Encoding]::ASCII.GetString($header, 0, 4) -eq 'RIFF' -and [System.Text.Encoding]::ASCII.GetString($header, 8, 4) -eq 'WEBP')
        }
        { $_ -in '.tif', '.tiff' } {
            $littleEndian = ($header[0] -eq 0x49 -and $header[1] -eq 0x49 -and (($header[2] -eq 0x2A -and $header[3] -eq 0x00) -or ($header[2] -eq 0x2B -and $header[3] -eq 0x00)))
            $bigEndian = ($header[0] -eq 0x4D -and $header[1] -eq 0x4D -and (($header[2] -eq 0x00 -and $header[3] -eq 0x2A) -or ($header[2] -eq 0x00 -and $header[3] -eq 0x2B)))
            return ($bytesRead -ge 4 -and ($littleEndian -or $bigEndian))
        }
        '.ico' {
            return ($bytesRead -ge 4 -and $header[0] -eq 0x00 -and $header[1] -eq 0x00 -and $header[2] -eq 0x01 -and $header[3] -eq 0x00)
        }
        { $_ -in '.avif', '.heic' } {
            if ($bytesRead -lt 12 -or [System.Text.Encoding]::ASCII.GetString($header, 4, 4) -ne 'ftyp') { return $false }
            $brand = [System.Text.Encoding]::ASCII.GetString($header, 8, 4)
            if ($Extension -ieq '.avif') { return $brand -in @('avif', 'avis') }
            return $brand -in @('heic', 'heix', 'hevc', 'hevx', 'mif1', 'msf1')
        }
        default { return $false }
    }
}

function Test-PeFileSignature {
    param ([string]$Path)

    $stream = $null
    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        if ($stream.Length -lt 64) { return $false }
        $header = New-Object byte[] 64
        if ($stream.Read($header, 0, $header.Length) -ne $header.Length -or $header[0] -ne 0x4D -or $header[1] -ne 0x5A) { return $false }
        $peOffset = [BitConverter]::ToInt32($header, 0x3C)
        if ($peOffset -lt 64 -or $peOffset -gt ($stream.Length - 4)) { return $false }
        $stream.Position = $peOffset
        $signature = New-Object byte[] 4
        return ($stream.Read($signature, 0, 4) -eq 4 -and [Text.Encoding]::ASCII.GetString($signature) -eq "PE`0`0")
    } catch {
        return $false
    } finally {
        if ($stream) { $stream.Dispose() }
    }
}

function New-AnalysisSandboxConfig {
    param (
        [bool]$EnableNetworking,
        [Parameter(Mandatory = $true)][string]$HostStagingFolder
    )

    $document = New-Object System.Xml.XmlDocument
    $document.Load($WsbFile)
    $networkNode = $document.SelectSingleNode('/Configuration/Networking')
    if (-not $networkNode) {
        throw "The Sandbox configuration has no Networking setting."
    }

    $sampleMapping = $document.SelectSingleNode("/Configuration/MappedFolders/MappedFolder[SandboxFolder='C:\Sample']")
    $sampleHostFolderNode = if ($sampleMapping) { $sampleMapping.SelectSingleNode('HostFolder') } else { $null }
    if (-not $sampleHostFolderNode) {
        throw "The Sandbox configuration has no C:\Sample staging mapping."
    }
    $sampleHostFolderNode.InnerText = $HostStagingFolder

    if ($EnableNetworking) {
        $networkNode.InnerText = "Enable"
        $logonCommandNode = $document.SelectSingleNode('/Configuration/LogonCommand/Command')
        if ($logonCommandNode -and $logonCommandNode.InnerText -notmatch '(?i)-AllowOnlineRuntimeInstall\b') {
            $logonCommandNode.InnerText = $logonCommandNode.InnerText.TrimEnd() + " -AllowOnlineRuntimeInstall"
        }
    } else {
        $networkNode.InnerText = "Disable"
    }

    $configPath = Join-Path ([IO.Path]::GetTempPath()) ("rbi-analysis-{0}.wsb" -f [Guid]::NewGuid().ToString("N"))
    $document.Save($configPath)
    return $configPath
}

function Move-FileToUniqueDestination {
    param (
        [string]$SourcePath,
        [string]$DestinationFolder,
        [string]$FileName
    )

    $extension = [IO.Path]::GetExtension($FileName)
    $baseName = [IO.Path]::GetFileNameWithoutExtension($FileName)
    for ($attempt = 0; $attempt -lt 8; $attempt++) {
        $candidateName = if ($attempt -eq 0) {
            $FileName
        } else {
            "{0}_{1}{2}" -f $baseName, [Guid]::NewGuid().ToString('N'), $extension
        }
        $candidatePath = Join-Path $DestinationFolder $candidateName
        if (Test-Path -LiteralPath $candidatePath) { continue }

        try {
            $null = Move-Item -LiteralPath $SourcePath -Destination $candidatePath -ErrorAction Stop
            return $candidatePath
        } catch {
            if (Test-Path -LiteralPath $candidatePath) { continue }
            throw
        }
    }

    throw "Could not reserve a unique destination for '$FileName'."
}

function Rotate-AnalysisReportIfNeeded {
    if (-not (Test-Path -LiteralPath $ReportFile -PathType Leaf)) { return }
    try {
        if ((Get-Item -LiteralPath $ReportFile -ErrorAction Stop).Length -lt $ReportRotationBytes) { return }
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $archivePath = Join-Path (Split-Path -Parent $ReportFile) ("analysis_report-{0}.txt" -f $stamp)
        if (Test-Path -LiteralPath $archivePath) {
            $archivePath = Join-Path (Split-Path -Parent $ReportFile) ("analysis_report-{0}-{1}.txt" -f $stamp, [Guid]::NewGuid().ToString('N'))
        }
        Move-Item -LiteralPath $ReportFile -Destination $archivePath -ErrorAction Stop
        Write-Host "[*] Rotated the analysis report to $archivePath (previous report reached 10 MB)." -ForegroundColor DarkGray
    } catch {
        Write-Host "[!] Could not rotate the analysis report: $($_.Exception.Message). The current report will be kept." -ForegroundColor Yellow
    }
}

function Invoke-DiskPartScript {
    param ([string[]]$Commands)

    $diskPartPath = Join-Path $env:SystemRoot "System32\diskpart.exe"
    if (-not (Test-Path -LiteralPath $diskPartPath -PathType Leaf)) { throw "DiskPart is unavailable at $diskPartPath." }
    $scriptPath = Join-Path ([IO.Path]::GetTempPath()) ("rbi-diskpart-{0}.txt" -f [Guid]::NewGuid().ToString("N"))
    $stdoutPath = "$scriptPath.out"
    $stderrPath = "$scriptPath.err"
    $process = $null
    try {
        [IO.File]::WriteAllLines($scriptPath, $Commands, [Text.Encoding]::ASCII)
        $process = Start-Process -FilePath $diskPartPath -ArgumentList "/s `"$scriptPath`"" -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -ErrorAction Stop
        if (-not $process.WaitForExit(120000)) {
            try { $process.Kill() } catch {}
            if (-not $process.WaitForExit(5000)) { throw "DiskPart did not exit after its 120-second timeout." }
            throw "DiskPart exceeded its 120-second timeout."
        }
        if ($process.ExitCode -ne 0) {
            $detail = if (Test-Path -LiteralPath $stderrPath) { [string](Get-Content -LiteralPath $stderrPath -Raw -ErrorAction SilentlyContinue) } else { "" }
            if (-not $detail -and (Test-Path -LiteralPath $stdoutPath)) { $detail = [string](Get-Content -LiteralPath $stdoutPath -Raw -ErrorAction SilentlyContinue) }
            $detail = ($detail -replace '[\r\n]+', ' ').Trim()
            if ($detail.Length -gt 400) { $detail = $detail.Substring(0, 400) }
            throw "DiskPart failed with exit code $($process.ExitCode). $detail"
        }
    } finally {
        if ($process) { $process.Dispose() }
        Remove-Item -LiteralPath $scriptPath, $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue
    }
}

function Initialize-WritableShareVolume {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "The writable Sandbox shares require an elevated session so the capped virtual disk can be attached."
    }
    $requiredStorageCommands = @('Get-DiskImage', 'Get-Disk', 'Get-Partition', 'Get-Volume', 'Add-PartitionAccessPath')
    $availableStorageCommands = @(Get-Command -Name $requiredStorageCommands -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name -Unique)
    if (@($requiredStorageCommands | Where-Object { $_ -notin $availableStorageCommands }).Count -gt 0) {
        throw "The Windows Storage cmdlets needed to verify the capped share volume are unavailable."
    }
    $hostDriveLetter = $QuarantineFolder.Substring(0, 1)
    $hostVolume = Get-Volume -DriveLetter $hostDriveLetter -ErrorAction Stop
    $minimumRequiredFreeBytes = ([long]$WritableShareVolumeLimitMiB * 1MB) + $MinimumHostFreeSpaceAfterShareBytes
    if ([long]$hostVolume.SizeRemaining -lt $minimumRequiredFreeBytes) {
        throw "The host drive needs at least $([Math]::Round($minimumRequiredFreeBytes / 1GB, 2)) GiB free before enabling writable Sandbox shares."
    }

    New-Item -ItemType Directory -Path $QuarantineFolder -Force -ErrorAction Stop | Out-Null
    New-Item -ItemType Directory -Path $WritableShareMountPath -Force -ErrorAction Stop | Out-Null
    $existingImage = Get-DiskImage -ImagePath $WritableShareVhdPath -ErrorAction SilentlyContinue
    if (-not $existingImage -and @(Get-ChildItem -LiteralPath $WritableShareMountPath -Force -ErrorAction Stop).Count -gt 0) {
        throw "The writable-share mount folder already contains files and is not a mounted volume; its contents were left untouched."
    }

    if (-not (Test-Path -LiteralPath $WritableShareVhdPath -PathType Leaf)) {
        $commands = @(
            "create vdisk file=`"$WritableShareVhdPath`" maximum=$WritableShareVolumeLimitMiB type=expandable",
            "select vdisk file=`"$WritableShareVhdPath`"",
            "attach vdisk",
            "create partition primary",
            "format fs=ntfs quick label=RBI_WRITABLE"
        )
        Invoke-DiskPartScript -Commands $commands
    } else {
        if (-not $existingImage) { throw "The existing writable-share VHD could not be inspected; it was left untouched." }
        if (-not $existingImage.Attached) {
            Invoke-DiskPartScript -Commands @(
                "select vdisk file=`"$WritableShareVhdPath`"",
                "attach vdisk"
            )
        }
    }

    $image = Get-DiskImage -ImagePath $WritableShareVhdPath -ErrorAction Stop
    if (-not $image.Attached) { throw "The capped writable-share VHD did not attach." }
    $disk = @($image | Get-Disk -ErrorAction Stop | Where-Object { -not $_.IsOffline -and -not $_.IsReadOnly }) | Select-Object -First 1
    if (-not $disk) { throw "The writable-share VHD has no online writable disk." }
    $partition = @($disk | Get-Partition -ErrorAction Stop | Where-Object { $_.PartitionNumber -eq 1 }) | Select-Object -First 1
    if (-not $partition) { throw "The writable-share VHD has no usable first partition." }
    $expectedMount = $WritableShareMountPath.TrimEnd('\')
    $hasExpectedMount = @($partition.AccessPaths | Where-Object { ([string]$_).TrimEnd('\') -ieq $expectedMount }).Count -gt 0
    if (-not $hasExpectedMount) {
        if (@(Get-ChildItem -LiteralPath $WritableShareMountPath -Force -ErrorAction Stop).Count -gt 0) {
            throw "The writable-share mount folder contains files and is not empty; its contents were left untouched."
        }
        Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber -AccessPath $expectedMount -ErrorAction Stop | Out-Null
        $partition = Get-Partition -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber -ErrorAction Stop
    }
    if (@($partition.AccessPaths | Where-Object { ([string]$_).TrimEnd('\') -ieq $expectedMount }).Count -eq 0) {
        throw "The writable-share volume is not mounted at $WritableShareMountPath."
    }

    $volume = $partition | Get-Volume -ErrorAction Stop
    $maximumBytes = [long]$WritableShareVolumeLimitMiB * 1MB
    if ($volume.FileSystem -ne 'NTFS' -or
        $volume.FileSystemLabel -ne 'RBI_WRITABLE' -or
        [long]$disk.Size -gt ($maximumBytes + 1MB) -or
        [long]$partition.Size -gt ($maximumBytes + 1MB)) {
        throw "The writable-share VHD does not match the expected NTFS label and $WritableShareVolumeLimitMiB MiB size limit."
    }
    New-Item -ItemType Directory -Path @($HoneypotFolder, $TelemetryFolder) -Force -ErrorAction Stop | Out-Null
    Write-Host "[*] Writable Sandbox shares are confined to a $WritableShareVolumeLimitMiB MiB virtual disk." -ForegroundColor DarkGray
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

if (-Not (Test-Path $SandboxBootstrapFile)) {
    Write-Host "ERROR: File sandbox-bootstrap.cmd not found!" -ForegroundColor Red
    Start-Sleep -Seconds 10
    exit
}

if (-Not (Test-Path $SafeFilesFolder)) {
    New-Item -ItemType Directory -Force -Path $SafeFilesFolder | Out-Null
}

if (-Not (Test-Path $ReviewFilesFolder)) {
    New-Item -ItemType Directory -Force -Path $ReviewFilesFolder | Out-Null
}
New-Item -ItemType Directory -Force -Path $FlaggedFilesFolder | Out-Null
New-Item -ItemType Directory -Force -Path $QueueRecoveryFolder | Out-Null

try {
    Initialize-WritableShareVolume
    $script:WritableShareVolumeReady = $true
} catch {
    $script:WritableShareVolumeReady = $false
    Write-Host "[!] Writable Sandbox shares are unavailable; dynamic sample execution will be skipped. $($_.Exception.Message)" -ForegroundColor Yellow
}

if (Test-Path -LiteralPath $LegacyThreatFilesFolder) {
    try {
        $legacyDestination = Join-Path $FlaggedFilesFolder "Legacy_Threat_Files"
        if (Test-Path -LiteralPath $legacyDestination) {
            $legacyDestination = Join-Path $FlaggedFilesFolder ("Legacy_Threat_Files_{0}" -f [Guid]::NewGuid().ToString('N'))
        }
        Move-Item -LiteralPath $LegacyThreatFilesFolder -Destination $legacyDestination -ErrorAction Stop
        Write-Host "[*] Preserved the old Threat_Files contents in the flagged review folder: $legacyDestination" -ForegroundColor DarkGray
    } catch {
        Write-Host "[!] Could not move the old Threat_Files folder to review; its contents were left untouched: $($_.Exception.Message)" -ForegroundColor Yellow
    }
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

    if ($ApiKey -match '["\r\n]') {
        return [pscustomobject]@{ Success = $false; HttpCode = 0; Json = $null; Error = "VirusTotal API key contains unsupported characters." }
    }

    if ($Method -eq "POST") {
        if (-not $FilePath -or -not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
            return [pscustomobject]@{ Success = $false; HttpCode = 0; Json = $null; Error = "VirusTotal upload file is unavailable." }
        }
        $httpClient = $null
        $fileStream = $null
        $fileContent = $null
        $multipart = $null
        $response = $null
        try {
            Add-Type -AssemblyName System.Net.Http -ErrorAction Stop
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            $httpClient = New-Object System.Net.Http.HttpClient
            $httpClient.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
            $httpClient.DefaultRequestHeaders.Add("x-apikey", $ApiKey)
            $safeUploadName = if ($UploadFileName) { [IO.Path]::GetFileName($UploadFileName) -replace '[^A-Za-z0-9._ -]', '_' } else { [IO.Path]::GetFileName($FilePath) -replace '[^A-Za-z0-9._ -]', '_' }
            $fileStream = [IO.File]::Open($FilePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
            $fileContent = New-Object System.Net.Http.StreamContent($fileStream)
            $fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse("application/octet-stream")
            $multipart = New-Object System.Net.Http.MultipartFormDataContent
            $multipart.Add($fileContent, "file", $safeUploadName)
            $response = $httpClient.PostAsync($Url, $multipart).GetAwaiter().GetResult()
            $httpCode = [int]$response.StatusCode
            $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            $json = $null
            if (-not [string]::IsNullOrWhiteSpace($body)) {
                try { $json = $body | ConvertFrom-Json -ErrorAction Stop } catch {}
            }
            $errorText = if ($json.error.message) { [string]$json.error.message } elseif ($json.error.code) { [string]$json.error.code } else { "HTTP $httpCode" }
            $success = ($httpCode -ge 200) -and ($httpCode -lt 300) -and ($null -ne $json)
            return [pscustomobject]@{ Success = $success; HttpCode = $httpCode; Json = $json; Error = $errorText }
        } catch {
            $diagnostic = ([string]$_.Exception.Message).Replace($ApiKey, "[redacted]")
            if ($diagnostic.Length -gt 350) { $diagnostic = $diagnostic.Substring(0, 350) }
            return [pscustomobject]@{ Success = $false; HttpCode = 0; Json = $null; Error = "VirusTotal upload failed. Details: $diagnostic" }
        } finally {
            if ($response) { $response.Dispose() }
            if ($multipart) { $multipart.Dispose() }
            if ($fileContent -and -not $multipart) { $fileContent.Dispose() }
            if ($fileStream) { $fileStream.Dispose() }
            if ($httpClient) { $httpClient.Dispose() }
        }
    }

    $curlExe = Join-Path $env:SystemRoot "System32\curl.exe"
    if (-not (Test-Path -LiteralPath $curlExe)) {
        return [pscustomobject]@{ Success = $false; HttpCode = 0; Json = $null; Error = "Windows curl.exe is unavailable for VirusTotal lookups." }
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
        CoverageSufficient = ($coveragePercent -ge 80)
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
                if ($cached -and $cachedIsFresh) {
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

                    $uploadResult = Invoke-VirusTotalRequest -ApiKey $apiKey -Url $uploadEndpoint -Method "POST" -FilePath $FilePath -UploadFileName ([IO.Path]::GetFileName($FilePath) -replace '\.rbi-processing$', '') -TimeoutSeconds 300
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
        Write-Host "[!] VirusTotal returned a report with low engine coverage ($($result.CoveragePercent)% classified). It cannot support a NO DETECTION verdict." -ForegroundColor Yellow
    } else {
        Write-Host "[!] VirusTotal is not conclusive ($($result.Status)); the sample cannot be moved to Safe_Files. $($result.Error)" -ForegroundColor Yellow
    }
    return $result
}

function Get-BoundedHoneypotInventory {
    param (
        [int]$MaxFiles = $MaxHoneypotFiles,
        [int]$MaxDirectories = $MaxHoneypotDirectories,
        [DateTime]$DeadlineUtc,
        [switch]$IncludeDirectories
    )

    $files = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    $directories = [System.Collections.Generic.List[string]]::new()
    $pending = [System.Collections.Generic.Stack[object]]::new()
    $directoriesVisited = 1
    $truncatedReason = $null
    $entriesVisited = 0
    $maximumEntries = $MaxFiles + $MaxDirectories
    try {
        $rootAttributes = [IO.File]::GetAttributes($HoneypotFolder)
        if (($rootAttributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'The honeypot root is a directory link and was not followed.'
        }
        if ($IncludeDirectories) { $directories.Add($HoneypotFolder) }
        $pending.Push([pscustomobject]@{
            Path = $HoneypotFolder
            Depth = 0
            Enumerator = [IO.Directory]::EnumerateFileSystemEntries($HoneypotFolder).GetEnumerator()
        })
    } catch {
        return [pscustomobject]@{ Files = @(); Directories = @(); EntriesVisited = 0; TruncatedReason = "Could not open the honeypot root: $($_.Exception.Message)" }
    }

    while ($pending.Count -gt 0) {
        if ([DateTime]::UtcNow -ge $DeadlineUtc) {
            $truncatedReason = "Host honeypot inventory exceeded its $HoneypotScanTimeoutSeconds-second time limit."
            break
        }
        if ($entriesVisited -ge $maximumEntries) {
            $truncatedReason = "Host honeypot inventory exceeded its bounded entry limit."
            break
        }

        $frame = $pending.Peek()
        $entryPath = $null
        try {
            if (-not $frame.Enumerator.MoveNext()) {
                $frame.Enumerator.Dispose()
                $null = $pending.Pop()
                continue
            }
            $entryPath = [string]$frame.Enumerator.Current
            $entriesVisited++
            $attributes = [IO.File]::GetAttributes($entryPath)
        } catch {
            if (-not $truncatedReason) { $truncatedReason = "Host could not inspect a honeypot entry: $($_.Exception.Message)" }
            if ($null -ne $entryPath) { continue }
            try { $frame.Enumerator.Dispose() } catch {}
            $null = $pending.Pop()
            continue
        }

        if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            if (-not $truncatedReason) { $truncatedReason = 'Host honeypot inventory encountered a file or directory link and did not follow it.' }
            continue
        }
        if (($attributes -band [IO.FileAttributes]::Directory) -ne 0) {
            if ($directoriesVisited -ge $MaxDirectories) {
                $truncatedReason = "Host honeypot inventory exceeded its $MaxHoneypotDirectories-directory limit."
                break
            }
            $directoriesVisited++
            if ($IncludeDirectories) { $directories.Add($entryPath) }
            if ($frame.Depth -ge 256) {
                if (-not $truncatedReason) { $truncatedReason = 'Host honeypot inventory exceeded 256 directory levels.' }
                continue
            }
            try {
                $pending.Push([pscustomobject]@{
                    Path = $entryPath
                    Depth = ($frame.Depth + 1)
                    Enumerator = [IO.Directory]::EnumerateFileSystemEntries($entryPath).GetEnumerator()
                })
            } catch {
                if (-not $truncatedReason) { $truncatedReason = "Host could not scan a honeypot subfolder: $($_.Exception.Message)" }
            }
            continue
        }

        if ($files.Count -ge $MaxFiles) {
            $truncatedReason = "Host honeypot inventory exceeded its $MaxHoneypotFiles-file limit."
            break
        }
        try {
            $files.Add([IO.FileInfo]::new($entryPath))
        } catch {
            if (-not $truncatedReason) { $truncatedReason = "Host could not read honeypot file metadata: $($_.Exception.Message)" }
        }
    }

    foreach ($frame in $pending) { try { $frame.Enumerator.Dispose() } catch {} }
    return [pscustomobject]@{
        Files = $files.ToArray()
        Directories = $directories.ToArray()
        EntriesVisited = $entriesVisited
        TruncatedReason = $truncatedReason
    }
}

function Get-HoneypotSnapshot {
    $snapshot = @{}
    $deadlineUtc = [DateTime]::UtcNow.AddSeconds($HoneypotScanTimeoutSeconds)
    $inventory = Get-BoundedHoneypotInventory -DeadlineUtc $deadlineUtc
    if ($inventory.TruncatedReason) {
        $script:HoneypotMonitorIncomplete = $true
        $script:HoneypotMonitorIncompleteReason = "Host honeypot baseline coverage is incomplete. $($inventory.TruncatedReason)"
    }

    $hashedBytes = [long]0
    foreach ($file in $inventory.Files) {
        if ([DateTime]::UtcNow -ge $deadlineUtc) {
            $script:HoneypotMonitorIncomplete = $true
            if (-not $script:HoneypotMonitorIncompleteReason) { $script:HoneypotMonitorIncompleteReason = 'Host honeypot hashing exceeded its time limit.' }
            break
        }
        if ($file.Length -gt $MaxHoneypotHashFileBytes -or $hashedBytes -gt ($MaxHoneypotHashBytes - $file.Length)) {
            $script:HoneypotMonitorIncomplete = $true
            if (-not $script:HoneypotMonitorIncompleteReason) { $script:HoneypotMonitorIncompleteReason = 'Host honeypot hashing exceeded its per-file or aggregate byte limit.' }
            continue
        }
        try {
            $snapshot[$file.FullName] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
            $hashedBytes += $file.Length
        } catch {
            $script:HoneypotMonitorIncomplete = $true
            if (-not $script:HoneypotMonitorIncompleteReason) {
                $script:HoneypotMonitorIncompleteReason = "Host could not read a honeypot file while collecting the baseline: $($file.FullName). $($_.Exception.Message)"
            }
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
    $knownDirectories[$HoneypotFolder.ToLowerInvariant()] = $true
    $deadlineUtc = [DateTime]::UtcNow.AddSeconds($HoneypotScanTimeoutSeconds)
    $inventory = Get-BoundedHoneypotInventory -DeadlineUtc $deadlineUtc -IncludeDirectories
    if ($inventory.TruncatedReason) {
        $script:HoneypotMonitorIncomplete = $true
        if (-not $script:HoneypotMonitorIncompleteReason) {
            $script:HoneypotMonitorIncompleteReason = "Host could not enumerate every honeypot directory before monitoring. $($inventory.TruncatedReason)"
        }
    }
    foreach ($directory in $inventory.Directories) { $knownDirectories[$directory.ToLowerInvariant()] = $true }
    $script:HoneypotKnownDirectories = $knownDirectories
    $script:HoneypotRecentChanges = New-Object System.Collections.ArrayList
    $script:HoneypotVirusBurstReason = $null

    $sourceIds = @()
    try {
        foreach ($eventName in @("Created", "Changed", "Deleted", "Renamed", "Error")) {
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
    $script:HoneypotRecentChanges = New-Object System.Collections.ArrayList
    $script:HoneypotKnownDirectories = @{}
}

function Get-HoneypotFileBurstSignal {
    if ($script:HoneypotVirusBurstReason) { return $script:HoneypotVirusBurstReason }

    foreach ($sourceId in @($script:HoneypotEventSourceIds)) {
        $queuedEvents = @(Get-Event -SourceIdentifier $sourceId -ErrorAction SilentlyContinue | Select-Object -First 50001)
        if ($queuedEvents.Count -gt 50000) {
            $script:HoneypotMonitorIncomplete = $true
            $script:HoneypotMonitorIncompleteReason = "The host honeypot event queue exceeded its 50,000-event processing limit; some changes may have been delayed or missed."
            $queuedEvents = @($queuedEvents | Select-Object -First 50000)
        }
        foreach ($queuedEvent in $queuedEvents) {
            $eventArgs = $queuedEvent.SourceEventArgs
            $eventTime = $queuedEvent.TimeGenerated.ToUniversalTime()
            if ($eventArgs -is [System.IO.ErrorEventArgs]) {
                $script:HoneypotMonitorIncomplete = $true
                try { $watcherError = $eventArgs.GetException().Message } catch { $watcherError = "The file-system event buffer overflowed or reported an unknown error." }
                $script:HoneypotMonitorIncompleteReason = "Host honeypot monitoring reported an event-buffer or watcher error: $watcherError"
                Remove-Event -EventIdentifier $queuedEvent.EventIdentifier -ErrorAction SilentlyContinue
                continue
            }
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
                if ($script:HoneypotRecentChanges.Count -ge 50000) {
                    $script:HoneypotMonitorIncomplete = $true
                    $script:HoneypotMonitorIncompleteReason = "Host honeypot monitoring exceeded its 50,000-event memory limit; some changes may not have been counted."
                    $script:HoneypotRecentChanges.RemoveRange(0, 25000)
                }
                [void]$script:HoneypotRecentChanges.Add([pscustomobject]@{ Path = $normalizedPath; At = $eventTime })
            }
            Remove-Event -EventIdentifier $queuedEvent.EventIdentifier -ErrorAction SilentlyContinue
        }
    }

    $now = [DateTime]::UtcNow
    $oldestRetained = $now.AddSeconds(-5)
    $events = @($script:HoneypotRecentChanges | Where-Object { $_.At -ge $oldestRetained } | Sort-Object At)
    $script:HoneypotRecentChanges = New-Object System.Collections.ArrayList
    foreach ($retainedEvent in $events) { [void]$script:HoneypotRecentChanges.Add($retainedEvent) }

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

        if ($pathCounts.Count -ge 200) {
            $script:HoneypotVirusBurstReason = "SUSPICIOUS: File-bomber/spammer burst detected: at least 200 distinct files changed within one second ($($pathCounts.Count) files)."
            return $script:HoneypotVirusBurstReason
        }
        if ($pathCounts.Count -gt 10) {
            return "SUSPICIOUS: More than 10 distinct files changed within one second ($($pathCounts.Count) files); rapid mass file modification can be consistent with ransomware or a file-bomber but is not proof of malware."
        }
    }

    return $null
}

function Get-HoneypotSignal {
    param ([hashtable]$Baseline)

    $deadlineUtc = [DateTime]::UtcNow.AddSeconds($HoneypotScanTimeoutSeconds)
    $inventory = Get-BoundedHoneypotInventory -DeadlineUtc $deadlineUtc
    if ($inventory.TruncatedReason) {
        $script:HoneypotMonitorIncomplete = $true
        if (-not $script:HoneypotMonitorIncompleteReason) {
            $script:HoneypotMonitorIncompleteReason = "Host could not enumerate every honeypot file during behavior monitoring. $($inventory.TruncatedReason)"
        }
    }
    $files = @($inventory.Files)

    $artifacts = @($files | Where-Object {
        $_.Name -match "(?i)(read.?me|decrypt|recover|restore|how.?to|ransom|help)" -or
        $_.Extension -match "(?i)^\.(lock|locked|encrypted|crypted|crypto|wnry|wncry|fun|pay|demons)$"
    })
    $noteArtifacts = @($files | Where-Object { $_.Name -match "(?i)(read.?me|decrypt|recover|restore|how.?to|ransom|help)" })
    $encryptedArtifacts = @($files | Where-Object { $_.Extension -match "(?i)^\.(lock|locked|encrypted|crypted|crypto|wnry|wncry|fun|pay|demons)$" })
    $knownRansomwareArtifacts = @($files | Where-Object { $_.Extension -match "(?i)^\.(wnry|wncry)$" })
    if (($noteArtifacts.Count -gt 0 -and $encryptedArtifacts.Count -gt 0) -or $knownRansomwareArtifacts.Count -ge 2) {
        $noteName = if ($noteArtifacts.Count -gt 0) { $noteArtifacts[0].Name } else { "multiple .WNCRY/.WNRY files" }
        $markerName = if ($encryptedArtifacts.Count -gt 0) { $encryptedArtifacts[0].Name } else { $knownRansomwareArtifacts[0].Name }
        return "VIRUS: Ransomware behavior confirmed by a ransom-note artifact ($noteName) and encrypted-file marker ($markerName)."
    }
    if ($artifacts.Count -gt 0) {
        return "Ransom note or encrypted-file marker found in the honeypot: $($artifacts[0].Name)"
    }

    $burstSignal = Get-HoneypotFileBurstSignal
    if ($burstSignal) { return $burstSignal }

    $hashedBytes = [long]0
    foreach ($path in $Baseline.Keys) {
        if ([DateTime]::UtcNow -ge $deadlineUtc) {
            $script:HoneypotMonitorIncomplete = $true
            if (-not $script:HoneypotMonitorIncompleteReason) { $script:HoneypotMonitorIncompleteReason = 'Host honeypot behavior hashing exceeded its time limit.' }
            break
        }
        if (-not (Test-Path -LiteralPath $path)) {
            return "A honeypot canary file was deleted: $(Split-Path -Leaf $path)"
        }

        try {
            $fileInfo = Get-Item -LiteralPath $path -ErrorAction Stop
            if ($fileInfo.Length -gt $MaxHoneypotHashFileBytes -or $hashedBytes -gt ($MaxHoneypotHashBytes - $fileInfo.Length)) {
                $script:HoneypotMonitorIncomplete = $true
                if (-not $script:HoneypotMonitorIncompleteReason) { $script:HoneypotMonitorIncompleteReason = 'Host honeypot behavior hashing exceeded its per-file or aggregate byte limit.' }
                continue
            }
            $currentHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
            $hashedBytes += $fileInfo.Length
        } catch {
            $script:HoneypotMonitorIncomplete = $true
            if (-not $script:HoneypotMonitorIncompleteReason) {
                $script:HoneypotMonitorIncompleteReason = "Host could not read a honeypot canary during behavior monitoring: $(Split-Path -Leaf $path). $($_.Exception.Message)"
            }
            continue
        }
        if ($currentHash -ne $Baseline[$path]) {
            return "A honeypot canary file was modified: $(Split-Path -Leaf $path)"
        }
    }

    return $null
}

function Get-RunnerStatus {
    $statusPath = Join-Path $TelemetryFolder "runner-status.json"
    try {
        if (-not (Test-Path -LiteralPath $statusPath -ErrorAction Stop)) { return $null }
        return Get-Content -LiteralPath $statusPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return $null
    }
}

function Get-SandboxBootstrapLogText {
    $logPath = Join-Path $TelemetryFolder "runner-bootstrap.log"
    try {
        if (-not (Test-Path -LiteralPath $logPath -ErrorAction Stop)) { return "" }
        $lines = @(Get-Content -LiteralPath $logPath -Tail 60 -ErrorAction Stop)
        return (($lines | ForEach-Object {
            $line = ([string]$_ -replace '[\r\n]+', ' ').Trim()
            if ($line.Length -gt 1000) { $line = $line.Substring(0, 1000) + "..." }
            $line
        }) -join [Environment]::NewLine)
    } catch {
        return "Could not read runner-bootstrap.log: $($_.Exception.Message)"
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
        [switch]$Force,
        [switch]$ReturnRelatedDetections
    )

    $matchingDetections = @()
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

        if ($isRelatedToCurrentSample) {
            $matchingDetections += [pscustomobject]@{
                ThreatName = if ($detection.ThreatName) { [string]$detection.ThreatName } else { "Threat ID $($detection.ThreatID)" }
                ActionSuccess = $detection.ActionSuccess
                ResourcePaths = @($resourcePaths)
            }
        }

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

    if ($ReturnRelatedDetections) { return $matchingDetections }
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
    $restartReasons = New-Object System.Collections.Generic.List[string]

    $bootstrapLogPath = Join-Path $TelemetryFolder "runner-bootstrap.log"
    $bootstrapStartCount = 0
    if (Test-Path -LiteralPath $bootstrapLogPath) {
        try {
            $bootstrapStartCount = @(Get-Content -LiteralPath $bootstrapLogPath -ErrorAction Stop | Where-Object {
                ([string]$_) -match '^\s*\[BOOTSTRAP\]\s+Started at\s+'
            }).Count
        } catch {}
    }
    if ($script:GuestBootstrapStartCount -gt 0 -and $bootstrapStartCount -gt $script:GuestBootstrapStartCount) {
        [void]$restartReasons.Add("guest bootstrap logon command started again ($bootstrapStartCount starts recorded)")
    } elseif ($script:GuestBootstrapStartCount -le 0 -and $bootstrapStartCount -gt 1) {
        [void]$restartReasons.Add("guest bootstrap logon command has multiple starts recorded ($bootstrapStartCount)")
    }
    if ($bootstrapStartCount -gt $script:GuestBootstrapStartCount) {
        $script:GuestBootstrapStartCount = $bootstrapStartCount
    }

    if (($priorIds.Count -gt 0) -and ($newIds.Count -gt 0)) {
        [void]$restartReasons.Add("runner-start history contains a new instance ID")
    } elseif (($priorIds.Count -eq 0) -and (@($currentIds | Select-Object -Unique).Count -gt 1)) {
        [void]$restartReasons.Add("runner-start history contains multiple instance IDs")
    }
    if ($instanceId -and $script:GuestRunnerInstanceId -and $instanceId -ne $script:GuestRunnerInstanceId) {
        [void]$restartReasons.Add("runner-status instance ID changed")
    }

    $script:GuestRunnerHistoryInstanceIds = @(@($priorIds + $currentIds) | Select-Object -Unique)
    if ($instanceId) { $script:GuestRunnerInstanceId = $instanceId }
    if ($state) { $script:LastGuestRunnerState = $state }
    if ($restartReasons.Count -gt 0) { return ($restartReasons -join "; ") }
    return $null
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
    param (
        [switch]$ForceRefresh,
        [int]$TimeoutMilliseconds = 5000
    )

    if (-not $SandboxCliPath) {
        $script:SandboxSessionQueryValid = $false
        $script:SandboxSessionQueryError = "wsb.exe is unavailable; Sandbox sessions cannot be enumerated."
        return @()
    }
    if (-not $ForceRefresh -and $script:SandboxSessionQueryUtc -ne [DateTime]::MinValue -and
        ([DateTime]::UtcNow - $script:SandboxSessionQueryUtc).TotalSeconds -lt 3) {
        return @($script:SandboxSessionIdsCache)
    }
    $listProcess = $null
    $stdoutTask = $null
    $stderrTask = $null
    $queryStage = "process startup"
    try {
        $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processStartInfo.FileName = $SandboxCliPath
        $processStartInfo.Arguments = "list --raw"
        $processStartInfo.UseShellExecute = $false
        $processStartInfo.CreateNoWindow = $true
        $processStartInfo.RedirectStandardOutput = $true
        $processStartInfo.RedirectStandardError = $true
        $listProcess = New-Object System.Diagnostics.Process
        $listProcess.StartInfo = $processStartInfo
        if (-not $listProcess.Start()) {
            throw "Process.Start did not start wsb.exe."
        }
        $stdoutTask = $listProcess.StandardOutput.ReadToEndAsync()
        $stderrTask = $listProcess.StandardError.ReadToEndAsync()
        $queryStage = "waiting for wsb.exe"
        if (-not $listProcess.WaitForExit($TimeoutMilliseconds)) {
            try { $listProcess.Kill(); $listProcess.WaitForExit() } catch {}
            $script:SandboxSessionQueryValid = $false
            $script:SandboxSessionQueryError = "wsb.exe list --raw timed out after $([Math]::Ceiling($TimeoutMilliseconds / 1000.0)) seconds."
            $script:SandboxSessionQueryUtc = [DateTime]::UtcNow
            return @()
        }
        $listProcess.WaitForExit()
        $queryStage = "reading wsb.exe output"
        $rawText = if ($stdoutTask) { [string]$stdoutTask.GetAwaiter().GetResult() } else { "" }
        $stderrText = if ($stderrTask) { [string]$stderrTask.GetAwaiter().GetResult() } else { "" }
        if ([string]::IsNullOrWhiteSpace($rawText)) {
            $script:SandboxSessionQueryValid = $false
            $stderrText = $stderrText.Trim()
            if ($stderrText.Length -gt 300) { $stderrText = $stderrText.Substring(0, 300) }
            $script:SandboxSessionQueryError = if ($stderrText) { "wsb.exe list --raw returned no session data: $stderrText" } else { "wsb.exe list --raw returned no session data." }
            $script:SandboxSessionQueryUtc = [DateTime]::UtcNow
            return @()
        }
        if ($listProcess.ExitCode -ne 0) {
            $script:SandboxSessionQueryValid = $false
            $stderrText = $stderrText.Trim()
            if ($stderrText.Length -gt 300) { $stderrText = $stderrText.Substring(0, 300) }
            $script:SandboxSessionQueryError = if ($stderrText) { "wsb.exe list --raw returned exit code $($listProcess.ExitCode): $stderrText" } else { "wsb.exe list --raw returned exit code $($listProcess.ExitCode)." }
            $script:SandboxSessionQueryUtc = [DateTime]::UtcNow
            return @()
        }
        $queryStage = "parsing wsb.exe JSON"
        $document = $rawText | ConvertFrom-Json -ErrorAction Stop
        $queryStage = "extracting Sandbox session IDs"
        $records = @(Get-WindowsSandboxSessionRecords -InputObject $document)
        $sessionListShapeRecognized = ($rawText -match '^\s*\[') -or ($rawText -match '(?i)"(sessions?|sandboxes?|items|data|instances?|windowsSandboxEnvironments)"\s*:')
        if ($records.Count -eq 0 -and -not $sessionListShapeRecognized) {
            throw "The wsb.exe response did not contain a recognized session-list structure."
        }
        $activeIds = @($records | Where-Object {
            $_.Id -match '(?i)^\{?[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\}?$' -and
            (-not $_.State -or $_.State -notmatch '(?i)^(stopped|closed|exited|terminated|completed|failed)$')
        } | Select-Object -ExpandProperty Id -Unique)
        $script:SandboxSessionIdsCache = @($activeIds)
        $script:SandboxSessionQueryUtc = [DateTime]::UtcNow
        $script:SandboxSessionQueryValid = $true
        $script:SandboxSessionQueryError = $null
        return @($activeIds)
    } catch {
        $script:SandboxSessionQueryValid = $false
        $script:SandboxSessionQueryError = "Could not parse the wsb.exe session list during ${queryStage}: $($_.Exception.Message)"
        $script:SandboxSessionQueryUtc = [DateTime]::UtcNow
        return @()
    } finally {
        if ($listProcess) { $listProcess.Dispose() }
    }
}

function Test-WindowsSandboxSessionRunning {
    param ([string]$SessionId)

    $sessionIds = @(Get-WindowsSandboxSessionIds)
    if (-not $script:SandboxSessionQueryValid) { return $true }
    if ($SessionId) { return ($SessionId -in $sessionIds) }
    return ($sessionIds.Count -gt 0)
}

function Stop-AnalysisSandbox {
    param ([string]$SessionId, [int[]]$ClientProcessIds)

    $stoppedByCli = $false
    if ($SessionId -and $SandboxCliPath) {
        $stopStdoutPath = Join-Path ([IO.Path]::GetTempPath()) ("sandbox-stop-{0}.out" -f [Guid]::NewGuid().ToString("N"))
        $stopStderrPath = Join-Path ([IO.Path]::GetTempPath()) ("sandbox-stop-{0}.err" -f [Guid]::NewGuid().ToString("N"))
        $stopProcess = $null
        try {
            $stopProcess = Start-Process -FilePath $SandboxCliPath -ArgumentList @("stop", "--id", $SessionId) -PassThru -WindowStyle Hidden -RedirectStandardOutput $stopStdoutPath -RedirectStandardError $stopStderrPath -ErrorAction Stop
            if (-not $stopProcess.WaitForExit(10000)) {
                try { $stopProcess.Kill(); $stopProcess.WaitForExit() } catch {}
                Write-Host "[!] wsb.exe stop --id timed out after 10 seconds; checking the session state before continuing." -ForegroundColor Yellow
            } elseif ($stopProcess.ExitCode -eq 0) {
                $stoppedByCli = $true
                Write-Host "[*] Windows Sandbox stopped cleanly (session $SessionId)." -ForegroundColor DarkGray
            } else {
                Write-Host "[!] wsb.exe stop --id returned exit code $($stopProcess.ExitCode); checking the session state before continuing." -ForegroundColor Yellow
            }
        } catch {
            Write-Host "[!] Could not invoke wsb.exe stop --id; checking the session state before continuing." -ForegroundColor Yellow
        } finally {
            if ($stopProcess) { $stopProcess.Dispose() }
            Remove-Item -LiteralPath $stopStdoutPath, $stopStderrPath -Force -ErrorAction SilentlyContinue
        }
    }

    if (-not $stoppedByCli) {
        foreach ($processId in $ClientProcessIds) {
            Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
        }
    }
    if (-not $ClientProcessIds) { $ClientProcessIds = @() }
    if ((-not $SessionId -or -not $SandboxCliPath) -and $ClientProcessIds.Count -eq 0) { return $false }

    $deadline = (Get-Date).AddSeconds(20)
    do {
        $activeIds = @(Get-WindowsSandboxProcesses | Select-Object -ExpandProperty Id)
        $processStillRunning = @($ClientProcessIds | Where-Object { $_ -in $activeIds }).Count -gt 0
        $sessionStillRunning = Test-WindowsSandboxSessionRunning -SessionId $SessionId
        if (-not $sessionStillRunning -and $processStillRunning) {
            foreach ($processId in $ClientProcessIds) {
                Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
            }
        }
        if (-not $processStillRunning -and -not $sessionStillRunning) { return $true }
        Start-Sleep -Seconds 1
    } while ((Get-Date) -lt $deadline)

    return $false
}

while ($true) {
    Sync-DefenderDetectionLog
    $sample = Get-StableQueueSample

    if (-not $sample) {
        if ($script:QueueDownloadActivity.Count -eq 0) {
            Write-Host "[!] No stable files found in Downloads. Waiting for a completed download..." -ForegroundColor DarkGray
        }
        Start-Sleep -Seconds 5
        continue
    }

    $originalName = $sample.Name
    $sampleQueueKey = Get-QueueFileKey -File $sample
    $sourcePath = "$($sample.FullName).rbi-processing"
    $runStatus = "INCONCLUSIVE"
    $runReason = "Analysis did not complete."
    $processingReady = $false
    $queueRecoveryMarker = $null
    $sampleReadLock = $null
    $sampleReadLockError = $null
    $sampleSizeBytes = [long]::MaxValue
    $defenderBlockedSample = $false
    $defenderBlockDetail = $null
    $sandboxProcessId = $null
    $sandboxSessionId = $null
    $queueMustStop = $false
    $sandboxClientIds = @()
    $existingClientIds = @()
    $existingSandboxIds = @()
    $startedSandbox = $false
    $sandboxStopped = $false
    $analysisWsbFile = $null
    $StagingFolder = Join-Path $StagingParentFolder ("Staging-{0}" -f [Guid]::NewGuid().ToString("N"))
    $PayloadFolder = Join-Path $StagingFolder "payload"
    $allowSandboxNetworking = $false
    $sandboxSkippedReason = $null
    $stagedSamplePrepared = $false
    $demoSeconds = 0
    $demonstrationElapsedSeconds = 0
    $sandboxRebootCount = 0
    $script:GuestRunnerInstanceId = $null
    $script:FirstGuestRunnerInstanceId = $null
    $script:LastGuestRunnerState = ""
    $script:GuestRunnerHistoryInstanceIds = @()
    $script:GuestBootstrapStartCount = 0
    $runnerCompleted = $false
    $staleHeartbeatReported = $false
    $baseline = @{}
    $finalHoneypotSignal = $null
    $script:HoneypotMonitorIncomplete = $false
    $script:HoneypotMonitorIncompleteReported = $false
    $script:HoneypotMonitorIncompleteReason = $null
    $virusTotalComplete = $false
    $virusTotalCoverageSufficient = $false
    $virusTotalMalicious = $null
    $virusTotalSuspicious = $null
    $behaviorThreatConfirmed = $false
    $runtimeRetryRequired = $false
    $runtimeInstallObserved = $false
    $deferredRuntimeSignalStatus = $null
    $deferredRuntimeSignalReason = $null

    Write-Host ([Environment]::NewLine + "[+] Processing file from queue: $originalName") -ForegroundColor Magenta
    Rotate-AnalysisReportIfNeeded
    $reportHeaderLines = @(
        "============================================================"
        "Automated Malware Analysis Report"
        "Sample: $originalName"
        "Date: $(Get-Date)"
    )
    Add-Content -Path $ReportFile -Value ([Environment]::NewLine + ($reportHeaderLines -join [Environment]::NewLine))

    try {
        $queueRecoveryMarker = New-QueueRecoveryMarker -OriginalPath $sample.FullName -ProcessingPath $sourcePath
        Move-Item -LiteralPath $sample.FullName -Destination $sourcePath -ErrorAction Stop
        $processingReady = $true
        Write-Host "[*] Marked with the internal .rbi-processing suffix while it is analyzed." -ForegroundColor DarkGray
    } catch {
        if ($queueRecoveryMarker -and -not $processingReady) {
            Remove-Item -LiteralPath $queueRecoveryMarker -Force -ErrorAction SilentlyContinue
            $queueRecoveryMarker = $null
        }
        $queueMoveError = $_.Exception.Message
        $defenderMatches = @(Sync-DefenderDetectionLog -RelatedPaths @($sample.FullName) -Force -ReturnRelatedDetections)
        if ($defenderMatches.Count -gt 0 -or $queueMoveError -match '(?i)(contains a virus|potentially unwanted software)') {
            $defenderBlockedSample = $true
            $runStatus = "VIRUS"
            if ($defenderMatches.Count -gt 0) {
                $threatNames = @($defenderMatches | ForEach-Object { $_.ThreatName } | Select-Object -Unique) -join ', '
                $defenderBlockDetail = "Windows Defender blocked access to this sample and recorded an exact-path detection ($threatNames). Check Windows Security Protection History for its final quarantine/removal action."
            } else {
                $defenderBlockDetail = "Windows reported that this sample contains a virus or potentially unwanted software and blocked access. Check Windows Security Protection History for the detection and its final quarantine/removal action."
            }
            $runReason = $defenderBlockDetail
            Add-Content -Path $ReportFile -Value "[DEFENDER] The pipeline could not move the queued sample because antivirus blocked access. No copy was restored or recreated by the pipeline."
        } else {
            $runReason = "Could not mark the sample as processing: $queueMoveError"
        }
    }

    if ($processingReady) {
        try {
            $sampleReadLock = [System.IO.File]::Open($sourcePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
            $sampleSizeBytes = [long](Get-Item -LiteralPath $sourcePath -ErrorAction Stop).Length
        } catch {
            $sampleReadLockError = $_.Exception.Message
            if ($sampleReadLock) { $sampleReadLock.Dispose(); $sampleReadLock = $null }
        }
    }

    if ($processingReady -and $sampleReadLock -and $sampleSizeBytes -le $MaxSampleAnalysisBytes) {
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
            $allowSandboxNetworking = [bool]($virusTotalComplete -and
                ($null -ne $virusTotalMalicious) -and ($virusTotalMalicious -eq 0) -and
                ($null -ne $virusTotalSuspicious) -and ($virusTotalSuspicious -eq 0))

            $payloadExtension = [System.IO.Path]::GetExtension($originalName).ToLowerInvariant()
            $sandboxRunnableExtensions = @('.exe', '.com', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.msi', '.hta', '.lnk', '.zip', '.dll', '.jpg', '.jpeg', '.jpe', '.jfif', '.png', '.gif', '.bmp', '.webp', '.tif', '.tiff', '.ico', '.avif', '.heic')
            $staticImageExtensions = @('.jpg', '.jpeg', '.jpe', '.jfif', '.png', '.gif', '.bmp', '.webp', '.tif', '.tiff', '.ico', '.avif', '.heic')
            if ($payloadExtension -in $staticImageExtensions) {
                if (-not (Test-ImageFileSignature -Path $sourcePath -Extension $payloadExtension)) {
                    $sandboxSkippedReason = "The image extension does not match the file signature; it was not opened in a guest image viewer."
                    $runStatus = 'INCONCLUSIVE'
                    $runReason = "The file extension indicates an image, but its contents do not match the expected image signature. It was not opened or executed; manual review is required."
                    Add-Content -Path $ReportFile -Value "[STATIC] Image extension/signature mismatch; did not treat this file as a clean image."
                } else {
                    if ($payloadExtension -eq '.ico') {
                        Add-Content -Path $ReportFile -Value "[SANDBOX] ICO signature matched; the guest runner will render it with the built-in icon preview instead of relying on a Windows file association. This does not test every icon decoder."
                    } else {
                        Add-Content -Path $ReportFile -Value "[SANDBOX] Image signature matched; opening the image with its registered viewer inside the disposable guest. This does not test every decoder or image format handler."
                    }
                }
            } elseif ($payloadExtension -eq '.dll') {
                if (-not (Test-PeFileSignature -Path $sourcePath)) {
                    $sandboxSkippedReason = 'The .dll extension does not match a valid PE image; it was not loaded in the Sandbox.'
                    $runStatus = 'INCONCLUSIVE'
                    $runReason = $sandboxSkippedReason
                    Add-Content -Path $ReportFile -Value "[STATIC] DLL extension/PE signature mismatch; did not attempt a load probe."
                } else {
                    $sandboxSkippedReason = $null
                    Add-Content -Path $ReportFile -Value "[SANDBOX] DLL sample will receive an isolated load-only probe. DllMain runs during loading when present; exported functions and host-application behavior are not invoked."
                }
            } elseif ($payloadExtension -notin $sandboxRunnableExtensions) {
                $sandboxSkippedReason = "No supported launcher is defined for extension '$payloadExtension'; no Windows file association was invoked. Static analysis and VirusTotal were checked, and manual review is required."
                $runStatus = 'INCONCLUSIVE'
                $runReason = $sandboxSkippedReason
                Add-Content -Path $ReportFile -Value "[SANDBOX] Dynamic analysis skipped: $sandboxSkippedReason"
            }

            $existingSandbox = @(Get-WindowsSandboxProcesses)
            $existingSandboxSessionIds = @(Get-WindowsSandboxSessionIds -TimeoutMilliseconds $SandboxSessionStartupQueryTimeoutMilliseconds)
            if ($sandboxSkippedReason) {
            } elseif (-not $script:SandboxSessionQueryValid) {
                $runStatus = "INCONCLUSIVE"
                $runReason = "Could not reliably enumerate Windows Sandbox sessions ($script:SandboxSessionQueryError). The sample was not launched to avoid reusing or overlooking an active session."
                Add-Content -Path $ReportFile -Value "[SANDBOX] Session enumeration failed; skipped launch and preserved the sample for review. Detail: $script:SandboxSessionQueryError"
            } elseif ($existingSandbox.Count -gt 0 -or $existingSandboxSessionIds.Count -gt 0) {
                $runReason = "An existing Windows Sandbox session is open; this sample was not run."
            } else {
                try {
                    $shareVolumeReady = $false
                    $shareVolumeErrors = @()
                    for ($shareAttempt = 1; $shareAttempt -le 3 -and -not $shareVolumeReady; $shareAttempt++) {
                        try {
                            Initialize-WritableShareVolume
                            $script:WritableShareVolumeReady = $true
                            $shareVolumeReady = $true
                        } catch {
                            $script:WritableShareVolumeReady = $false
                            $shareVolumeErrors += $_.Exception.Message
                            if ($shareAttempt -lt 3) { Start-Sleep -Seconds 2 }
                        }
                    }
                    if (-not $shareVolumeReady) {
                        $shareVolumeFailure = @($shareVolumeErrors | Select-Object -Unique) -join ' | '
                        throw "Capped writable-share volume initialization failed after 3 attempts: $shareVolumeFailure"
                    }
                    foreach ($managedFolder in @($StagingFolder, $TelemetryFolder, $HoneypotFolder)) {
                        if (Test-Path -LiteralPath $managedFolder) {
                            Remove-Item -LiteralPath $managedFolder -Recurse -Force -ErrorAction Stop
                        }
                    }
                    $honeypotSubfolders = @("Desktop", "Documents", "Pictures", "Downloads") | ForEach-Object { Join-Path $HoneypotFolder $_ }
                    $foldersToCreate = @($PayloadFolder, $TelemetryFolder, $FeatureSourceFolder, $NetFx3SxsSourceFolder) + $honeypotSubfolders
                    New-Item -ItemType Directory -Force -Path $foldersToCreate | Out-Null
                    Copy-Item -LiteralPath $SandboxRunnerFile -Destination (Join-Path $StagingFolder "sandbox-runner.ps1") -Force -ErrorAction Stop
                    Copy-Item -LiteralPath $SandboxBootstrapFile -Destination (Join-Path $StagingFolder "sandbox-bootstrap.cmd") -Force -ErrorAction Stop
                    $stagedSamplePath = Join-Path $PayloadFolder $originalName
                    Copy-Item -LiteralPath $sourcePath -Destination $stagedSamplePath -Force -ErrorAction Stop
                    $stagedSamplePrepared = $true
                    $stagedSha256 = (Get-FileHash -LiteralPath $stagedSamplePath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
                    if (-not $virusTotalResult -or -not $virusTotalResult.Sha256 -or $stagedSha256 -ne [string]$virusTotalResult.Sha256) {
                        throw "The staged Sandbox copy did not match the SHA-256 of the file analyzed on the host. The sample was not launched."
                    }

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
                    Add-Content -Path $ReportFile -Value "[SANDBOX] Could not prepare the capped writable-share volume or isolated guest folders: $($_.Exception.Message)"
                }

                if ($runReason -eq "Analysis did not complete.") {
                    $existingClientIds = @(Get-WindowsSandboxProcesses | Select-Object -ExpandProperty Id)
                    $existingSandboxIds = @(Get-WindowsSandboxSessionIds -TimeoutMilliseconds $SandboxSessionStartupQueryTimeoutMilliseconds)
                    if ($allowSandboxNetworking) {
                        Add-Content -Path $ReportFile -Value "[SANDBOX] Networking enabled because the completed VirusTotal report has zero malicious and suspicious detections (classification coverage: $($virusTotalResult.CoveragePercent)%). Incomplete coverage and zero detections are not guarantees of safety or containment."
                        Write-Host "[*] Sandbox networking enabled: VirusTotal completed with zero malicious/suspicious detections ($($virusTotalResult.CoveragePercent)% coverage)." -ForegroundColor Yellow
                    } else {
                        $networkBlockReason = if ($virusTotalComplete -and (($virusTotalMalicious -gt 0) -or ($virusTotalSuspicious -gt 0))) { "VirusTotal reported malicious or suspicious detections" } else { "VirusTotal did not provide a completed report with zero malicious and suspicious detections" }
                        Add-Content -Path $ReportFile -Value "[SANDBOX] Networking disabled because $networkBlockReason. This blocks guest Internet access for command-and-control, worm communication, and online installers; it does not guarantee containment."
                        Write-Host "[*] Sandbox networking disabled: $networkBlockReason." -ForegroundColor Yellow
                    }
                    Write-Host "[*] Starting Windows Sandbox and auto-running the sample..." -ForegroundColor Cyan
                    try {
                        $analysisWsbFile = New-AnalysisSandboxConfig -EnableNetworking $allowSandboxNetworking -HostStagingFolder $StagingFolder
                        Start-Process -FilePath $analysisWsbFile -ErrorAction Stop | Out-Null
                        $startedSandbox = $true
                    } catch {
                        $runReason = "Windows Sandbox could not be launched: $($_.Exception.Message)"
                    }

                    if ($startedSandbox) {
                        Write-Host "[*] Waiting for the guest runner (up to $SandboxStartupTimeoutSeconds seconds)..." -ForegroundColor Yellow
                        $startupClock = [Diagnostics.Stopwatch]::StartNew()
                        $startupSeconds = 0
                        $nextSessionProbeSeconds = 0
                        $runnerConfirmed = $false
                        $sawSandboxDuringStartup = $false
                        $guestStatus = $null
                        while (-not $runnerConfirmed -and $startupClock.Elapsed.TotalSeconds -lt $SandboxStartupTimeoutSeconds) {
                            $startupSeconds = [int]$startupClock.Elapsed.TotalSeconds
                            $guestStatus = Get-RunnerStatus
                            $bootstrapLogText = Get-SandboxBootstrapLogText
                            if ($bootstrapLogText -match '(?im)^\[BOOTSTRAP\] ERROR: (.+)$') {
                                $runReason = "Guest bootstrap could not start the runner: $($matches[1])"
                                Write-Host "[!] $runReason" -ForegroundColor Yellow
                                break
                            }
                            if ($bootstrapLogText -match '(?im)^\[BOOTSTRAP\] Runner exited with code ([0-9]+)') {
                                $runnerExitCode = $matches[1]
                                $zipFailure = [regex]::Match($bootstrapLogText, '(?im)^\[ZIP\] (.+)$')
                                if ($runnerExitCode -eq "3" -and $zipFailure.Success) {
                                    $runReason = "ZIP inspection failed before launch: $($zipFailure.Groups[1].Value)"
                                    Add-Content -Path $ReportFile -Value "[SANDBOX] $runReason"
                                } else {
                                    $runReason = "Guest runner exited with code $runnerExitCode before reporting a startup status. See the runner-bootstrap.log excerpt in the report."
                                }
                                Write-Host "[!] $runReason" -ForegroundColor Yellow
                                break
                            }
                            $startupRestartReason = Test-GuestRunnerRestart -Status $guestStatus
                            if ($startupRestartReason) {
                                $sandboxRebootCount++
                                $runStatus = "INCONCLUSIVE"
                                $runReason = "A new guest runner instance was detected during setup or analysis ($startupRestartReason). The runner will monitor the guest without launching the sample again; a restart alone is not treated as a threat."
                                Add-Content -Path $ReportFile -Value "[SANDBOX] New guest runner instance detected (#$sandboxRebootCount) during startup ($startupRestartReason); awaiting the post-reboot observation."
                                Write-Host "[!] New guest runner instance detected. Waiting for its post-restart check; this alone is not a threat verdict." -ForegroundColor Yellow
                                $runnerConfirmed = $true
                                break
                            }
                            if ($guestStatus -and ($guestStatus.state -in @("STARTED", "LAUNCHING_PAYLOAD", "PREPARING_RUNTIME", "INSTALLING_RUNTIME", "POST_REBOOT_CHECK", "POST_REBOOT_COMPLETE", "REBOOTED", "INSPECTING_ARCHIVE", "RUNNING", "SUSPICIOUS", "VIRUS", "ZIP_BOMB", "UNSAFE_ARCHIVE", "COMPLETED", "INCONCLUSIVE", "UNSUPPORTED", "ERROR"))) {
                                $runnerConfirmed = $true
                                break
                            }

                            $sandboxClientIds = @(Get-WindowsSandboxProcesses |
                                Where-Object { $_.Id -notin $existingClientIds } |
                                Select-Object -ExpandProperty Id)
                            if ($sandboxClientIds.Count -gt 0) {
                                $sandboxProcessId = $sandboxClientIds[0]
                            }

                            $newSandboxIds = @()
                            $shouldProbeSessions = ($startupSeconds -ge $nextSessionProbeSeconds) -or ($sawSandboxDuringStartup -and $sandboxClientIds.Count -eq 0)
                            if ($shouldProbeSessions) {
                                $newSandboxIds = @(Get-WindowsSandboxSessionIds -TimeoutMilliseconds $SandboxSessionStartupQueryTimeoutMilliseconds | Where-Object { $_ -notin $existingSandboxIds })
                                if ($newSandboxIds.Count -gt 0) { $sandboxSessionId = $newSandboxIds[0] }
                                $nextSessionProbeSeconds = $startupSeconds + 10
                            }
                            if ($sandboxClientIds.Count -gt 0 -or $newSandboxIds.Count -gt 0) { $sawSandboxDuringStartup = $true }

                            if ($sawSandboxDuringStartup -and $sandboxClientIds.Count -eq 0 -and $newSandboxIds.Count -eq 0 -and $script:SandboxSessionQueryValid) {
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
                        }
                        $startupSeconds = [int]$startupClock.Elapsed.TotalSeconds

                        $sandboxClientIds = @(Get-WindowsSandboxProcesses |
                            Where-Object { $_.Id -notin $existingClientIds } |
                            Select-Object -ExpandProperty Id)
                        if ($sandboxClientIds.Count -gt 0) {
                            $sandboxProcessId = $sandboxClientIds[0]
                            $sawSandboxDuringStartup = $true
                        }
                        if (-not $sandboxSessionId) {
                            $newSandboxIds = @(Get-WindowsSandboxSessionIds -ForceRefresh -TimeoutMilliseconds $SandboxSessionStartupQueryTimeoutMilliseconds | Where-Object { $_ -notin $existingSandboxIds })
                            if ($newSandboxIds.Count -gt 0) {
                                $sandboxSessionId = $newSandboxIds[0]
                                $sawSandboxDuringStartup = $true
                            }
                        }

                        if (-not $runnerConfirmed) {
                            if ($runReason -eq "Analysis did not complete.") {
                                if ($sandboxProcessId) {
                                    $runReason = "The Sandbox window opened, but the guest runner did not confirm that the payload launched within $SandboxStartupTimeoutSeconds seconds."
                                } else {
                                    $runReason = "No Sandbox client or guest-runner startup signal appeared within $SandboxStartupTimeoutSeconds seconds. The payload launch was not confirmed."
                                }
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
                            $analysisClock = [Diagnostics.Stopwatch]::StartNew()
                            $analysisHardClock = [Diagnostics.Stopwatch]::StartNew()
                            $analysisHardLimitSeconds = $RuntimeSetupTimeoutSeconds + $MaxAnalysisSeconds
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
                            while ($analysisClock.Elapsed.TotalSeconds -lt $analysisDeadlineSeconds -and
                                $analysisHardClock.Elapsed.TotalSeconds -lt $analysisHardLimitSeconds) {
                                $analysisSeconds = [int]$analysisClock.Elapsed.TotalSeconds
                                $liveClients = @(Get-WindowsSandboxProcesses | Where-Object { $_.Id -notin $existingClientIds })
                                $sandboxStillRunning = ($liveClients.Count -gt 0) -or (Test-WindowsSandboxSessionRunning -SessionId $sandboxSessionId)
                                if (($sandboxProcessId -or $sandboxSessionId) -and -not $sandboxStillRunning) {
                                    $exitGuestStatus = Get-RunnerStatus
                                    $exitRestartReason = Test-GuestRunnerRestart -Status $exitGuestStatus
                                    if ($exitRestartReason) {
                                        $sandboxRebootCount++
                                        $runStatus = "INCONCLUSIVE"
                                        $runReason = "A new guest runner instance was detected ($exitRestartReason), then the Sandbox session exited before its post-restart check completed. The sample was not cleared as safe."
                                        Add-Content -Path $ReportFile -Value "[SANDBOX] Runner history confirms a new guest runner instance immediately before the Sandbox session disappeared: $exitRestartReason"
                                        Write-Host "[!] A new guest runner instance was detected, but the Sandbox exited before its post-restart check; preserving the sample for review." -ForegroundColor Yellow
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
                                $analysisRestartReason = Test-GuestRunnerRestart -Status $guestStatus
                                if ($analysisRestartReason) {
                                    $sandboxRebootCount++
                                    if ($runStatus -notin @("SUSPICIOUS", "VIRUS")) {
                                        $runStatus = "INCONCLUSIVE"
                                        $runReason = "A new guest runner instance was detected during analysis ($analysisRestartReason). The guest is being monitored without launching the sample again; the restart alone is not a threat verdict."
                                    }
                                    Add-Content -Path $ReportFile -Value "[SANDBOX] New guest runner instance detected (#$sandboxRebootCount) during dynamic analysis ($analysisRestartReason); the payload will not be relaunched automatically."
                                    Write-Host "[!] New guest runner instance detected. Continuing with a post-restart observation; the restart alone is not a threat verdict." -ForegroundColor Yellow
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
                                        $analysisClock.Restart()
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
                                            $analysisClock.Restart()
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
                                        if ($guestState -eq "RUNNING") {
                                            Add-Content -Path $ReportFile -Value "[SANDBOX] $($guestStatus.details)"
                                        }
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
                                            $guestCompletionDetail = if ($guestStatus.details) { ([string]$guestStatus.details -replace '[\r\n]+', ' ').Trim() } else { "No completion details were reported." }
                                            Add-Content -Path $ReportFile -Value "[SANDBOX] Guest runner completed its internal observation window. $guestCompletionDetail Host-side monitoring continues until the full analysis window ends."
                                            Write-Host "[*] Guest runner completed; $guestCompletionDetail Host-side monitoring continues before a clean verdict is considered." -ForegroundColor Cyan
                                        }
                                    }
                                    if (($guestState -eq "UNSUPPORTED") -or ($guestState -eq "ERROR")) {
                                        $guestFailureDetail = if ($guestStatus -and $guestStatus.details) { ([string]$guestStatus.details -replace '[\r\n]+', ' ').Trim() } else { "No detailed guest error was reported." }
                                        Add-Content -Path $ReportFile -Value "[SANDBOX] Guest runtime/setup failure detail: $guestFailureDetail"
                                        Write-Host "[!] Guest runtime/setup failure: $guestFailureDetail" -ForegroundColor Yellow
                                        if ($deferredRuntimeSignalStatus) {
                                            $runStatus = "INCONCLUSIVE"
                                            $runReason = "The guest could not confirm a working sample launch. Runtime/setup failure: $($guestStatus.details) Previously recorded behavior signal for manual review: $deferredRuntimeSignalReason"
                                            Add-Content -Path $ReportFile -Value "[SANDBOX] Runtime/setup failed before a working payload launch was confirmed; the saved signal remains in the report and the item will be preserved for review."
                                        } else {
                                            $runReason = $guestStatus.details
                                        }
                                        break
                                    }
                                    if ($guestState -eq "INCONCLUSIVE") {
                                        $runStatus = "INCONCLUSIVE"
                                        $runReason = if ($guestStatus.details) { [string]$guestStatus.details } else { "Guest monitoring was incomplete; the sample was preserved for review." }
                                        Add-Content -Path $ReportFile -Value "[SANDBOX] Guest monitoring was incomplete; the sample was not cleared as safe. $runReason"
                                        Write-Host "[!] Guest monitoring was incomplete; preserving the sample for review." -ForegroundColor Yellow
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
                                $sandboxStillRunning = ($liveClients.Count -gt 0) -or (Test-WindowsSandboxSessionRunning -SessionId $sandboxSessionId)
                                if (($sandboxProcessId -or $sandboxSessionId) -and -not $sandboxStillRunning) {
                                    $exitGuestStatus = Get-RunnerStatus
                                    $exitRestartReason = Test-GuestRunnerRestart -Status $exitGuestStatus
                                    if ($exitRestartReason) {
                                        $sandboxRebootCount++
                                        $runStatus = "INCONCLUSIVE"
                                        $runReason = "A new guest runner instance was detected ($exitRestartReason), then the Sandbox session exited before post-restart monitoring finished. The sample was not cleared as safe."
                                        Add-Content -Path $ReportFile -Value "[SANDBOX] Runner history confirms a new guest runner instance immediately before the Sandbox session disappeared: $exitRestartReason"
                                        Write-Host "[!] A new guest runner instance was detected, but the Sandbox exited before its post-restart check finished; the result is inconclusive." -ForegroundColor Yellow
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
                                    } elseif ($guestStatus -and [string]$guestStatus.state -eq "RUNNING" -and [IO.Path]::GetExtension($originalName) -ieq ".msi") {
                                        Write-Host "[*] MSI install is still running; dynamic analysis $analysisSeconds/$MaxAnalysisSeconds seconds. Monitoring continues; an unfinished installer will remain in Review_Files." -ForegroundColor Yellow
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
                                $analysisSeconds = [int]$analysisClock.Elapsed.TotalSeconds
                            }
                            $analysisSeconds = [int]$analysisClock.Elapsed.TotalSeconds

                            if ($runStatus -eq "INCONCLUSIVE" -and $runnerCompleted -and $sandboxRebootCount -eq 0 -and $analysisSeconds -ge $MaxAnalysisSeconds) {
                                $liveClients = @(Get-WindowsSandboxProcesses | Where-Object { $_.Id -notin $existingClientIds })
                                $sandboxStillRunning = ($liveClients.Count -gt 0) -or (Test-WindowsSandboxSessionRunning -SessionId $sandboxSessionId)
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

                            if ($analysisHardClock.Elapsed.TotalSeconds -ge $analysisHardLimitSeconds -and $runStatus -notin @("SUSPICIOUS", "VIRUS")) {
                                $runStatus = "INCONCLUSIVE"
                                $runReason = "The fixed $analysisHardLimitSeconds-second analysis watchdog expired. Guest status changes cannot extend this limit; the sample was not cleared as safe."
                                if ($deferredRuntimeSignalReason) { $runReason += " Previously recorded host behavior signal: $deferredRuntimeSignalReason" }
                                Add-Content -Path $ReportFile -Value "[SANDBOX] Fixed analysis watchdog expired; stopped waiting on guest-controlled status and preserved the sample for review."
                            }

                        }
                    }
                }
            }
        }
    } elseif ($processingReady) {
        if (-not $sampleReadLock) {
            $runReason = "Could not lock the queued sample against changes before analysis: $sampleReadLockError. Preserving it for review."
        } elseif ($sampleSizeBytes -gt $MaxSampleAnalysisBytes) {
            $runReason = "Sample size ($sampleSizeBytes bytes) exceeds the $MaxSampleAnalysisBytes-byte analysis limit. Hashing, upload, and Sandbox execution were skipped; preserving the sample for review."
        } else {
            $runReason = "Could not determine the sample size safely before analysis. Preserving it for review."
        }
        Add-Content -Path $ReportFile -Value "[ANALYSIS] $runReason"
    }

    if ($startedSandbox -and $script:HoneypotWatcher) {
        $finalHoneypotSignal = Get-HoneypotSignal -Baseline $baseline
        if ($finalHoneypotSignal) {
            if ($finalHoneypotSignal -match '^VIRUS:\s*(.*)$') {
                $runStatus = "VIRUS"
                $runReason = $matches[1]
            } elseif ($runStatus -ne "VIRUS") {
                $runStatus = "SUSPICIOUS"
                $runReason = $finalHoneypotSignal
            }
            Add-Content -Path $ReportFile -Value "[SANDBOX] Final host-side honeypot poll detected behavior before the session was stopped: $finalHoneypotSignal"
        }
    }

    if ($runStatus -eq "NO DETECTION" -and $script:HoneypotMonitorIncomplete) {
        $runStatus = "INCONCLUSIVE"
        $monitorIssue = if ($script:HoneypotMonitorIncompleteReason) { $script:HoneypotMonitorIncompleteReason } else { "Host honeypot monitoring did not cover the full analysis." }
        $runReason = "$monitorIssue No clean verdict is issued when host monitoring is incomplete."
    }
    if ($script:HoneypotMonitorIncomplete -and -not $script:HoneypotMonitorIncompleteReported) {
        $monitorIssue = if ($script:HoneypotMonitorIncompleteReason) { $script:HoneypotMonitorIncompleteReason } else { "Host honeypot monitoring was incomplete." }
        Add-Content -Path $ReportFile -Value "[SANDBOX] MONITORING INCOMPLETE: $monitorIssue"
        $script:HoneypotMonitorIncompleteReported = $true
    }

    $virusTotalHasDetections = $virusTotalComplete -and ($virusTotalMalicious -gt 0 -or $virusTotalSuspicious -gt 0)
    if ($runStatus -in @("SUSPICIOUS", "VIRUS") -and -not $finalHoneypotSignal -and -not $virusTotalHasDetections -and -not $defenderBlockedSample) {
        $guestReportedState = $runStatus
        $guestReportedReason = if ($runReason) { $runReason } else { "The guest did not provide additional signal details." }
        if ($guestReportedReason -match '(?i)File-bomber/spammer burst detected: at least 200') {
            $runReason = "$guestReportedReason Guest telemetry is writable by the sample, but the configured 200-file burst rule is treated as SUSPICIOUS and the original will be deleted."
            Add-Content -Path $ReportFile -Value "[SANDBOX] The 200-file-per-second file-bomber/spammer rule was met. Kept SUSPICIOUS and will delete the original; the reported count came from guest monitoring."
        } else {
            $runStatus = "INCONCLUSIVE"
            $runReason = "The guest runner reported $guestReportedState, but no independent host honeypot or VirusTotal signal confirmed it. Guest telemetry is writable by the sample, so the report is preserved for review instead of treating the unverified status as a detection. Original guest detail: $guestReportedReason"
            Add-Content -Path $ReportFile -Value "[SANDBOX] Guest-only threat status was not trusted without independent host-side or VirusTotal corroboration; preserved as INCONCLUSIVE. Original guest detail: $guestReportedReason"
        }
    }

    if ($runStatus -eq "NO DETECTION" -and $startedSandbox) {
        $cleanStatus = Get-RunnerStatus
        $cleanGateFailures = New-Object System.Collections.Generic.List[string]
        if (-not $virusTotalComplete -or -not $virusTotalCoverageSufficient -or $virusTotalHasDetections) {
            [void]$cleanGateFailures.Add("VirusTotal did not provide a sufficiently covered, completed zero-detection report")
        }
        if (-not $cleanStatus -or [string]$cleanStatus.state -ne "COMPLETED") {
            [void]$cleanGateFailures.Add("the guest runner did not report COMPLETED")
        }
        if (-not $cleanStatus -or [int]$cleanStatus.launched -lt 1) {
            [void]$cleanGateFailures.Add("a payload launch was not confirmed")
        }
        if ($cleanStatus -and [string]$cleanStatus.details -match "(?i)MSI .* still running") {
            [void]$cleanGateFailures.Add("the MSI installer was still running at the observation limit")
        }
        if ($sandboxRebootCount -gt 0) {
            [void]$cleanGateFailures.Add("a guest runner restart was detected")
        }
        if ($staleHeartbeatReported) {
            [void]$cleanGateFailures.Add("the guest runner heartbeat became stale during analysis")
        }
        if ($script:HoneypotMonitorIncomplete) {
            [void]$cleanGateFailures.Add("host-side behavior monitoring was incomplete")
        }
        if ($finalHoneypotSignal) {
            [void]$cleanGateFailures.Add("the host-side honeypot recorded behavior")
        }
        if ($defenderBlockedSample) {
            [void]$cleanGateFailures.Add("Windows Defender blocked the sample")
        }
        $finalDefenderMatches = @(Sync-DefenderDetectionLog -RelatedPaths @($sample.FullName, $sourcePath, (Join-Path $PayloadFolder $originalName)) -Force -ReturnRelatedDetections)
        if ($finalDefenderMatches.Count -gt 0) {
            [void]$cleanGateFailures.Add("Windows Defender recorded a detection for this sample")
        }

        if ($cleanGateFailures.Count -gt 0) {
            $runStatus = "INCONCLUSIVE"
            $runReason = "No independent alert was confirmed, but the sample did not meet the clean-file conditions: $($cleanGateFailures -join '; '). Preserved for review."
            Add-Content -Path $ReportFile -Value "[SANDBOX] No clean verdict: $($cleanGateFailures -join '; '). The sample was preserved for review."
        } else {
            $runReason = "No alert was found in the completed VirusTotal report or full host-side behavior observation, and the guest confirmed a payload launch and completed its observation. This is not a guarantee of safety."
            Add-Content -Path $ReportFile -Value "[SANDBOX] NO DETECTION corroborated: VirusTotal coverage was sufficient with zero malicious/suspicious detections, the guest confirmed launch and completed observation, and host-side monitoring completed without a signal. The guest status share remains writable by the sample, so this verdict is not proof of safety."
        }
    }

    $behaviorThreatConfirmed = $runStatus -in @("SUSPICIOUS", "VIRUS")
    $dynamicRunReason = $runReason
    if ($virusTotalComplete -and ($virusTotalMalicious -gt 0 -or $virusTotalSuspicious -gt 0)) {
        if ($runStatus -ne "VIRUS") {
            $runStatus = "SUSPICIOUS"
            $runReason = "VirusTotal reported detections (malicious: $virusTotalMalicious/$($virusTotalResult.Total) engines; suspicious: $virusTotalSuspicious). This is a reputation-based alert, not proof that this run launched the sample or observed malicious behavior."
            if ($startedSandbox -and -not $behaviorThreatConfirmed) {
                Add-Content -Path $ReportFile -Value "[SANDBOX] Dynamic analysis did not confirm malicious behavior. The sample launch may have failed or no monitored behavior occurred."
                if ($dynamicRunReason) {
                    $sandboxResultSummary = ([string]$dynamicRunReason -replace '[\r\n]+', ' ').Trim()
                    Add-Content -Path $ReportFile -Value "[SANDBOX DETAIL] The dynamic result before the VirusTotal verdict was: $sandboxResultSummary"
                }
            }
            if ($sandboxSkippedReason) { $runReason += " Dynamic analysis was skipped: $sandboxSkippedReason" }
        }
    } elseif ((-not $virusTotalComplete -or -not $virusTotalCoverageSufficient) -and $runStatus -eq "NO DETECTION") {
        $runStatus = "INCONCLUSIVE"
        $runReason = "Sandbox monitoring found no behavior, but VirusTotal did not return a completed report with enough engines reporting a classification. The sample is preserved for review."
    }

    if ($startedSandbox -and $behaviorThreatConfirmed -and $runStatus -in @("SUSPICIOUS", "VIRUS")) {
        $demoSeconds = $DemoVisibleSeconds
        $remainingSeconds = $demoSeconds
        $demoRecoverySeen = ($sandboxRebootCount -gt 0)
        $demoRestartConfirmed = ($sandboxRebootCount -gt 0)
        $demoRestartVisibilityGranted = ($sandboxRebootCount -gt 0)
        $demoSawStaleHeartbeat = [bool]$staleHeartbeatReported
        $sandboxUnavailableDuringDemo = $false
        $demoReadinessWaitSeconds = 0
        $sandboxMissingSeconds = 0
        $demoKnownClientIds = @(Get-WindowsSandboxProcesses | Where-Object { $_.Id -notin $existingClientIds } | Select-Object -ExpandProperty Id)
        $demoKnownSessionIds = @(Get-WindowsSandboxSessionIds | Where-Object { $_ -notin $existingSandboxIds })
        $demoTimer = $null
        $demoReadySince = $null
        $demoRestartDetectionClock = $null
        $demoRestartDetectionReported = $false
        $lastLoggedRemaining = -1
        if ($demoRecoverySeen) {
            $demoTimer = [System.Diagnostics.Stopwatch]::StartNew()
            Add-Content -Path $ReportFile -Value "[SANDBOX] A new guest runner instance was already detected. Started the fixed $DemoVisibleSeconds-second demonstration timer without waiting for another runner search."
            Write-Host "[!] New guest runner instance already detected. The fixed $DemoVisibleSeconds-second timer starts now; no additional runner search." -ForegroundColor Yellow
        } else {
            Write-Host "[!] Threat activity confirmed. After payload launch is confirmed, the Sandbox will settle for $DemoLaunchSettleSeconds seconds, then remain visible for $DemoVisibleSeconds seconds." -ForegroundColor Yellow
        }

        while (-not $sandboxUnavailableDuringDemo) {
            $demoSignal = Get-HoneypotFileBurstSignal
            if ($demoSignal -match '^VIRUS:\s*(.*)$') {
                $runStatus = "VIRUS"
                $runReason = $matches[1]
            }

            $demoGuestStatus = Get-RunnerStatus
            $guestRunnerRestartReason = Test-GuestRunnerRestart -Status $demoGuestStatus
            $guestRunnerRestarted = [bool]$guestRunnerRestartReason
            if ($demoGuestStatus -and [string]$demoGuestStatus.state -eq "VIRUS") {
                $runStatus = "VIRUS"
                $runReason = [string]$demoGuestStatus.details
            }
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
            if ($runnerHeartbeatStale) { $demoSawStaleHeartbeat = $true }
            $recoverySignalObserved = $guestRunnerRestarted -or $runnerHeartbeatStale -or ($newDemoClientIds.Count -gt 0) -or ($newDemoSessionIds.Count -gt 0)
            $sandboxCurrentlyPresent = ($currentDemoClientIds.Count -gt 0) -or ($currentDemoSessionIds.Count -gt 0) -or (-not $script:SandboxSessionQueryValid)
            if ($guestRunnerRestarted) {
                $sandboxRebootCount++
                $demoRestartConfirmed = $true
                if ($demoRecoverySeen) {
                    $confirmedRestartDetail = "Guest restart confirmed: $guestRunnerRestartReason"
                    Add-Content -Path $ReportFile -Value "[SANDBOX] $confirmedRestartDetail"
                    Write-Host "[!] $confirmedRestartDetail. Continuing the bounded demonstration timer." -ForegroundColor Yellow
                }
            } elseif ($demoSawStaleHeartbeat -and -not $demoRestartConfirmed -and ($newDemoClientIds.Count -gt 0 -or $newDemoSessionIds.Count -gt 0)) {
                $sandboxRebootCount++
                $demoRestartConfirmed = $true
                $hostRestartReason = if ($newDemoSessionIds.Count -gt 0) { "a new Sandbox session ID appeared" } else { "a new Sandbox client process appeared" }
                $confirmedRestartDetail = "Sandbox restart confirmed after the runner heartbeat became stale: $hostRestartReason."
                Add-Content -Path $ReportFile -Value "[SANDBOX] $confirmedRestartDetail"
                Write-Host "[!] $confirmedRestartDetail Continuing the bounded demonstration timer." -ForegroundColor Yellow
            }

            if ($demoRestartConfirmed -and -not $demoRestartVisibilityGranted -and $demoTimer) {
                $demoTimer.Restart()
                $demoRestartVisibilityGranted = $true
                $lastLoggedRemaining = -1
                Add-Content -Path $ReportFile -Value "[SANDBOX] A guest or Sandbox restart was confirmed; started a fresh fixed $DemoVisibleSeconds-second visible review interval after the restart."
                Write-Host "[*] Restart confirmed. Keeping Windows Sandbox open for a fresh $DemoVisibleSeconds-second review interval." -ForegroundColor Green
            }

            if ($recoverySignalObserved -and -not $demoRecoverySeen) {
                $recoveryReasons = New-Object System.Collections.Generic.List[string]
                if ($guestRunnerRestarted) {
                    [void]$recoveryReasons.Add("new guest runner instance: $guestRunnerRestartReason")
                }
                if ($runnerHeartbeatStale) { [void]$recoveryReasons.Add("runner heartbeat is stale; this can indicate a hang or reboot, but does not confirm one") }
                if ($newDemoClientIds.Count -gt 0) { [void]$recoveryReasons.Add("new Sandbox client process observed") }
                if ($newDemoSessionIds.Count -gt 0) { [void]$recoveryReasons.Add("new Sandbox session ID observed") }
                $demoRecoverySeen = $true
                $demoReadySince = $null
                if (-not $demoTimer) { $demoTimer = [System.Diagnostics.Stopwatch]::StartNew() }
                $recoveryDetail = $recoveryReasons -join "; "
                Add-Content -Path $ReportFile -Value "[SANDBOX] Recovery signal observed; the fixed $DemoVisibleSeconds-second demonstration timer continues and no additional runner search is performed. $recoveryDetail"
                Write-Host "[!] $recoveryDetail. The fixed demonstration timer continues; not waiting for the runner." -ForegroundColor Yellow
            }

            if (-not $sandboxCurrentlyPresent) {
                $sandboxMissingSeconds++
                if ($demoSawStaleHeartbeat -and -not $demoRestartConfirmed) {
                    if (-not $demoRestartDetectionClock) {
                        $demoRestartDetectionClock = [System.Diagnostics.Stopwatch]::StartNew()
                        Add-Content -Path $ReportFile -Value "[SANDBOX] The Sandbox session disappeared while the runner heartbeat was stale. Waiting up to $SandboxRestartDetectionGraceSeconds seconds for the guest or session to return."
                        Write-Host "[!] Sandbox disappeared after the runner heartbeat became stale. Waiting up to $SandboxRestartDetectionGraceSeconds seconds for restart recovery." -ForegroundColor Yellow
                    }
                    $restartWaitMilliseconds = ($SandboxRestartDetectionGraceSeconds * 1000) - $demoRestartDetectionClock.ElapsedMilliseconds
                    if ($restartWaitMilliseconds -le 0) {
                        if (-not $demoRestartDetectionReported) {
                            Add-Content -Path $ReportFile -Value "[SANDBOX] The Sandbox session did not return within the bounded $SandboxRestartDetectionGraceSeconds-second recovery window; no restarted runner was observed."
                            Write-Host "[!] Sandbox did not return within the bounded recovery window; preserving the current verdict." -ForegroundColor Yellow
                            $demoRestartDetectionReported = $true
                        }
                        $sandboxUnavailableDuringDemo = $true
                        break
                    }
                    $demoKnownClientIds = $currentDemoClientIds
                    $demoKnownSessionIds = $currentDemoSessionIds
                    Start-Sleep -Milliseconds ([int][Math]::Min(1000, $restartWaitMilliseconds))
                    continue
                }
                $missingWindowLimit = if ($demoRecoverySeen) { $SandboxRestartWindowGraceSeconds } else { 3 }
                if ($sandboxMissingSeconds -ge $missingWindowLimit) {
                    $sandboxUnavailableDuringDemo = $true
                    if ($runStatus -ne "VIRUS") { $runReason = "Windows Sandbox was closed during the demonstration. The suspicious sample remains classified as suspicious." }
                    Add-Content -Path $ReportFile -Value "[SANDBOX] The Sandbox client and session disappeared; ending the demonstration immediately without clearing the threat verdict."
                    Write-Host "[!] Sandbox was closed. Ending this item and continuing the queue." -ForegroundColor Red
                    break
                }

                $demoKnownClientIds = $currentDemoClientIds
                $demoKnownSessionIds = $currentDemoSessionIds
                Start-Sleep -Milliseconds 1000
                continue
            }
            $sandboxMissingSeconds = 0

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
                        Add-Content -Path $ReportFile -Value "[SANDBOX] Payload launch is confirmed; allowing $DemoLaunchSettleSeconds seconds for the visible application/files to appear before starting the $DemoVisibleSeconds-second demonstration timer."
                        Write-Host "[*] Payload launch is confirmed. Giving $DemoLaunchSettleSeconds seconds for its window and files to appear before the visible timer." -ForegroundColor Green
                    }
                    if ($demoReadySince.Elapsed.TotalSeconds -ge $DemoLaunchSettleSeconds) {
                        $demoTimer = [System.Diagnostics.Stopwatch]::StartNew()
                        $demoReadySince = $null
                        $remainingSeconds = $DemoVisibleSeconds
                        $lastLoggedRemaining = -1
                        Add-Content -Path $ReportFile -Value "[SANDBOX] The $DemoLaunchSettleSeconds-second appearance grace ended; started the fixed $DemoVisibleSeconds-second demonstration timer."
                        Write-Host "[*] The visible $DemoVisibleSeconds-second demonstration starts now." -ForegroundColor Green
                    } else {
                        $demoKnownClientIds = $currentDemoClientIds
                        $demoKnownSessionIds = $currentDemoSessionIds
                        Start-Sleep -Milliseconds 1000
                        continue
                    }
                } elseif ($demoGuestState -in @("UNSUPPORTED", "ERROR")) {
                    $demoReadySince = $null
                    $demoFailureDetail = if ($demoGuestStatus -and $demoGuestStatus.details) { ([string]$demoGuestStatus.details -replace '[\r\n]+', ' ').Trim() } else { "No detailed guest error was reported." }
                    Add-Content -Path $ReportFile -Value "[SANDBOX] Guest setup ended in $demoGuestState before the demonstration readiness conditions were met; skipped the demonstration timer. Detail: $demoFailureDetail"
                    Write-Host "[!] Guest setup ended in $demoGuestState before the payload launch was confirmed. $demoFailureDetail" -ForegroundColor Yellow
                    if ($deferredRuntimeSignalStatus) {
                        $runStatus = "INCONCLUSIVE"
                        $runReason = "Runtime setup failed before the required sample retry was confirmed: $($demoGuestStatus.details) Previously recorded behavior signal for manual review: $deferredRuntimeSignalReason"
                    }
                    break
                } else {
                    $demoReadySince = $null
                    $demoReadinessWaitSeconds++
                    if ($demoReadinessWaitSeconds -ge $SandboxStartupTimeoutSeconds) {
                        $sandboxUnavailableDuringDemo = $true
                        Add-Content -Path $ReportFile -Value "[SANDBOX] Guest did not report a ready state before the demonstration timeout."
                        Write-Host "[!] Guest did not become ready for the demonstration; continuing the queue." -ForegroundColor Yellow
                        break
                    }
                    Start-Sleep -Milliseconds 1000
                    continue
                }
            }

            $remainingMilliseconds = ($DemoVisibleSeconds * 1000) - $demoTimer.ElapsedMilliseconds
            if ($remainingMilliseconds -le 0) {
                if ($demoSawStaleHeartbeat -and -not $demoRestartConfirmed) {
                    if (-not $demoRestartDetectionClock) {
                        $demoRestartDetectionClock = [System.Diagnostics.Stopwatch]::StartNew()
                        Add-Content -Path $ReportFile -Value "[SANDBOX] The visible timer ended while the runner heartbeat was stale. Waiting up to $SandboxRestartDetectionGraceSeconds additional seconds for a confirmed guest or Sandbox restart."
                        Write-Host "[!] The visible timer ended while the runner heartbeat was stale. Checking for a restart for up to $SandboxRestartDetectionGraceSeconds more seconds." -ForegroundColor Yellow
                    }
                    $restartWaitMilliseconds = ($SandboxRestartDetectionGraceSeconds * 1000) - $demoRestartDetectionClock.ElapsedMilliseconds
                    if ($restartWaitMilliseconds -le 0) {
                        if (-not $demoRestartDetectionReported) {
                            Add-Content -Path $ReportFile -Value "[SANDBOX] No restarted runner or new Sandbox session was observed within the bounded $SandboxRestartDetectionGraceSeconds-second recovery window; the guest heartbeat remained unconfirmed."
                            Write-Host "[!] No Sandbox restart was confirmed within the bounded recovery window; preserving the current verdict." -ForegroundColor Yellow
                            $demoRestartDetectionReported = $true
                        }
                        break
                    }
                    $restartWaitSeconds = [int][Math]::Ceiling($restartWaitMilliseconds / 1000.0)
                    if (($restartWaitSeconds % 5 -eq 0 -or $restartWaitSeconds -eq 1) -and $restartWaitSeconds -ne $lastLoggedRemaining) {
                        Write-Host "[*] Restart detection window remaining: $restartWaitSeconds seconds." -ForegroundColor Cyan
                        $lastLoggedRemaining = $restartWaitSeconds
                    }
                    $demoKnownClientIds = $currentDemoClientIds
                    $demoKnownSessionIds = $currentDemoSessionIds
                    Start-Sleep -Milliseconds ([int][Math]::Min(1000, $restartWaitMilliseconds))
                    continue
                }
                break
            }
            $remainingSeconds = [int][Math]::Ceiling($remainingMilliseconds / 1000.0)
            if (($remainingSeconds % 5 -eq 0 -or $remainingSeconds -eq 1) -and $remainingSeconds -ne $lastLoggedRemaining) {
                Write-Host "[*] Demonstration time remaining: $remainingSeconds seconds. The sample stays inside Windows Sandbox." -ForegroundColor Cyan
                $lastLoggedRemaining = $remainingSeconds
            }
            $demoKnownClientIds = $currentDemoClientIds
            $demoKnownSessionIds = $currentDemoSessionIds
            Start-Sleep -Milliseconds ([int][Math]::Min(1000, $remainingMilliseconds))
        }

        if ($demoTimer -and -not $sandboxUnavailableDuringDemo -and $demoTimer.ElapsedMilliseconds -ge ($DemoVisibleSeconds * 1000)) {
            $demonstrationElapsedSeconds = $DemoVisibleSeconds
            Add-Content -Path $ReportFile -Value "[SANDBOX] The fixed $DemoVisibleSeconds-second demonstration ended; shutting down Windows Sandbox immediately."
            Write-Host "[*] The $DemoVisibleSeconds-second demonstration is complete; shutting down Windows Sandbox now." -ForegroundColor Green
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
            $sessionStillOpenNow = Test-WindowsSandboxSessionRunning -SessionId $sandboxSessionId
            if ($clientsStillOpen.Count -eq 0 -and -not $sessionStillOpenNow) {
                $sandboxStopped = $true
                Add-Content -Path $ReportFile -Value "[SANDBOX] Session had already exited; no live Sandbox client or session remained to stop."
                Write-Host "[*] Sandbox session has already exited. Finalizing this file and continuing the queue." -ForegroundColor DarkGray
            }
        }
        if ($sandboxStopped) {
            if ($sandboxUnavailableDuringDemo) {
                Add-Content -Path $ReportFile -Value "[SANDBOX] No live session returned within the short restart grace; continuing the queue."
            } elseif ($demonstrationElapsedSeconds -ge $DemoVisibleSeconds) {
                Add-Content -Path $ReportFile -Value "[SANDBOX] Completed the fixed $DemoVisibleSeconds-second demonstration interval, then stopped."
            } else {
                Add-Content -Path $ReportFile -Value "[SANDBOX] Stopped after analysis."
            }
            Write-Host "[*] Sandbox closed. Finalizing this file, then continuing the queue." -ForegroundColor DarkGray
        }
        if (-not $sandboxStopped) {
            Write-Host "[!] Automatic Sandbox shutdown was not confirmed. Close this session manually; the queue will wait before processing the next file." -ForegroundColor Yellow
            $lastShutdownWaitNoticeUtc = [DateTime]::MinValue
            $shutdownWaitDeadlineUtc = [DateTime]::UtcNow.AddSeconds($SandboxShutdownWaitSeconds)
            do {
                Start-Sleep -Seconds 2
                $remainingClients = @(Get-WindowsSandboxProcesses |
                    Where-Object { $_.Id -in $sandboxClientIds })
                $sessionStillOpen = Test-WindowsSandboxSessionRunning -SessionId $sandboxSessionId
                if (($remainingClients.Count -gt 0 -or $sessionStillOpen) -and
                    ([DateTime]::UtcNow - $lastShutdownWaitNoticeUtc).TotalSeconds -ge 10) {
                    Write-Host "[*] Waiting for the current Sandbox session to close..." -ForegroundColor DarkGray
                    $lastShutdownWaitNoticeUtc = [DateTime]::UtcNow
                }
            } while (($remainingClients.Count -gt 0 -or $sessionStillOpen) -and [DateTime]::UtcNow -lt $shutdownWaitDeadlineUtc)
            if ($remainingClients.Count -eq 0 -and -not $sessionStillOpen) {
                $sandboxStopped = $true
                Add-Content -Path $ReportFile -Value "[SANDBOX] Closed manually after automatic shutdown could not be confirmed."
            } else {
                $queueMustStop = $true
                Add-Content -Path $ReportFile -Value "[SANDBOX] Shutdown remained unconfirmed after $SandboxShutdownWaitSeconds seconds. Stopped the queue instead of running another sample in a possibly active session."
                Write-Host "[!] Sandbox is still unconfirmed as closed after $SandboxShutdownWaitSeconds seconds. The current file will be finalized for review, and the queue will stop." -ForegroundColor Yellow
                if ($runStatus -notin @("SUSPICIOUS", "VIRUS")) {
                    $runStatus = "INCONCLUSIVE"
                    $runReason = "Windows Sandbox shutdown could not be confirmed within the allowed wait. The sample is preserved for review and the queue stopped to avoid using a possibly active session."
                }
            }
        }
    }

    if ($startedSandbox) {
        $bootstrapLogText = Get-SandboxBootstrapLogText
        if ($bootstrapLogText) {
            Add-Content -Path $ReportFile -Value ("[SANDBOX] Guest bootstrap log (last lines):" + [Environment]::NewLine + $bootstrapLogText)
        } elseif (-not $runnerConfirmed) {
            Add-Content -Path $ReportFile -Value "[SANDBOX] No runner-bootstrap.log was created. The Sandbox logon command may not have run, the mapped Telemetry folder may have failed to mount, or the guest could not write to it."
        }
    }

    if ($sampleReadLock) {
        try { $sampleReadLock.Dispose() } catch {}
        $sampleReadLock = $null
    }
    if ($analysisWsbFile -and (Test-Path -LiteralPath $analysisWsbFile)) {
        Remove-Item -LiteralPath $analysisWsbFile -Force -ErrorAction SilentlyContinue
    }
    $stagedSamplePath = Join-Path $PayloadFolder $originalName
    if ($stagedSamplePrepared -and $runStatus -notin @("SUSPICIOUS", "VIRUS") -and (Test-Path -LiteralPath $stagedSamplePath)) {
        try {
            Remove-Item -LiteralPath $stagedSamplePath -Force -ErrorAction Stop
        } catch {
            Add-Content -Path $ReportFile -Value "[ACTION] Could not remove the temporary Sandbox copy at ${stagedSamplePath}: $($_.Exception.Message)"
            Write-Host "[!] Could not remove the temporary Sandbox copy: $stagedSamplePath" -ForegroundColor Yellow
        }
    }

    $verdictText = "[VERDICT] " + $runStatus + [Environment]::NewLine + "[DETAIL] " + $runReason
    Add-Content -Path $ReportFile -Value $verdictText

    if (-not $processingReady) {
        $SkippedQueuePaths[$sampleQueueKey] = $true
        if ($defenderBlockedSample) {
            Add-Content -Path $ReportFile -Value "[ACTION] Antivirus blocked the pipeline from accessing $($sample.FullName). The pipeline did not restore, recreate, or delete it; check Windows Security Protection History for the antivirus action."
            Write-Host "[!] $runReason" -ForegroundColor Red
            Write-Host "[!] Skipping this path for the current run; check Windows Security Protection History." -ForegroundColor Yellow
        } else {
            Add-Content -Path $ReportFile -Value "[ACTION] Original file was left unchanged at $($sample.FullName)."
            Write-Host "[!] $runReason" -ForegroundColor Yellow
            Write-Host "[!] Original file left unchanged and skipped for this run: $($sample.FullName)" -ForegroundColor Yellow
        }
    } elseif ($runStatus -in @("SUSPICIOUS", "VIRUS")) {
        $alertSource = if ($behaviorThreatConfirmed) { "Behavior monitoring" } else { "VirusTotal" }
        Write-Host "[!] $alertSource flagged the sample. Deleting it from Downloads and removing the temporary Sandbox copy..." -ForegroundColor Red
        $originalDeleted = $false
        $deleteError = $null
        if (Test-Path -LiteralPath $sourcePath) {
            try {
                Remove-Item -LiteralPath $sourcePath -Force -ErrorAction Stop
                $originalDeleted = -not (Test-Path -LiteralPath $sourcePath)
                if (-not $originalDeleted) { throw "The file still exists after the delete request." }
            } catch {
                $deleteError = $_.Exception.Message
            }
        }
        if ($stagedSamplePrepared -and (Test-Path -LiteralPath $stagedSamplePath)) {
            try {
                Remove-Item -LiteralPath $stagedSamplePath -Force -ErrorAction Stop
            } catch {
                Add-Content -Path $ReportFile -Value "[ACTION] Could not remove the temporary Sandbox copy at ${stagedSamplePath}: $($_.Exception.Message)"
            }
        }
        if ($originalDeleted) {
            Add-Content -Path $ReportFile -Value "[ACTION] Flagged original permanently deleted from Downloads. The temporary Sandbox copy was removed when possible."
            Write-Host "[!] Flagged sample deleted from Downloads." -ForegroundColor Red
        } elseif ($deleteError) {
            Add-Content -Path $ReportFile -Value "[ACTION] Could not delete the flagged original: $deleteError. Check Windows Security Protection History; if it remains at $sourcePath, remove it manually."
            Write-Host "[!] Could not delete the flagged sample. Check Windows Security Protection History; if it remains, remove it from $sourcePath" -ForegroundColor Yellow
        } else {
            Add-Content -Path $ReportFile -Value "[ACTION] No original sample remained to delete; Windows Security may already have removed or quarantined it."
        }
    } elseif (-not (Test-Path -LiteralPath $sourcePath)) {
        Add-Content -Path $ReportFile -Value "[ACTION] Source file disappeared during analysis while the pipeline verdict was $runStatus. This action branch does not delete the file; check Windows Security Protection History or another antivirus quarantine."
        Write-Host "[!] Source file disappeared during analysis with verdict $runStatus. This branch did not delete it; check Windows Security Protection History or another antivirus quarantine." -ForegroundColor Yellow
    } elseif ($runStatus -eq "NO DETECTION") {
        try {
            $finalDest = Move-FileToUniqueDestination -SourcePath $sourcePath -DestinationFolder $SafeFilesFolder -FileName $originalName
            Add-Content -Path $ReportFile -Value "[ACTION] No alert in the completed checks; file moved to $finalDest"
            $noDetectionLimit = if ($sandboxSkippedReason) {
                "[LIMIT] NO DETECTION is not proof that a file is safe. Only VirusTotal's completed scan was used; dynamic Sandbox execution was skipped."
            } else {
                "[LIMIT] NO DETECTION is not proof that a file is safe. The verdict reflects VirusTotal's completed scan and the bounded Sandbox behavior observation."
            }
            Add-Content -Path $ReportFile -Value $noDetectionLimit
            Write-Host "[+] No detections in completed checks. Moved to Safe_Files: $finalDest (this is not a guarantee of safety)." -ForegroundColor Green
        } catch {
            Add-Content -Path $ReportFile -Value "[ACTION] Could not move the file to Safe_Files: $($_.Exception.Message). It remains at $sourcePath."
            Write-Host "[!] Could not move the file; it remains at: $sourcePath" -ForegroundColor Yellow
        }
    } else {
        try {
            $reviewDest = Move-FileToUniqueDestination -SourcePath $sourcePath -DestinationFolder $ReviewFilesFolder -FileName "$originalName.processing"
            Add-Content -Path $ReportFile -Value "[ACTION] Inconclusive sample preserved for review at $reviewDest"
            Write-Host "[!] INCONCLUSIVE. Preserved for review: $reviewDest" -ForegroundColor Yellow
        } catch {
            Add-Content -Path $ReportFile -Value "[ACTION] File remains at $sourcePath. Could not move to review: $($_.Exception.Message)"
            Write-Host "[!] INCONCLUSIVE. File remains at: $sourcePath" -ForegroundColor Yellow
        }
    }

    if ((-not $startedSandbox -or $sandboxStopped) -and (Test-Path -LiteralPath $StagingFolder -PathType Container)) {
        try {
            Remove-Item -LiteralPath $StagingFolder -Recurse -Force -ErrorAction Stop
        } catch {
            Add-Content -Path $ReportFile -Value "[ACTION] Could not remove temporary staging folder ${StagingFolder}: $($_.Exception.Message)"
        }
    }

    if ($queueRecoveryMarker -and -not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
        try {
            Remove-Item -LiteralPath $queueRecoveryMarker -Force -ErrorAction Stop
        } catch {
            Add-Content -Path $ReportFile -Value "[QUEUE] Could not remove the completed recovery record '$queueRecoveryMarker': $($_.Exception.Message)"
        }
    }

    if ($queueMustStop) {
        Write-Host "[+] Item finished. Report: $ReportFile" -ForegroundColor Green
        Write-Host "[!] Queue stopped because Sandbox shutdown could not be confirmed. Close or restart Windows Sandbox, then rerun the analyzer." -ForegroundColor Yellow
        exit 2
    }
    Write-Host "[+] Item finished. Continuing the queue. Report: $ReportFile" -ForegroundColor Green
    Start-Sleep -Seconds 2
}
