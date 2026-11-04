param ([switch]$AllowOnlineRuntimeInstall)

$ErrorActionPreference = "Stop"
$script:AllowOnlineRuntimeInstall = [bool]$AllowOnlineRuntimeInstall

$StageFolder = "C:\Sample"
$PayloadFolder = Join-Path $StageFolder "payload"
$TelemetryFile = "C:\Telemetry\runner-status.json"
$RunnerHistoryFile = "C:\Telemetry\runner-start-history.log"
$FeatureSourceFolder = "C:\FeatureSource"
$ObservationSeconds = 35
$MsiObservationSeconds = 180
$GuestReviewHeartbeatSeconds = 300
$PostRebootCheckSeconds = 8
$MaxZipEntries = 10000
$MaxExpandedBytes = 536870912
$MaxEntryRatio = 200
$MaxArchiveInspectionSeconds = 120
$MaxMonitoredFiles = 20000
$MaxMonitoredDirectories = 50000
$MaxGuestInventorySeconds = 10
$ObservationIntervalSeconds = 2
$LaunchRuntimePromptGraceSeconds = 5
$NetFx3SourceFolder = "C:\NetFx3Source\sources\sxs"
$RunnerInstanceId = [Guid]::NewGuid().ToString("N")
$script:RunnerMutex = [System.Threading.Mutex]::new($false, "Local\RBI_GuestRunner")
$runnerMutexAcquired = $false
try {
    $runnerMutexAcquired = $script:RunnerMutex.WaitOne(0)
} catch [System.Threading.AbandonedMutexException] {
    $runnerMutexAcquired = $true
}
if (-not $runnerMutexAcquired) {
    Write-Output "[BOOTSTRAP] Another guest runner instance is already active; skipping the duplicate start."
    exit 0
}
$script:VbScriptEngineReady = $false
$script:VbScriptRuntimeFailure = $null
$script:GuestMonitorTruncated = $false
$script:GuestMonitorTruncatedReason = $null

function Register-RunnerForGuestLogon {
    try {
        $runKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        $powerShellPath = Join-Path $PSHOME "powershell.exe"
        $runnerPath = $PSCommandPath
        $runnerCommand = '"{0}" -NoLogo -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "{1}"' -f $powerShellPath, $runnerPath
        if ($script:AllowOnlineRuntimeInstall) {
            $runnerCommand += " -AllowOnlineRuntimeInstall"
        }
        New-Item -Path $runKeyPath -Force -ErrorAction Stop | Out-Null
        New-ItemProperty -Path $runKeyPath -Name "AutomatedMalwareAnalysisPipeline" -Value $runnerCommand -PropertyType String -Force -ErrorAction Stop | Out-Null
        return $true
    } catch {
        $script:RunnerLogonRegistrationError = $_.Exception.Message
        return $false
    }
}

function Set-RunnerStatus {
    param (
        [string]$State,
        [string]$Details,
        [int]$Launched = 0
    )

    if ($State -eq "STARTED") {
        try {
            $historyLine = $RunnerInstanceId + "|" + [DateTime]::UtcNow.ToString("o") + [Environment]::NewLine
            [System.IO.File]::AppendAllText($RunnerHistoryFile, $historyLine, [System.Text.Encoding]::UTF8)
        } catch {}
    }

    $status = [ordered]@{
        state = $State
        details = $Details
        launched = $Launched
        instanceId = $RunnerInstanceId
        updated = (Get-Date).ToString("o")
    }
    $statusJson = $status | ConvertTo-Json -Compress
    $statusTempFile = Join-Path (Split-Path -Parent $TelemetryFile) ("runner-status-{0}.tmp" -f [Guid]::NewGuid().ToString("N"))
    try {
        [System.IO.File]::WriteAllText($statusTempFile, $statusJson, (New-Object System.Text.UTF8Encoding($false)))
        if ([System.IO.File]::Exists($TelemetryFile)) {
            try {
                [System.IO.File]::Replace($statusTempFile, $TelemetryFile, $null)
            } catch {
                Move-Item -LiteralPath $statusTempFile -Destination $TelemetryFile -Force -ErrorAction Stop
            }
        } else {
            [System.IO.File]::Move($statusTempFile, $TelemetryFile)
        }
    } finally {
        if ([System.IO.File]::Exists($statusTempFile)) {
            Remove-Item -LiteralPath $statusTempFile -Force -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-DismWithProgress {
    param (
        [string]$Executable,
        [string[]]$Arguments,
        [string]$Component,
        [string]$LogPath,
        [string]$StatusState = "PREPARING_RUNTIME",
        [int]$Launched = 0
    )

    $script:LastDismProgressPercent = -1
    try { "DISM started for $Component at $([DateTime]::UtcNow.ToString('o'))." | Set-Content -LiteralPath $LogPath -Encoding UTF8 -ErrorAction Stop } catch {}
    $dismOutput = @(& $Executable @Arguments 2>&1 | ForEach-Object {
        $line = "$_"
        try { Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8 -ErrorAction Stop } catch {}
        $progressMatch = [regex]::Match($line, '(?<![\d.])(?<percent>\d{1,3}(?:\.\d+)?)\s*%')
        if ($progressMatch.Success) {
            $progressPercent = [int][Math]::Floor([double]::Parse($progressMatch.Groups["percent"].Value, [Globalization.CultureInfo]::InvariantCulture))
            if ($progressPercent -gt $script:LastDismProgressPercent) {
                $script:LastDismProgressPercent = $progressPercent
                $sampleContext = if ($StatusState -eq "INSTALLING_RUNTIME") { "The sample is paused for runtime repair." } else { "The sample has not launched." }
                Set-RunnerStatus -State $StatusState -Details "Installing ${Component}: DISM reports $progressPercent% complete. $sampleContext" -Launched $Launched
            }
        }
        $line
    })
    $dismExitCode = $LASTEXITCODE
    try { "DISM exited with code $dismExitCode at $([DateTime]::UtcNow.ToString('o'))." | Add-Content -LiteralPath $LogPath -Encoding UTF8 -ErrorAction Stop } catch {}

    return [pscustomobject]@{
        ExitCode = $dismExitCode
        Output = $dismOutput
    }
}

function Disable-SandboxSmartScreen {
    $policyPath = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System"
    New-Item -Path $policyPath -Force | Out-Null
    New-ItemProperty -LiteralPath $policyPath -Name "EnableSmartScreen" -Value 0 -PropertyType DWord -Force | Out-Null

    $configuredValue = (Get-ItemProperty -LiteralPath $policyPath -Name "EnableSmartScreen" -ErrorAction Stop).EnableSmartScreen
    if ([int]$configuredValue -ne 0) {
        throw "Could not disable SmartScreen inside the disposable Sandbox guest. The sample was not launched."
    }
}

function Initialize-RuntimeWindowApi {
    if (-not ("SandboxRuntimeWindowApi" -as [type])) {
        Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public sealed class SandboxRuntimeWindowInfo
{
    public IntPtr Handle { get; set; }
    public string Title { get; set; }
    public string Text { get; set; }
    public uint ProcessId { get; set; }
}

public static class SandboxRuntimeWindowApi
{
    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    private delegate bool EnumChildProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool EnumWindows(EnumWindowsProc callback, IntPtr lParam);
    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool EnumChildWindows(IntPtr hWnd, EnumChildProc callback, IntPtr lParam);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int maxCount);
    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);
    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool PostMessage(IntPtr hWnd, uint message, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int command);
    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    private static string ReadText(IntPtr hWnd)
    {
        StringBuilder text = new StringBuilder(2048);
        GetWindowText(hWnd, text, text.Capacity);
        return text.ToString();
    }

    public static SandboxRuntimeWindowInfo[] GetVisibleWindows()
    {
        List<SandboxRuntimeWindowInfo> windows = new List<SandboxRuntimeWindowInfo>();
        EnumWindows(delegate(IntPtr hWnd, IntPtr lParam)
        {
            if (!IsWindowVisible(hWnd)) return true;
            string title = ReadText(hWnd);
            StringBuilder content = new StringBuilder();
            EnumChildWindows(hWnd, delegate(IntPtr child, IntPtr childParam)
            {
                if (IsWindowVisible(child))
                {
                    string text = ReadText(child);
                    if (!String.IsNullOrWhiteSpace(text)) content.AppendLine(text);
                }
                return true;
            }, IntPtr.Zero);
            uint processId;
            GetWindowThreadProcessId(hWnd, out processId);
            windows.Add(new SandboxRuntimeWindowInfo
            {
                Handle = hWnd,
                Title = title,
                Text = content.ToString(),
                ProcessId = processId
            });
            return true;
        }, IntPtr.Zero);
        return windows.ToArray();
    }

    public static bool ActivateVisibleWindowForProcess(uint targetProcessId)
    {
        foreach (SandboxRuntimeWindowInfo window in GetVisibleWindows())
        {
            if (window.ProcessId != targetProcessId) continue;
            ShowWindow(window.Handle, 9); // SW_RESTORE
            return SetForegroundWindow(window.Handle);
        }
        return false;
    }

    public static bool CloseWindow(IntPtr hWnd)
    {
        return PostMessage(hWnd, 0x0010, IntPtr.Zero, IntPtr.Zero); // WM_CLOSE
    }

    public static bool IsVisibleWindow(IntPtr hWnd)
    {
        return IsWindowVisible(hWnd);
    }

    public static uint GetWindowProcessId(IntPtr hWnd)
    {
        uint processId;
        GetWindowThreadProcessId(hWnd, out processId);
        return processId;
    }

    public static IntPtr GetForegroundWindowHandle()
    {
        return GetForegroundWindow();
    }
}
'@
    }
}

function Find-MissingRuntimePrompt {
    Initialize-RuntimeWindowApi
    foreach ($window in [SandboxRuntimeWindowApi]::GetVisibleWindows()) {
        $dialogText = [string]$window.Text
        if ([string]$window.Title -match "(?i)Windows Script Host" -and
            $dialogText -match "(?is)There is no script engine for file extension.*\.vbs") {
            return [pscustomobject]@{ Runtime = "VBScript"; Handle = $window.Handle; ProcessId = $window.ProcessId }
        }
        if ($dialogText -match "(?is)\.NET Framework 3\.5" -and
            $dialogText -match "(?i)Download and install this feature|needs the following Windows feature") {
            return [pscustomobject]@{ Runtime = "NetFx3"; Handle = $window.Handle; ProcessId = $window.ProcessId }
        }
    }
    try {
        Add-Type -AssemblyName UIAutomationClient -ErrorAction Stop
        Add-Type -AssemblyName UIAutomationTypes -ErrorAction Stop
        $foregroundHandle = [SandboxRuntimeWindowApi]::GetForegroundWindowHandle()
        if ($foregroundHandle -ne [IntPtr]::Zero) {
            $foregroundElement = [System.Windows.Automation.AutomationElement]::FromHandle($foregroundHandle)
            $dialogText = New-Object System.Text.StringBuilder
            [void]$dialogText.Append([string]$foregroundElement.Current.Name)
            $descendants = $foregroundElement.FindAll(
                [System.Windows.Automation.TreeScope]::Descendants,
                [System.Windows.Automation.Condition]::TrueCondition
            )
            foreach ($element in $descendants) {
                try {
                    $elementName = [string]$element.Current.Name
                    if (-not [string]::IsNullOrWhiteSpace($elementName)) { [void]$dialogText.Append(" ").Append($elementName) }
                } catch {}
            }
            $automationText = $dialogText.ToString()
            if ($automationText -match "(?is)There is no script engine for file extension.*\.vbs") {
                return [pscustomobject]@{ Runtime = "VBScript"; Handle = $foregroundHandle; ProcessId = [SandboxRuntimeWindowApi]::GetWindowProcessId($foregroundHandle) }
            }
            if ($automationText -match "(?is)\.NET Framework 3\.5" -and
                $automationText -match "(?i)Download and install this feature|needs the following Windows feature") {
                return [pscustomobject]@{ Runtime = "NetFx3"; Handle = $foregroundHandle; ProcessId = [SandboxRuntimeWindowApi]::GetWindowProcessId($foregroundHandle) }
            }
        }
    } catch {}
    return $null
}

function Find-MissingDependencyPrompt {
    Initialize-RuntimeWindowApi
    foreach ($window in [SandboxRuntimeWindowApi]::GetVisibleWindows()) {
        $dialogText = ([string]$window.Title + ' ' + [string]$window.Text)
        $containsDllName = $dialogText -match '(?i)\b[\w.+-]+\.dll\b'
        $containsMissingDependencyText = $dialogText -match '(?i)was not found|is missing|cannot be found|could not be found|missing from|unable to locate component|specified module could not be found'
        if ($containsDllName -and $containsMissingDependencyText) {
            return [pscustomobject]@{
                Handle = $window.Handle
                ProcessId = $window.ProcessId
                Details = ($dialogText -replace '\s+', ' ').Trim()
            }
        }
    }
    return $null
}

function Close-MissingRuntimePrompt {
    param (
        [IntPtr]$Handle,
        [uint32]$ProcessId
    )
    Initialize-RuntimeWindowApi
    if (-not [SandboxRuntimeWindowApi]::IsVisibleWindow($Handle)) { return $true }
    if ($ProcessId -and [SandboxRuntimeWindowApi]::GetWindowProcessId($Handle) -ne $ProcessId) { return $true }
    [void][SandboxRuntimeWindowApi]::CloseWindow($Handle)
    for ($attempt = 0; $attempt -lt 16; $attempt++) {
        if (-not [SandboxRuntimeWindowApi]::IsVisibleWindow($Handle)) { return $true }
        if ($ProcessId -and [SandboxRuntimeWindowApi]::GetWindowProcessId($Handle) -ne $ProcessId) { return $true }
        Start-Sleep -Milliseconds 250
    }
    return $false
}

function Get-ArchiveContents {
    param ([string]$ArchivePath)

    $archiveTimer = [Diagnostics.Stopwatch]::StartNew()
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = $null
    $tempFolder = Join-Path $env:TEMP ("Sample-" + [Guid]::NewGuid().ToString("N"))
    $expandedBytes = [long]0
    $actualExpandedBytes = [long]0
    $keepTempFolder = $false

    try {
        $archive = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)
        if ($archive.Entries.Count -gt $MaxZipEntries) {
            return [pscustomobject]@{ State = "ZIP_BOMB"; Details = "Archive contains more than $MaxZipEntries entries."; Files = @() }
        }
        $fileEntries = @($archive.Entries | Where-Object { -not [string]::IsNullOrEmpty($_.Name) })

        foreach ($entry in $fileEntries) {
            if ($archiveTimer.Elapsed.TotalSeconds -ge $MaxArchiveInspectionSeconds) {
                return [pscustomobject]@{ State = "UNSUPPORTED"; Details = "ZIP inspection exceeded the $MaxArchiveInspectionSeconds-second time limit before extraction completed."; Files = @() }
            }
            $relativePath = $entry.FullName.Replace('/', '\')
            if ([System.IO.Path]::IsPathRooted($relativePath) -or $relativePath -match '(^|\\)\.\.(\\|$)') {
                return [pscustomobject]@{ State = "UNSAFE_ARCHIVE"; Details = "Archive contains a path that escapes its extraction folder."; Files = @() }
            }

            if ($entry.Length -gt $MaxExpandedBytes -or $expandedBytes -gt ($MaxExpandedBytes - $entry.Length)) {
                return [pscustomobject]@{ State = "ZIP_BOMB"; Details = "Archive expands beyond the $MaxExpandedBytes-byte limit."; Files = @() }
            }
            $expandedBytes += $entry.Length

            if ($entry.Length -gt 10485760) {
                if ($entry.CompressedLength -eq 0 -or ($entry.Length / [double]$entry.CompressedLength) -gt $MaxEntryRatio) {
                    return [pscustomobject]@{ State = "ZIP_BOMB"; Details = "An archive entry exceeds the compression-ratio limit."; Files = @() }
                }
            }
        }

        $archiveFileSize = (Get-Item -LiteralPath $ArchivePath).Length
        if ($expandedBytes -gt 104857600 -and $archiveFileSize -gt 0 -and ($expandedBytes / [double]$archiveFileSize) -gt $MaxEntryRatio) {
            return [pscustomobject]@{ State = "ZIP_BOMB"; Details = "Archive exceeds the overall compression-ratio limit."; Files = @() }
        }

        New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null
        $tempRoot = [System.IO.Path]::GetFullPath($tempFolder).TrimEnd('\') + '\'
        foreach ($entry in $archive.Entries) {
            if ($archiveTimer.Elapsed.TotalSeconds -ge $MaxArchiveInspectionSeconds) {
                return [pscustomobject]@{ State = "UNSUPPORTED"; Details = "ZIP extraction exceeded the $MaxArchiveInspectionSeconds-second time limit; no payload was launched."; Files = @() }
            }
            $relativePath = $entry.FullName.Replace('/', '\')
            if ([string]::IsNullOrEmpty($relativePath)) { continue }
            $targetPath = [System.IO.Path]::GetFullPath((Join-Path $tempRoot $relativePath))
            if (-not $targetPath.StartsWith($tempRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
                return [pscustomobject]@{ State = "UNSAFE_ARCHIVE"; Details = "Archive contains a path that escapes its extraction folder."; Files = @() }
            }

            if ([string]::IsNullOrEmpty($entry.Name)) {
                New-Item -ItemType Directory -Path $targetPath -Force | Out-Null
                continue
            }

            New-Item -ItemType Directory -Path (Split-Path -Parent $targetPath) -Force | Out-Null
            $inputStream = $entry.Open()
            $outputStream = [System.IO.File]::Open($targetPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            try {
                $buffer = New-Object byte[] 65536
                $entryWritten = [long]0
                while (($read = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    if ($archiveTimer.Elapsed.TotalSeconds -ge $MaxArchiveInspectionSeconds) {
                        return [pscustomobject]@{ State = "UNSUPPORTED"; Details = "ZIP extraction exceeded the $MaxArchiveInspectionSeconds-second time limit; no payload was launched."; Files = @() }
                    }
                    $entryWritten += $read
                    if ($entryWritten -gt ($entry.Length + 1048576) -or
                        $entryWritten -gt $MaxExpandedBytes -or
                        $read -gt ($MaxExpandedBytes - $actualExpandedBytes)) {
                        return [pscustomobject]@{ State = "ZIP_BOMB"; Details = "Archive data expanded beyond its declared size or the $MaxExpandedBytes-byte aggregate limit."; Files = @() }
                    }
                    $actualExpandedBytes += $read
                    $outputStream.Write($buffer, 0, $read)
                }
                if ($entryWritten -ne $entry.Length) {
                    return [pscustomobject]@{ State = "UNSAFE_ARCHIVE"; Details = "An archive entry's actual size does not match its declared size."; Files = @() }
                }
            } finally {
                $inputStream.Dispose()
                $outputStream.Dispose()
            }
        }

        if ($archiveTimer.Elapsed.TotalSeconds -ge $MaxArchiveInspectionSeconds) {
            return [pscustomobject]@{ State = "UNSUPPORTED"; Details = "ZIP inspection exceeded the $MaxArchiveInspectionSeconds-second time limit; no payload was launched."; Files = @() }
        }
        $payloadFiles = New-Object System.Collections.ArrayList
        $nestedArchive = $null
        foreach ($payloadFile in Get-ChildItem -LiteralPath $tempFolder -Recurse -File) {
            if ($archiveTimer.Elapsed.TotalSeconds -ge $MaxArchiveInspectionSeconds) {
                return [pscustomobject]@{ State = "UNSUPPORTED"; Details = "ZIP inspection exceeded the $MaxArchiveInspectionSeconds-second time limit; no payload was launched."; Files = @() }
            }
            [void]$payloadFiles.Add($payloadFile)
            if ($payloadFile.Extension.ToLowerInvariant() -in @(".zip", ".7z", ".rar", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".cab", ".iso")) {
                $nestedArchive = $payloadFile
                break
            }
        }
        if ($nestedArchive) {
            return [pscustomobject]@{ State = "UNSUPPORTED"; Details = "Nested archives were not expanded; review this sample manually."; Files = @() }
        }

        if ($archiveTimer.Elapsed.TotalSeconds -ge $MaxArchiveInspectionSeconds) {
            return [pscustomobject]@{ State = "UNSUPPORTED"; Details = "ZIP inspection exceeded the $MaxArchiveInspectionSeconds-second time limit; no payload was launched."; Files = @() }
        }
        if ($payloadFiles.Count -eq 0) {
            return [pscustomobject]@{ State = "UNSUPPORTED"; Details = "The archive contains no files to analyze."; Files = @() }
        }

        $keepTempFolder = $true
        return [pscustomobject]@{ State = "READY"; Details = "Archive passed the extraction limits ($($fileEntries.Count) files, $actualExpandedBytes expanded bytes)."; Files = @($payloadFiles.ToArray()); WorkFolder = $tempFolder }
    } catch {
        $archiveError = ([string]$_.Exception.Message -replace '[\r\n]+', ' ').Trim()
        if ($archiveError.Length -gt 400) { $archiveError = $archiveError.Substring(0, 400) + "..." }
        return [pscustomobject]@{ State = "UNSUPPORTED"; Details = "ZIP could not be read or safely extracted; no payload was launched. $archiveError"; Files = @() }
    } finally {
        if ($archive) { $archive.Dispose() }
        if (-not $keepTempFolder -and (Test-Path -LiteralPath $tempFolder)) {
            Remove-Item -LiteralPath $tempFolder -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Initialize-VbScriptRuntime {
    param (
        [switch]$Required,
        [switch]$AfterLaunch,
        [int]$Launched = 0
    )

    if ($script:VbScriptEngineReady) { return $null }
    if ($script:VbScriptRuntimeFailure) {
        if ($Required) { throw "Unsupported payload runtime: $script:VbScriptRuntimeFailure" }
        return $script:VbScriptRuntimeFailure
    }

    $systemDll = Join-Path $env:SystemRoot "System32\vbscript.dll"
    $wowDll = Join-Path $env:SystemRoot "SysWOW64\vbscript.dll"
    $dismLog = Join-Path (Split-Path -Parent $TelemetryFile) "vbscript-install.log"
    $dllsPresent = @(@($systemDll, $wowDll) | Where-Object { Test-Path -LiteralPath $_ })
    $dismRestartNeeded = $false
    $runtimeStatusState = if ($AfterLaunch) { "INSTALLING_RUNTIME" } else { "PREPARING_RUNTIME" }
    $runtimeContext = if ($AfterLaunch) { "The sample launch is paused for runtime repair." } else { "The sample has not launched." }

    if ($dllsPresent.Count -eq 0) {
        if (-not (Test-Path -LiteralPath $FeatureSourceFolder)) {
            $script:VbScriptRuntimeFailure = "VBScript source folder C:\FeatureSource is missing."
        } else {
            $dism = Join-Path $env:SystemRoot "System32\dism.exe"
            $dismArguments = @("/Online", "/Add-Capability", "/CapabilityName:VBScript~~~~", "/Source:$FeatureSourceFolder", "/LimitAccess", "/NoRestart")
            Set-RunnerStatus -State $runtimeStatusState -Details "Installing the VBScript Feature on Demand from C:\FeatureSource with offline DISM. $runtimeContext" -Launched $Launched
            try {
                $dismResult = Invoke-DismWithProgress -Executable $dism -Arguments $dismArguments -Component "VBScript" -LogPath $dismLog -StatusState $runtimeStatusState -Launched $Launched
                $dismExitCode = $dismResult.ExitCode

                if ($dismExitCode -eq 3010) {
                    $dismRestartNeeded = $true
                    $script:VbScriptRuntimeFailure = "DISM installed VBScript but reports that the guest needs a restart; the sample was not launched. See C:\Telemetry\vbscript-install.log."
                } elseif ($dismExitCode -ne 0) {
                    $script:VbScriptRuntimeFailure = "DISM could not install VBScript from C:\FeatureSource (exit code $dismExitCode). See C:\Telemetry\vbscript-install.log and C:\Windows\Logs\DISM\dism.log."
                }
            } catch {
                $script:VbScriptRuntimeFailure = "Could not run DISM to install VBScript: $($_.Exception.Message)"
            }

            $dllsPresent = @(@($systemDll, $wowDll) | Where-Object { Test-Path -LiteralPath $_ })
            if ($dllsPresent.Count -eq 0 -and -not $script:VbScriptRuntimeFailure) {
                $script:VbScriptRuntimeFailure = "DISM returned success, but vbscript.dll is still missing. Check that C:\FeatureSource contains the matching VBScript Feature-on-Demand repository. See C:\Telemetry\vbscript-install.log."
            }
        }
    }

    if ($dllsPresent.Count -gt 0 -and -not $dismRestartNeeded) {
        try {
            Set-RunnerStatus -State $runtimeStatusState -Details "Registering the 64-bit and 32-bit VBScript engines and the .vbs handler. $runtimeContext" -Launched $Launched
            foreach ($vbscriptDll in $dllsPresent) {
                $regsvr = if ($vbscriptDll -like "*\SysWOW64\*") {
                    Join-Path $env:SystemRoot "SysWOW64\regsvr32.exe"
                } else {
                    Join-Path $env:SystemRoot "System32\regsvr32.exe"
                }
                if (-not (Test-Path -LiteralPath $regsvr)) { continue }

                $registration = Start-Process -FilePath $regsvr -ArgumentList @("/s", ('"' + $vbscriptDll + '"')) -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
                if ($registration.ExitCode -ne 0) {
                    throw "regsvr32 returned exit code $($registration.ExitCode) for $vbscriptDll."
                }
            }

            $extensionKey = "Registry::HKEY_CLASSES_ROOT\.vbs"
            $engineKey = "Registry::HKEY_CLASSES_ROOT\VBSFile\ScriptEngine"
            $openCommandKey = "Registry::HKEY_CLASSES_ROOT\VBSFile\Shell\Open\Command"
            New-Item -Path $extensionKey -Force | Out-Null
            New-Item -Path $engineKey -Force | Out-Null
            New-Item -Path $openCommandKey -Force | Out-Null
            Set-Item -LiteralPath $extensionKey -Value "VBSFile"
            Set-Item -LiteralPath $engineKey -Value "VBScript"
            Set-Item -LiteralPath $openCommandKey -Value '"C:\Windows\System32\WScript.exe" "%1" %*'

            $script:VbScriptEngineReady = $true
            $script:VbScriptRuntimeFailure = $null
            return $null
        } catch {
            $script:VbScriptRuntimeFailure = "VBScript engine registration failed: $($_.Exception.Message)"
        }
    }

    if (-not $script:VbScriptRuntimeFailure) {
        $script:VbScriptRuntimeFailure = "VBScript/Windows Script Host is unavailable."
    }
    if ($Required) { throw "Unsupported payload runtime: $script:VbScriptRuntimeFailure" }
    return $script:VbScriptRuntimeFailure
}

function Initialize-NetFx3Runtime {
    param (
        [switch]$AfterLaunch,
        [int]$Launched = 0
    )

    try {
        $netFxState = Get-WindowsOptionalFeature -Online -FeatureName NetFx3 -ErrorAction Stop
    } catch {
        return "Could not query the .NET Framework 3.5 optional feature: $($_.Exception.Message)"
    }
    if ($netFxState.State -eq "Enabled") { return $null }

    $netFxSource = $NetFx3SourceFolder
    $dism = Join-Path $env:SystemRoot "System32\dism.exe"
    $netFxLog = Join-Path (Split-Path -Parent $TelemetryFile) "netfx3-install.log"
    $runtimeStatusState = if ($AfterLaunch) { "INSTALLING_RUNTIME" } else { "PREPARING_RUNTIME" }
    $runtimeContext = if ($AfterLaunch) { "The sample launch is paused for runtime repair." } else { "The sample has not launched." }
    $nativeArchitecture = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    $packageArchitecture = switch -Regex ($nativeArchitecture) {
        "(?i)^amd64$" { "amd64"; break }
        "(?i)^arm64$" { "arm64"; break }
        default { "x86" }
    }
    $netFxNamePattern = '(?i)(netfx3|net-framework-3).*(ondemand|package).*\.cab$'
    $architecturePattern = "(?i)(?:^|[~._-])$packageArchitecture(?:[~._-]|\.cab$)"
    $netFxCandidates = @()
    if (Test-Path -LiteralPath $netFxSource -PathType Container) {
        $namedCandidates = @(Get-ChildItem -LiteralPath $netFxSource -File -Filter '*.cab' -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match $netFxNamePattern })
        $architectureCandidates = @($namedCandidates | Where-Object { $_.Name -match $architecturePattern })
        $netFxCandidates = @($architectureCandidates + @($namedCandidates | Where-Object { $_.FullName -notin @($architectureCandidates.FullName) }))
    }

    $netFxCab = $null
    $packageApplicabilityFailure = $null
    foreach ($candidate in $netFxCandidates) {
        try {
            $packageInfo = Get-WindowsPackage -Online -PackagePath $candidate.FullName -ErrorAction Stop
            $applicableValue = if ($packageInfo) { $packageInfo.Applicable } else { $null }
            $isApplicable = ($applicableValue -is [bool] -and $applicableValue) -or ([string]$applicableValue -match "(?i)^(yes|true)$")
            if ($isApplicable) {
                $netFxCab = $candidate
                $netFxSource = $candidate.DirectoryName
                break
            }
            $packageApplicabilityFailure = "DISM marked $($candidate.Name) as not applicable to this guest image."
        } catch {
            $packageApplicabilityFailure = "DISM could not verify $($candidate.Name): $($_.Exception.Message)"
        }
    }

    $offlineFailure = $null
    if ($netFxCab) {
        Set-RunnerStatus -State $runtimeStatusState -Details "Installing .NET Framework 3.5 from the matching $packageArchitecture package at $netFxSource. $runtimeContext" -Launched $Launched
        try {
            $offlineArguments = @("/Online", "/Enable-Feature", "/FeatureName:NetFx3", "/All", "/Source:$netFxSource", "/LimitAccess", "/NoRestart")
            $installResult = Invoke-DismWithProgress -Executable $dism -Arguments $offlineArguments -Component ".NET Framework 3.5" -LogPath $netFxLog -StatusState $runtimeStatusState -Launched $Launched
            if ($installResult.ExitCode -eq 3010) {
                return ".NET Framework 3.5 installation requires a guest restart; the pipeline will not automatically relaunch a sample after reboot."
            }
            if ($installResult.ExitCode -eq 0) {
                $netFxState = Get-WindowsOptionalFeature -Online -FeatureName NetFx3 -ErrorAction SilentlyContinue
                if ($netFxState.State -eq "Enabled") { return $null }
                $offlineFailure = "DISM returned success, but NetFx3 did not reach the Enabled state."
            } else {
                $offlineFailure = "The local NetFx3 source was rejected by DISM (exit code $($installResult.ExitCode))."
            }
        } catch {
            $offlineFailure = "The local NetFx3 installation failed: $($_.Exception.Message)"
        }
    } elseif ($packageApplicabilityFailure) {
        $candidateNames = if ($netFxCandidates.Count -gt 0) { ($netFxCandidates | Select-Object -ExpandProperty Name) -join ', ' } else { 'none' }
        $offlineFailure = "$packageApplicabilityFailure NetFx3 CAB candidates found: $candidateNames."
    } else {
        $allCabNames = if (Test-Path -LiteralPath $netFxSource -PathType Container) {
            $names = @(Get-ChildItem -LiteralPath $netFxSource -File -Filter '*.cab' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name -First 8)
            if ($names.Count -gt 0) { $names -join ', ' } else { 'none' }
        } else { 'source folder missing' }
        $offlineFailure = "No CAB whose name identifies a NetFx3 on-demand package was found in $netFxSource (CAB files present: $allCabNames). The separate VBScript Features-on-Demand repository at C:\FeatureSource is not a substitute for the Windows installation media SxS source."
    }

    if (-not $script:AllowOnlineRuntimeInstall) {
        return ".NET Framework 3.5 could not be installed from the local source. $offlineFailure Online fallback is disabled for this sample because its network was not cleared by the host scan. Copy the matching Windows installation ISO's sources\sxs folder to C:\RBI_NetFx3Source\sources\sxs on the host. See C:\Telemetry\netfx3-install.log."
    }

    try {
        $servicingPolicyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing"
        $windowsUpdatePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        New-Item -Path $servicingPolicyPath -Force | Out-Null
        New-ItemProperty -LiteralPath $servicingPolicyPath -Name "RepairContentServerSource" -PropertyType DWord -Value 2 -Force | Out-Null
        New-Item -Path $windowsUpdatePolicyPath -Force | Out-Null
        New-ItemProperty -LiteralPath $windowsUpdatePolicyPath -Name "UseWUServer" -PropertyType DWord -Value 0 -Force | Out-Null
        Set-Service -Name "wuauserv" -StartupType Manual -ErrorAction Stop
        $windowsUpdateService = Get-Service -Name "wuauserv" -ErrorAction Stop
        if ($windowsUpdateService.Status -eq "Running") {
            Restart-Service -Name "wuauserv" -Force -ErrorAction Stop
        } else {
            Start-Service -Name "wuauserv" -ErrorAction Stop
        }
    } catch {
        return ".NET Framework 3.5 could not use Windows Update directly after the local source failed: $($_.Exception.Message) Offline source detail: $offlineFailure"
    }

    Set-RunnerStatus -State $runtimeStatusState -Details "The local NetFx3 source was unavailable; downloading .NET Framework 3.5 from Microsoft Windows Update. The Sandbox network is permitted for this sample. $runtimeContext" -Launched $Launched
    try {
        $onlineArguments = @("/Online", "/Enable-Feature", "/FeatureName:NetFx3", "/All", "/NoRestart")
        $onlineInstallResult = Invoke-DismWithProgress -Executable $dism -Arguments $onlineArguments -Component ".NET Framework 3.5 (Windows Update)" -LogPath $netFxLog -StatusState $runtimeStatusState -Launched $Launched
    } catch {
        return ".NET Framework 3.5 could not be downloaded from Windows Update: $($_.Exception.Message) Offline source detail: $offlineFailure See C:\Telemetry\netfx3-install.log."
    }
    if ($onlineInstallResult.ExitCode -eq 3010) {
        return ".NET Framework 3.5 installation requires a guest restart; the pipeline will not automatically relaunch a sample after reboot."
    }
    if ($onlineInstallResult.ExitCode -ne 0) {
        return ".NET Framework 3.5 could not be installed from Windows Update (DISM exit code $($onlineInstallResult.ExitCode)). Offline source detail: $offlineFailure See C:\Telemetry\netfx3-install.log and C:\Windows\Logs\DISM\dism.log."
    }

    $netFxState = Get-WindowsOptionalFeature -Online -FeatureName NetFx3 -ErrorAction SilentlyContinue
    if ($netFxState.State -ne "Enabled") {
        return ".NET Framework 3.5 installation returned success but did not reach the Enabled state. Offline source detail: $offlineFailure"
    }
    return $null
}

function Start-Payload {
    param ([System.IO.FileInfo]$File)
    Unblock-File -LiteralPath $File.FullName -ErrorAction SilentlyContinue
    $quotedPath = '"' + $File.FullName + '"'
    switch ($File.Extension.ToLowerInvariant()) {
        ".ps1" {
            return Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File $quotedPath" -WorkingDirectory $File.DirectoryName -PassThru
        }
        { $_ -in ".bat", ".cmd" } {
            return Start-Process -FilePath $env:ComSpec -ArgumentList "/c call $quotedPath" -WorkingDirectory $File.DirectoryName -PassThru
        }
        { $_ -in ".vbs", ".js" } {
            $scriptExtension = $File.Extension.ToLowerInvariant()
            if ($scriptExtension -eq ".vbs" -and -not $script:VbScriptEngineReady) {
                Initialize-VbScriptRuntime -Required | Out-Null
            }
            $scriptHost = $null
            $scriptHostCandidates = @(
                [pscustomobject]@{
                    HostPath = Join-Path $env:SystemRoot "System32\cscript.exe"
                    EnginePath = Join-Path $env:SystemRoot "System32\vbscript.dll"
                },
                [pscustomobject]@{
                    HostPath = Join-Path $env:SystemRoot "SysWOW64\cscript.exe"
                    EnginePath = Join-Path $env:SystemRoot "SysWOW64\vbscript.dll"
                }
            )
            foreach ($candidate in $scriptHostCandidates) {
                if ((Test-Path -LiteralPath $candidate.HostPath) -and
                    ($scriptExtension -ne ".vbs" -or (Test-Path -LiteralPath $candidate.EnginePath))) {
                    $scriptHost = $candidate.HostPath
                    break
                }
            }
            if (-not $scriptHost) {
                if ($scriptExtension -eq ".vbs") {
                    throw "Unsupported payload runtime: VBScript/Windows Script Host is not installed or enabled in this Sandbox. Add the matching offline VBScript Feature-on-Demand package to the guest image; the sample was not launched."
                }
                throw "Unsupported payload runtime: Windows Script Host (cscript.exe) is not available in this Sandbox."
            }

            $scriptArguments = '//nologo "' + $File.FullName + '"'
            $scriptProcess = Start-Process -FilePath $scriptHost -ArgumentList $scriptArguments -WorkingDirectory $File.DirectoryName -PassThru -ErrorAction Stop
            if ($scriptProcess.WaitForExit(1000) -and $scriptProcess.ExitCode -ne 0) {
                throw "Windows Script Host failed to execute '$($File.Name)' (exit code $($scriptProcess.ExitCode))."
            }
            return $scriptProcess
        }
        ".msi" {
            $msiLogPath = Join-Path (Split-Path -Parent $TelemetryFile) "msiexec-install.log"
            $quotedMsiLogPath = '"' + $msiLogPath + '"'
            $msiArguments = "/i $quotedPath /qn /norestart /L*V $quotedMsiLogPath"
            return Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArguments -WorkingDirectory $File.DirectoryName -PassThru -ErrorAction Stop
        }
        ".dll" {
            $peArchitecture = Get-PeArchitecture -Path $File.FullName
            if (-not $peArchitecture) { throw "Unsupported payload runtime: '$($File.Name)' is not a valid supported PE DLL." }
            $is64BitOs = [Environment]::Is64BitOperatingSystem
            $powerShellPath = switch ($peArchitecture) {
                "x86" { if ($is64BitOs) { Join-Path $env:SystemRoot "SysWOW64\WindowsPowerShell\v1.0\powershell.exe" } else { Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe" } }
                "x64" { if ($is64BitOs) { Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe" } else { $null } }
                "arm64" { if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq [Runtime.InteropServices.Architecture]::Arm64) { Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe" } else { $null } }
            }
            if (-not $powerShellPath -or -not (Test-Path -LiteralPath $powerShellPath)) {
                throw "Unsupported payload runtime: no matching PowerShell loader is available for the $peArchitecture DLL."
            }
            $escapedDllPath = $File.FullName.Replace("'", "''")
            $loaderScript = @"
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SandboxDllLoadProbe {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr LoadLibrary(string fileName);
}
'@
`$loadedModule = [SandboxDllLoadProbe]::LoadLibrary('$escapedDllPath')
if (`$loadedModule -eq [IntPtr]::Zero) { exit 31 }
Start-Sleep -Seconds $($ObservationSeconds + $GuestReviewHeartbeatSeconds)
"@
            $encodedLoader = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($loaderScript))
            return Start-Process -FilePath $powerShellPath -ArgumentList "-NoLogo -NoProfile -NonInteractive -EncodedCommand $encodedLoader" -WorkingDirectory $File.DirectoryName -PassThru -ErrorAction Stop
        }
        { $_ -in ".jpg", ".jpeg", ".jpe", ".jfif", ".png", ".gif", ".bmp", ".webp", ".tif", ".tiff", ".ico", ".avif", ".heic" } {
            if (-not (Test-ImageFileSignature -Path $File.FullName -Extension $File.Extension)) {
                throw "Unsupported payload runtime: image extension '$($File.Extension)' does not match its file signature; the image was not opened."
            }
            $useBuiltInIconViewer = $File.Extension -ieq ".ico"
            if (-not $useBuiltInIconViewer) {
                try {
                    return Start-Process -FilePath $File.FullName -WorkingDirectory $File.DirectoryName -PassThru -ErrorAction Stop
                } catch {
                    $registeredViewerError = $_.Exception.Message
                }
            }
            if ($useBuiltInIconViewer -or $registeredViewerError) {
                $fallbackExtensions = @(".jpg", ".jpeg", ".jpe", ".jfif", ".png", ".gif", ".bmp", ".tif", ".tiff", ".ico")
                if ($File.Extension.ToLowerInvariant() -notin $fallbackExtensions) {
                    throw "Unsupported payload runtime: no guest viewer is registered for '$($File.Extension)'; the built-in fallback does not decode that format."
                }
                if ($File.Length -gt 33554432) {
                    throw "Unsupported payload runtime: no guest viewer is registered and the built-in image fallback is limited to 32 MB."
                }

                $escapedImagePath = $File.FullName.Replace("'", "''")
                $loadImageCommand = if ($useBuiltInIconViewer) {
                    @"
    `$icon = New-Object System.Drawing.Icon -ArgumentList '$escapedImagePath'
    `$image = `$icon.ToBitmap()
    `$icon.Dispose()
    `$icon = `$null
"@
                } else {
                    "    `$image = [System.Drawing.Image]::FromFile('$escapedImagePath')"
                }
                $imageViewerScript = @"
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms
`$image = `$null
`$icon = `$null
try {
    $loadImageCommand
    if (([long]`$image.Width * [long]`$image.Height) -gt 20000000) { exit 32 }
    [System.Windows.Forms.Application]::EnableVisualStyles()
    `$form = New-Object System.Windows.Forms.Form
    `$form.Text = 'Sandbox image review'
    `$form.Width = 1024
    `$form.Height = 768
    `$form.StartPosition = 'CenterScreen'
    `$picture = New-Object System.Windows.Forms.PictureBox
    `$picture.Dock = 'Fill'
    `$picture.SizeMode = 'Zoom'
    `$picture.Image = `$image
    `$form.Controls.Add(`$picture)
    `$form.Add_FormClosed({ if (`$image) { `$image.Dispose() } })
    [void]`$form.ShowDialog()
} catch {
    if (`$image) { `$image.Dispose() }
    if (`$icon) { `$icon.Dispose() }
    exit 31
}
"@
                $encodedViewerScript = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($imageViewerScript))
                return Start-Process -FilePath "powershell.exe" -ArgumentList "-NoLogo -NoProfile -NonInteractive -EncodedCommand $encodedViewerScript" -WorkingDirectory $File.DirectoryName -PassThru -ErrorAction Stop
            }
        }
        ".reg" {
            throw "Unsupported payload runtime: .reg files are not imported because registry changes are not monitored by this runner."
        }
        { $_ -in '.exe', '.com', '.scr', '.hta', '.lnk' } {
            return Start-Process -FilePath $File.FullName -WorkingDirectory $File.DirectoryName -PassThru -ErrorAction Stop
        }
        default {
            throw "Unsupported sample type '$($File.Extension)'; no application association was invoked. The file was not launched."
        }
    }
}

function Get-PayloadLaunchSummary {
    param (
        [System.IO.FileInfo[]]$Files,
        [System.Diagnostics.Process[]]$Processes
    )

    Initialize-RuntimeWindowApi
    $observations = New-Object System.Collections.Generic.List[string]
    for ($index = 0; $index -lt $Processes.Count; $index++) {
        $process = $Processes[$index]
        $file = if ($index -lt $Files.Count) { $Files[$index] } else { $null }
        $name = if ($file) { $file.Name } else { "payload $($index + 1)" }
        try {
            $process.Refresh()
            if ($process.HasExited) {
                [void]$observations.Add("$name process (PID $($process.Id)) exited during startup with code $($process.ExitCode).")
                continue
            }

            if ($file -and $file.Extension -ieq ".msi") {
                [void]$observations.Add("$name is running through msiexec in quiet mode (/qn); no installer window is expected. Verbose MSI log: C:\Telemetry\msiexec-install.log.")
                continue
            }

            $windows = @([SandboxRuntimeWindowApi]::GetVisibleWindows() | Where-Object { [uint32]$_.ProcessId -eq [uint32]$process.Id })
            if ($windows.Count -gt 0) {
                $windowTitle = ([string]$windows[0].Title -replace '[\r\n]+', ' ').Trim()
                if (-not $windowTitle) { $windowTitle = "untitled window" }
                $activated = [SandboxRuntimeWindowApi]::ActivateVisibleWindowForProcess([uint32]$process.Id)
                $focusNote = if ($activated) { "brought to the foreground" } else { "visible, but Windows did not allow it to take the foreground" }
                [void]$observations.Add("$name process (PID $($process.Id)) has visible $windowTitle; it was $focusNote.")
            } else {
                [void]$observations.Add("$name process (PID $($process.Id)) is active, but no visible top-level window was detected.")
            }
        } catch {
            $detail = ([string]$_.Exception.Message -replace '[\r\n]+', ' ').Trim()
            [void]$observations.Add("Could not inspect $name process (PID $($process.Id)): $detail")
        }
    }

    if ($observations.Count -eq 0) { return "No payload process was available for the startup check." }
    return ($observations -join " ")
}

function Get-PeArchitecture {
    param ([string]$Path)

    $stream = $null
    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        if ($stream.Length -lt 64) { return $null }
        $dosHeader = New-Object byte[] 64
        if ($stream.Read($dosHeader, 0, $dosHeader.Length) -ne $dosHeader.Length -or $dosHeader[0] -ne 0x4D -or $dosHeader[1] -ne 0x5A) { return $null }
        $peOffset = [BitConverter]::ToInt32($dosHeader, 0x3C)
        if ($peOffset -lt 64 -or $peOffset -gt ($stream.Length - 6)) { return $null }
        $stream.Position = $peOffset
        $header = New-Object byte[] 6
        if ($stream.Read($header, 0, $header.Length) -ne $header.Length -or
            [Text.Encoding]::ASCII.GetString($header, 0, 4) -ne "PE`0`0") { return $null }
        switch ([BitConverter]::ToUInt16($header, 4)) {
            0x014C { return "x86" }
            0x8664 { return "x64" }
            0xAA64 { return "arm64" }
            default { return $null }
        }
    } catch {
        return $null
    } finally {
        if ($stream) { $stream.Dispose() }
    }
}

function Test-ImageFileSignature {
    param ([string]$Path, [string]$Extension)

    $stream = $null
    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $header = New-Object byte[] 16
        $bytesRead = $stream.Read($header, 0, $header.Length)
    } catch {
        return $false
    } finally {
        if ($stream) { $stream.Dispose() }
    }
    switch ($Extension.ToLowerInvariant()) {
        { $_ -in '.jpg', '.jpeg', '.jpe', '.jfif' } { return ($bytesRead -ge 3 -and $header[0] -eq 0xFF -and $header[1] -eq 0xD8 -and $header[2] -eq 0xFF) }
        '.png' { return ($bytesRead -ge 8 -and $header[0] -eq 0x89 -and $header[1] -eq 0x50 -and $header[2] -eq 0x4E -and $header[3] -eq 0x47 -and $header[4] -eq 0x0D -and $header[5] -eq 0x0A -and $header[6] -eq 0x1A -and $header[7] -eq 0x0A) }
        '.gif' { return ($bytesRead -ge 6 -and [Text.Encoding]::ASCII.GetString($header, 0, 6) -in @('GIF87a', 'GIF89a')) }
        '.bmp' { return ($bytesRead -ge 2 -and $header[0] -eq 0x42 -and $header[1] -eq 0x4D) }
        '.webp' { return ($bytesRead -ge 12 -and [Text.Encoding]::ASCII.GetString($header, 0, 4) -eq 'RIFF' -and [Text.Encoding]::ASCII.GetString($header, 8, 4) -eq 'WEBP') }
        { $_ -in '.tif', '.tiff' } {
            $littleEndian = ($header[0] -eq 0x49 -and $header[1] -eq 0x49 -and (($header[2] -eq 0x2A -and $header[3] -eq 0x00) -or ($header[2] -eq 0x2B -and $header[3] -eq 0x00)))
            $bigEndian = ($header[0] -eq 0x4D -and $header[1] -eq 0x4D -and (($header[2] -eq 0x00 -and $header[3] -eq 0x2A) -or ($header[2] -eq 0x00 -and $header[3] -eq 0x2B)))
            return ($bytesRead -ge 4 -and ($littleEndian -or $bigEndian))
        }
        '.ico' { return ($bytesRead -ge 4 -and $header[0] -eq 0x00 -and $header[1] -eq 0x00 -and $header[2] -eq 0x01 -and $header[3] -eq 0x00) }
        { $_ -in '.avif', '.heic' } {
            if ($bytesRead -lt 12 -or [Text.Encoding]::ASCII.GetString($header, 4, 4) -ne 'ftyp') { return $false }
            $brand = [Text.Encoding]::ASCII.GetString($header, 8, 4)
            if ($Extension -ieq '.avif') { return $brand -in @('avif', 'avis') }
            return $brand -in @('heic', 'heix', 'hevc', 'hevx', 'mif1', 'msf1')
        }
        default { return $false }
    }
}

function Test-ZipSignature {
    param ([string]$Path)

    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $signature = New-Object byte[] 4
        $read = $stream.Read($signature, 0, $signature.Length)
        return ($read -eq 4 -and $signature[0] -eq 0x50 -and $signature[1] -eq 0x4B -and $signature[2] -in @(0x03, 0x05, 0x07))
    } finally {
        $stream.Dispose()
    }
}

function Start-GuestFileChangeMonitor {
    param ([string[]]$Roots)

    try {
        if (-not ("SandboxGuestFileChangeMonitor" -as [type])) {
            Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Threading;

public sealed class SandboxGuestFileChangeRecord
{
    public string Path { get; set; }
    public string ChangeType { get; set; }
    public DateTime UtcTime { get; set; }
}

public static class SandboxGuestFileChangeMonitor
{
    private static readonly ConcurrentQueue<SandboxGuestFileChangeRecord> Changes = new ConcurrentQueue<SandboxGuestFileChangeRecord>();
    private static readonly List<FileSystemWatcher> Watchers = new List<FileSystemWatcher>();
    private static readonly HashSet<string> KnownDirectories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    private static readonly object Sync = new object();
    private static int QueuedCount;
    private static volatile bool HasOverflowed;
    private static string FailureDetail;
    private const int QueueLimit = 10000;
    private const int MaximumKnownDirectories = 50000;
    private const int MaximumDirectoryTraversalMilliseconds = 5000;
    public static bool Overflowed { get { return HasOverflowed; } }
    public static string LastError { get { return FailureDetail; } }

    private static void RememberDirectoryTree(string root)
    {
        RememberDirectoryTree(root, DateTime.UtcNow.AddMilliseconds(MaximumDirectoryTraversalMilliseconds));
    }

    private static void RememberDirectoryTree(string root, DateTime deadlineUtc)
    {
        Stack<string> pending = new Stack<string>();
        pending.Push(root);
        while (pending.Count > 0)
        {
            if (DateTime.UtcNow >= deadlineUtc)
            {
                HasOverflowed = true;
                FailureDetail = "Guest directory baseline exceeded the 5-second traversal limit; behavior coverage is incomplete.";
                break;
            }
            string current = pending.Pop();
            if (KnownDirectories.Contains(current)) continue;
            if (KnownDirectories.Count >= MaximumKnownDirectories)
            {
                HasOverflowed = true;
                FailureDetail = "Guest directory baseline exceeded the 50000-directory monitoring limit; behavior coverage is incomplete.";
                break;
            }
            KnownDirectories.Add(current);
            try
            {
                foreach (string child in Directory.EnumerateDirectories(current))
                {
                    if (DateTime.UtcNow >= deadlineUtc)
                    {
                        HasOverflowed = true;
                        FailureDetail = "Guest directory baseline exceeded the 5-second traversal limit; behavior coverage is incomplete.";
                        break;
                    }
                    try
                    {
                        if (!KnownDirectories.Contains(child) && KnownDirectories.Count + pending.Count >= MaximumKnownDirectories)
                        {
                            HasOverflowed = true;
                            FailureDetail = "Guest directory baseline exceeded the 50000-directory monitoring limit; behavior coverage is incomplete.";
                            break;
                        }
                        if ((File.GetAttributes(child) & FileAttributes.ReparsePoint) == FileAttributes.ReparsePoint)
                        {
                            KnownDirectories.Add(child);
                            continue;
                        }
                        pending.Push(child);
                    }
                    catch (Exception error)
                    {
                        HasOverflowed = true;
                        FailureDetail = error.Message;
                    }
                }
            }
            catch (Exception error)
            {
                HasOverflowed = true;
                FailureDetail = error.Message;
            }
        }
    }

    private static void QueueChange(object sender, FileSystemEventArgs e)
    {
        try
        {
            if (Directory.Exists(e.FullPath))
            {
                lock (Sync) RememberDirectoryTree(e.FullPath);
                return;
            }
        }
        catch { }
        if (e.ChangeType == WatcherChangeTypes.Deleted)
        {
            lock (Sync)
            {
                if (KnownDirectories.Contains(e.FullPath))
                {
                    KnownDirectories.RemoveWhere(path => path.Equals(e.FullPath, StringComparison.OrdinalIgnoreCase) || path.StartsWith(e.FullPath.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase));
                    return;
                }
            }
        }
        if (Interlocked.Increment(ref QueuedCount) > QueueLimit)
        {
            Interlocked.Decrement(ref QueuedCount);
            HasOverflowed = true;
            return;
        }
        Changes.Enqueue(new SandboxGuestFileChangeRecord { Path = e.FullPath, ChangeType = e.ChangeType.ToString(), UtcTime = DateTime.UtcNow });
    }

    private static void QueueRename(object sender, RenamedEventArgs e)
    {
        try
        {
            if (Directory.Exists(e.FullPath))
            {
                lock (Sync)
                {
                    string oldPrefix = e.OldFullPath.TrimEnd('\\') + "\\";
                    string[] movedDirectories = new string[0];
                    if (KnownDirectories.Contains(e.OldFullPath))
                    {
                        movedDirectories = new List<string>(KnownDirectories).FindAll(path =>
                            path.Equals(e.OldFullPath, StringComparison.OrdinalIgnoreCase) ||
                            path.StartsWith(oldPrefix, StringComparison.OrdinalIgnoreCase)).ToArray();
                    }
                    if (movedDirectories.Length > 0)
                    {
                        foreach (string oldPath in movedDirectories) KnownDirectories.Remove(oldPath);
                        foreach (string oldPath in movedDirectories) KnownDirectories.Add(e.FullPath + oldPath.Substring(e.OldFullPath.Length));
                    }
                    else RememberDirectoryTree(e.FullPath);
                }
                return;
            }
        }
        catch { }
        lock (Sync)
        {
            if (KnownDirectories.Contains(e.OldFullPath))
            {
                KnownDirectories.RemoveWhere(path => path.Equals(e.OldFullPath, StringComparison.OrdinalIgnoreCase) || path.StartsWith(e.OldFullPath.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase));
                return;
            }
        }
        if (Interlocked.Increment(ref QueuedCount) > QueueLimit)
        {
            Interlocked.Decrement(ref QueuedCount);
            HasOverflowed = true;
            return;
        }
        Changes.Enqueue(new SandboxGuestFileChangeRecord { Path = e.FullPath, ChangeType = "Renamed", UtcTime = DateTime.UtcNow });
    }

    private static void OnError(object sender, ErrorEventArgs e)
    {
        HasOverflowed = true;
        Exception error = e.GetException();
        FailureDetail = error == null ? "The Windows filesystem watcher reported an unknown error." : error.Message;
    }

    public static bool Start(string[] roots)
    {
        Stop();
        HasOverflowed = false;
        FailureDetail = null;
        lock (Sync)
        {
            try
            {
                KnownDirectories.Clear();
                DateTime directoryDeadlineUtc = DateTime.UtcNow.AddMilliseconds(MaximumDirectoryTraversalMilliseconds);
                foreach (string root in roots)
                {
                    if (String.IsNullOrWhiteSpace(root) || !Directory.Exists(root)) continue;
                    RememberDirectoryTree(root, directoryDeadlineUtc);
                    FileSystemWatcher watcher = new FileSystemWatcher(root);
                    watcher.IncludeSubdirectories = true;
                    watcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime | NotifyFilters.Attributes;
                    watcher.InternalBufferSize = 65536;
                    watcher.Changed += QueueChange;
                    watcher.Created += QueueChange;
                    watcher.Deleted += QueueChange;
                    watcher.Renamed += QueueRename;
                    watcher.Error += OnError;
                    watcher.EnableRaisingEvents = true;
                    Watchers.Add(watcher);
                }
                if (Watchers.Count == 0)
                {
                    FailureDetail = "No guest folders could be monitored.";
                    return false;
                }
                return true;
            }
            catch (Exception error)
            {
                FailureDetail = error.Message;
                foreach (FileSystemWatcher watcher in Watchers) watcher.Dispose();
                Watchers.Clear();
                return false;
            }
        }
    }

    public static SandboxGuestFileChangeRecord[] Drain()
    {
        List<SandboxGuestFileChangeRecord> drained = new List<SandboxGuestFileChangeRecord>();
        SandboxGuestFileChangeRecord item;
        while (Changes.TryDequeue(out item))
        {
            Interlocked.Decrement(ref QueuedCount);
            drained.Add(item);
        }
        return drained.ToArray();
    }

    public static void Stop()
    {
        lock (Sync)
        {
            foreach (FileSystemWatcher watcher in Watchers) watcher.Dispose();
            Watchers.Clear();
            KnownDirectories.Clear();
            SandboxGuestFileChangeRecord item;
            while (Changes.TryDequeue(out item)) Interlocked.Decrement(ref QueuedCount);
        }
    }
}
'@
        }
        $started = [SandboxGuestFileChangeMonitor]::Start([string[]]$Roots)
        if (-not $started) {
            $script:GuestMonitorTruncated = $true
            $script:GuestMonitorTruncatedReason = "Guest filesystem change monitoring could not start: $([SandboxGuestFileChangeMonitor]::LastError)"
        } elseif ([SandboxGuestFileChangeMonitor]::Overflowed) {
            $script:GuestMonitorTruncated = $true
            $script:GuestMonitorTruncatedReason = "Guest filesystem monitoring started with incomplete directory coverage: $([SandboxGuestFileChangeMonitor]::LastError)"
            [SandboxGuestFileChangeMonitor]::Stop()
            return $false
        }
        return [bool]$started
    } catch {
        $script:GuestMonitorTruncated = $true
        $script:GuestMonitorTruncatedReason = "Guest filesystem change monitoring could not start: $($_.Exception.Message)"
        return $false
    }
}

function Stop-GuestFileChangeMonitor {
    if ("SandboxGuestFileChangeMonitor" -as [type]) {
        try { [SandboxGuestFileChangeMonitor]::Stop() } catch {}
    }
}

function Get-BoundedGuestFiles {
    param (
        [string]$Root,
        [int]$MaxFiles,
        [int]$MaxDirectories,
        [DateTime]$DeadlineUtc
    )

    $files = New-Object System.Collections.ArrayList
    $pendingDirectories = [System.Collections.Generic.Stack[string]]::new()
    $pendingDirectories.Push($Root)
    $directoriesVisited = 0
    $truncatedReason = $null
    $stopTraversal = $false
    $userProfile = [Environment]::GetFolderPath("UserProfile")
    $documentsRoot = [IO.Path]::GetFullPath((Join-Path $userProfile "Documents")).TrimEnd('\')

    while ($pendingDirectories.Count -gt 0 -and -not $stopTraversal) {
        if ([DateTime]::UtcNow -ge $DeadlineUtc) {
            $truncatedReason = "Guest file inventory exceeded its time limit."
            break
        }
        if ($directoriesVisited -ge $MaxDirectories) {
            $truncatedReason = "Guest file inventory exceeded the $MaxMonitoredDirectories-directory limit."
            break
        }

        $currentDirectory = $pendingDirectories.Pop()
        $directoriesVisited++
        try {
            foreach ($entryPath in [IO.Directory]::EnumerateFileSystemEntries($currentDirectory)) {
                if ([DateTime]::UtcNow -ge $DeadlineUtc) {
                    $truncatedReason = "Guest file inventory exceeded its time limit."
                    $stopTraversal = $true
                    break
                }
                try {
                    $attributes = [IO.File]::GetAttributes($entryPath)
                    if (($attributes -band [IO.FileAttributes]::Directory) -ne 0) {
                        if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                            $entryParent = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($entryPath)).TrimEnd('\')
                            $entryName = [IO.Path]::GetFileName([IO.Path]::GetFullPath($entryPath))
                            $knownProfileAlias = ($entryParent -ieq $documentsRoot) -and ($entryName -in @("My Music", "My Pictures", "My Videos"))
                            if (-not $knownProfileAlias -and -not $truncatedReason) {
                                $truncatedReason = "Guest file inventory encountered directory link '$entryPath' whose target was not followed."
                            }
                            continue
                        }
                        if ($directoriesVisited + $pendingDirectories.Count -ge $MaxDirectories) {
                            $truncatedReason = "Guest file inventory exceeded the $MaxMonitoredDirectories-directory limit."
                            $stopTraversal = $true
                            break
                        }
                        $pendingDirectories.Push($entryPath)
                        continue
                    }
                    if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                        if (-not $truncatedReason) { $truncatedReason = "Guest file inventory encountered file link '$entryPath' whose target was not followed." }
                        continue
                    }

                    [void]$files.Add((Get-Item -LiteralPath $entryPath -Force -ErrorAction Stop))
                    if ($files.Count -gt $MaxFiles) {
                        $truncatedReason = "Guest file inventory exceeded the $MaxMonitoredFiles-file limit."
                        $stopTraversal = $true
                        break
                    }
                } catch {
                    if (-not $truncatedReason) { $truncatedReason = "Guest file inventory could not inspect an entry: $($_.Exception.Message)" }
                }
            }
        } catch {
            if (-not $truncatedReason) { $truncatedReason = "Guest file inventory could not enumerate ${currentDirectory}: $($_.Exception.Message)" }
        }
    }

    return [pscustomobject]@{
        Files = $files.ToArray()
        DirectoriesVisited = $directoriesVisited
        TruncatedReason = $truncatedReason
    }
}

function Get-GuestSnapshot {
    param ([string[]]$Roots)

    $snapshot = @{}
    $directoriesVisited = 0
    $deadlineUtc = [DateTime]::UtcNow.AddSeconds($MaxGuestInventorySeconds)
    foreach ($root in $Roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        $remainingCapacity = $MaxMonitoredFiles - $snapshot.Count
        $remainingDirectories = $MaxMonitoredDirectories - $directoriesVisited
        $inventory = Get-BoundedGuestFiles -Root $root -MaxFiles $remainingCapacity -MaxDirectories $remainingDirectories -DeadlineUtc $deadlineUtc
        $directoriesVisited += $inventory.DirectoriesVisited
        if ($inventory.TruncatedReason) {
            $script:GuestMonitorTruncated = $true
            $script:GuestMonitorTruncatedReason = "Guest baseline coverage is incomplete under $root. $($inventory.TruncatedReason)"
        }
        $rootFiles = @($inventory.Files)
        if ($rootFiles.Count -gt $remainingCapacity) {
            $script:GuestMonitorTruncated = $true
            $script:GuestMonitorTruncatedReason = "Guest baseline exceeded the $MaxMonitoredFiles-file monitoring limit."
            $rootFiles = @($rootFiles | Select-Object -First $remainingCapacity)
        }
        foreach ($file in $rootFiles) {
            $snapshot[$file.FullName] = "$($file.Length)|$($file.LastWriteTimeUtc.Ticks)|$($file.CreationTimeUtc.Ticks)|$([int]$file.Attributes)"
        }
    }
    return ,$snapshot
}

function Get-GuestBehaviorSignal {
    param (
        [hashtable]$Baseline,
        [string[]]$Roots,
        [string[]]$ExcludedPaths = @()
    )

    $excludedPathSet = @{}
    foreach ($excludedPath in $ExcludedPaths) {
        if (-not [string]::IsNullOrWhiteSpace($excludedPath)) {
            $excludedPathSet[[IO.Path]::GetFullPath($excludedPath).ToLowerInvariant()] = $true
        }
    }

    $files = New-Object System.Collections.ArrayList
    $directoriesVisited = 0
    $deadlineUtc = [DateTime]::UtcNow.AddSeconds(5)
    foreach ($root in $Roots) {
        if (Test-Path -LiteralPath $root) {
            $remainingCapacity = $MaxMonitoredFiles - $files.Count
            $remainingDirectories = $MaxMonitoredDirectories - $directoriesVisited
            $inventory = Get-BoundedGuestFiles -Root $root -MaxFiles $remainingCapacity -MaxDirectories $remainingDirectories -DeadlineUtc $deadlineUtc
            $directoriesVisited += $inventory.DirectoriesVisited
            if ($inventory.TruncatedReason) {
                $script:GuestMonitorTruncated = $true
                $script:GuestMonitorTruncatedReason = "Guest behavior coverage is incomplete under $root. $($inventory.TruncatedReason)"
            }
            $rootFiles = @($inventory.Files)
            if ($rootFiles.Count -gt $remainingCapacity) {
                $script:GuestMonitorTruncated = $true
                $script:GuestMonitorTruncatedReason = "Guest behavior scan exceeded the $MaxMonitoredFiles-file monitoring limit."
                $rootFiles = @($rootFiles | Select-Object -First $remainingCapacity)
            }
            foreach ($rootFile in $rootFiles) { [void]$files.Add($rootFile) }
        }
    }

    $currentSnapshot = @{}
    foreach ($file in $files) {
        $currentSnapshot[$file.FullName] = "$($file.Length)|$($file.LastWriteTimeUtc.Ticks)|$($file.CreationTimeUtc.Ticks)|$([int]$file.Attributes)"
    }

    $changedFiles = @($files | Where-Object {
        -not $excludedPathSet.ContainsKey($_.FullName.ToLowerInvariant()) -and
        (-not $Baseline.ContainsKey($_.FullName) -or $currentSnapshot[$_.FullName] -ne $Baseline[$_.FullName])
    } | ForEach-Object {
        [pscustomobject]@{ Path = $_.FullName.ToLowerInvariant(); At = $_.LastWriteTimeUtc }
    })
    $eventPaths = @{}
    $watchEvents = @()
    if ("SandboxGuestFileChangeMonitor" -as [type]) {
        $watchEvents = @([SandboxGuestFileChangeMonitor]::Drain())
        if ([SandboxGuestFileChangeMonitor]::Overflowed) {
            $script:GuestMonitorTruncated = $true
            $script:GuestMonitorTruncatedReason = "The guest filesystem change queue overflowed; some changes may have been missed."
        }
        foreach ($watchEvent in $watchEvents) {
            $eventPath = ([string]$watchEvent.Path).ToLowerInvariant()
            if (-not $eventPath) { continue }
            if ($excludedPathSet.ContainsKey($eventPath)) { continue }
            $eventPaths[$eventPath] = $true
            $changedFiles += [pscustomobject]@{ Path = $eventPath; At = $watchEvent.UtcTime }
        }
    }
    $changedFiles = @($changedFiles | Sort-Object At)
    $artifactPaths = @($changedFiles | ForEach-Object { [string]$_.Path } | Sort-Object -Unique)
    $notePaths = @($artifactPaths | Where-Object { (Split-Path -Leaf $_) -match "(?i)(read.?me|decrypt|recover|restore|how.?to|ransom|help)" })
    $encryptedPaths = @($artifactPaths | Where-Object { [IO.Path]::GetExtension($_) -match "(?i)^\.(lock|locked|encrypted|crypted|crypto|wnry|wncry|fun|pay|demons)$" })
    $knownRansomwarePaths = @($artifactPaths | Where-Object { [IO.Path]::GetExtension($_) -match "(?i)^\.(wnry|wncry)$" })
    if (($notePaths.Count -gt 0 -and $encryptedPaths.Count -gt 0) -or $knownRansomwarePaths.Count -ge 2) {
        $noteName = if ($notePaths.Count -gt 0) { Split-Path -Leaf $notePaths[0] } else { "multiple .WNCRY/.WNRY files" }
        $markerName = if ($encryptedPaths.Count -gt 0) { Split-Path -Leaf $encryptedPaths[0] } else { Split-Path -Leaf $knownRansomwarePaths[0] }
        return "VIRUS: Ransomware behavior confirmed by a ransom-note artifact ($noteName) and encrypted-file marker ($markerName)."
    }
    if ($artifactPaths.Count -gt 0) {
        return "Ransom note or encrypted-file marker created, renamed, or changed in the guest: $($artifactPaths[0])"
    }

    $pathCounts = @{}
    $left = 0
    for ($right = 0; $right -lt $changedFiles.Count; $right++) {
        $rightPath = [string]$changedFiles[$right].Path
        if (-not $pathCounts.ContainsKey($rightPath)) { $pathCounts[$rightPath] = 0 }
        $pathCounts[$rightPath]++
        while (($changedFiles[$right].At - $changedFiles[$left].At).TotalSeconds -gt 1.0) {
            $leftPath = [string]$changedFiles[$left].Path
            $pathCounts[$leftPath]--
            if ($pathCounts[$leftPath] -le 0) { $pathCounts.Remove($leftPath) }
            $left++
        }
        if ($pathCounts.Count -ge 200) {
            return "SUSPICIOUS: File-bomber/spammer burst detected: at least 200 distinct files changed within one second ($($pathCounts.Count) files)."
        }
        if ($pathCounts.Count -gt 10) {
            return "SUSPICIOUS: More than 10 distinct files changed within one second ($($pathCounts.Count) files); rapid mass file modification can be consistent with ransomware or a file-bomber but is not proof of malware."
        }
    }

    foreach ($path in $Baseline.Keys) {
        if ($excludedPathSet.ContainsKey(([string]$path).ToLowerInvariant())) { continue }
        if (-not $currentSnapshot.ContainsKey($path)) {
            return "A guest canary or working file was deleted: $(Split-Path -Leaf $path)"
        }
        if ($currentSnapshot[$path] -ne $Baseline[$path] -or $eventPaths.ContainsKey($path.ToLowerInvariant())) {
            return "A guest canary or working file changed: $(Split-Path -Leaf $path)"
        }
    }

    return $null
}

function Invoke-PostRebootCheck {
    param ([object]$PriorStatus)

    $priorState = if ($PriorStatus) { [string]$PriorStatus.state } else { "unknown" }
    $priorDetails = if ($PriorStatus) { [string]$PriorStatus.details } else { "" }
    $runtimeWasInstalling = ($priorState -in @("PREPARING_RUNTIME", "INSTALLING_RUNTIME")) -and
        ($priorDetails -match "(?i)(installing|registering|runtime|VBScript|NetFx3|\.NET Framework)")
    $runtimeNote = if ($runtimeWasInstalling) { " The previous guest status indicates runtime setup was in progress." } else { "" }

    $userProfile = [Environment]::GetFolderPath("UserProfile")
    $monitorRoots = @(
        (Join-Path $userProfile "Desktop"),
        (Join-Path $userProfile "Documents"),
        (Join-Path $userProfile "Pictures"),
        (Join-Path $userProfile "Music"),
        (Join-Path $userProfile "Videos"),
        (Join-Path $userProfile "Downloads")
    )
    $monitorRoots += @(Get-ChildItem -LiteralPath $env:TEMP -Directory -Filter "Sample-*" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
    $monitorRoots = @($monitorRoots | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -Unique)
    $baseline = Get-GuestSnapshot -Roots $monitorRoots
    $reviewState = "POST_REBOOT_CHECK"
    $reviewDetails = "Guest reboot detected after prior state $priorState. Monitoring guest folders and canaries for $PostRebootCheckSeconds seconds; the sample will not be launched again automatically.$runtimeNote"
    if ($script:GuestMonitorTruncated) {
        Set-RunnerStatus -State "INCONCLUSIVE" -Details "$($script:GuestMonitorTruncatedReason) Post-reboot coverage is incomplete." -Launched 0
        return
    }
    if (-not (Start-GuestFileChangeMonitor -Roots $monitorRoots)) {
        Set-RunnerStatus -State "INCONCLUSIVE" -Details "$($script:GuestMonitorTruncatedReason) The sample was not relaunched." -Launched 0
        return
    }
    Set-RunnerStatus -State $reviewState -Details $reviewDetails -Launched 0

    for ($elapsed = 0; $elapsed -lt $PostRebootCheckSeconds; $elapsed += $ObservationIntervalSeconds) {
        $behaviorSignal = Get-GuestBehaviorSignal -Baseline $baseline -Roots $monitorRoots -ExcludedPaths @($filesToRun | ForEach-Object { $_.FullName })
        if ($behaviorSignal) {
            $reviewState = if ($behaviorSignal -match '^VIRUS:\s*') { "VIRUS" } else { "SUSPICIOUS" }
            $reviewDetails = "$behaviorSignal Detected during the post-reboot observation; the sample was not relaunched."
        }
        if ($script:GuestMonitorTruncated) {
            Stop-GuestFileChangeMonitor
            Set-RunnerStatus -State "INCONCLUSIVE" -Details "$($script:GuestMonitorTruncatedReason) Post-reboot observation coverage is incomplete; the sample was not relaunched. Previous signal, if any: $reviewDetails" -Launched 0
            return
        }
        if (($elapsed % 6) -eq 0) {
            Set-RunnerStatus -State $reviewState -Details $reviewDetails -Launched 0
        }
        Start-Sleep -Seconds $ObservationIntervalSeconds
    }

    if ($reviewState -eq "POST_REBOOT_CHECK") {
        Set-RunnerStatus -State "POST_REBOOT_COMPLETE" -Details "The post-reboot observation completed without new monitored behavior. The reboot alone is not treated as a threat; the sample was not relaunched, so the result requires review." -Launched 0
    } else {
        Set-RunnerStatus -State "POST_REBOOT_COMPLETE" -Details "Post-reboot observation completed with behavior state $reviewState. $reviewDetails The sample was not relaunched." -Launched 0
    }
    Stop-GuestFileChangeMonitor
}

$hadPriorRunnerInstance = $false
$priorRunnerStatus = $null
if (Test-Path -LiteralPath $TelemetryFile) {
    try { $priorRunnerStatus = Get-Content -LiteralPath $TelemetryFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop } catch {}
}
if (Test-Path -LiteralPath $RunnerHistoryFile) {
    try {
        $priorRunnerIds = @(Get-Content -LiteralPath $RunnerHistoryFile -ErrorAction Stop | ForEach-Object {
            $line = ([string]$_).TrimStart([char]0xFEFF)
            if ($line -match '^([0-9a-f]{32})\|') { $matches[1] }
        } | Select-Object -Unique)
        $hadPriorRunnerInstance = $priorRunnerIds.Count -gt 0
    } catch {}
}

try {
    $runnerLogonRecoveryRegistered = Register-RunnerForGuestLogon
    if ($runnerLogonRecoveryRegistered) {
        Write-Output "[BOOTSTRAP] Guest logon restart hook is registered."
        Set-RunnerStatus -State "STARTED" -Details "Sandbox logon command is running. Guest logon restart hook is registered."
    } else {
        Write-Output "[BOOTSTRAP] WARNING: Guest logon restart hook could not be registered: $script:RunnerLogonRegistrationError"
        Set-RunnerStatus -State "STARTED" -Details "Sandbox logon command is running, but guest logon restart hook could not be registered: $script:RunnerLogonRegistrationError"
    }
    if ($hadPriorRunnerInstance) {
        Invoke-PostRebootCheck -PriorStatus $priorRunnerStatus
        exit 0
    }

    $sample = Get-ChildItem -LiteralPath $PayloadFolder -File | Select-Object -First 1
    if (-not $sample) {
        Set-RunnerStatus -State "ERROR" -Details "No sample was found in the read-only staging folder."
        exit 2
    }

    $filesToRun = @()
    $workFolder = $null
    if ($sample.Extension -ieq ".zip" -or (Test-ZipSignature -Path $sample.FullName)) {
        Set-RunnerStatus -State "INSPECTING_ARCHIVE" -Details "Checking ZIP contents and expansion limits."
        $archiveResult = Get-ArchiveContents -ArchivePath $sample.FullName
        if ($archiveResult.State -ne "READY") {
            Write-Output "[ZIP] $($archiveResult.State): $($archiveResult.Details) No archive payload was launched."
            Set-RunnerStatus -State $archiveResult.State -Details $archiveResult.Details
            exit 3
        }

        if (@($archiveResult.Files | Where-Object { $_.Extension -ieq ".reg" }).Count -gt 0) {
            Set-RunnerStatus -State "UNSUPPORTED" -Details "ZIP contains a .reg file, but registry changes are not monitored by this runner; no archive payload was launched."
            exit 4
        }
        $supportedArchiveFiles = @($archiveResult.Files | Where-Object { $_.Extension.ToLowerInvariant() -in @(".exe", ".com", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi", ".hta", ".lnk", ".dll", ".jpg", ".jpeg", ".jpe", ".jfif", ".png", ".gif", ".bmp", ".webp", ".tif", ".tiff", ".ico", ".avif", ".heic") })
        if ($supportedArchiveFiles.Count -gt 5) {
            Set-RunnerStatus -State "UNSUPPORTED" -Details "ZIP contains $($supportedArchiveFiles.Count) supported payload files; the safe per-archive launch limit is 5. No payload was launched to avoid silently skipping entries."
            exit 4
        }
        $filesToRun = $supportedArchiveFiles
        $workFolder = $archiveResult.WorkFolder
        if ($filesToRun.Count -eq 0) {
            Set-RunnerStatus -State "UNSUPPORTED" -Details "ZIP was inspected and extracted within limits, but it contains no supported executable payload."
            exit 4
        }
    } elseif ($sample.Extension.ToLowerInvariant() -in @(".7z", ".rar", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".cab", ".iso")) {
        Set-RunnerStatus -State "UNSUPPORTED" -Details "Archive format $($sample.Extension) is not safely inspected by this runner; no payload was executed. Manual review is required."
        exit 4
    } else {
        $workFolder = Join-Path $env:TEMP ("Sample-" + [Guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $workFolder -Force | Out-Null
        $workingCopy = Join-Path $workFolder $sample.Name
        Copy-Item -LiteralPath $sample.FullName -Destination $workingCopy -Force
        $filesToRun = @((Get-Item -LiteralPath $workingCopy -ErrorAction Stop))
    }

    $userProfile = [Environment]::GetFolderPath("UserProfile")
    $monitorRoots = @(
        (Join-Path $userProfile "Desktop"),
        (Join-Path $userProfile "Documents"),
        (Join-Path $userProfile "Pictures"),
        (Join-Path $userProfile "Music"),
        (Join-Path $userProfile "Videos"),
        (Join-Path $userProfile "Downloads"),
        $workFolder
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique

    $script:GuestMonitorTruncated = $false
    $script:GuestMonitorTruncatedReason = $null
    $baseline = Get-GuestSnapshot -Roots $monitorRoots
    if ($script:GuestMonitorTruncated) {
        Set-RunnerStatus -State "INCONCLUSIVE" -Details "$($script:GuestMonitorTruncatedReason) The sample was not launched because a complete baseline could not be collected." -Launched 0
        exit 4
    }
    if (-not (Start-GuestFileChangeMonitor -Roots $monitorRoots)) {
        Set-RunnerStatus -State "INCONCLUSIVE" -Details "$($script:GuestMonitorTruncatedReason) The sample was not launched." -Launched 0
        exit 4
    }

    $launchedCount = 0
    $launchedProcesses = @()
    $payloadExitFailure = $null
    $payloadExitNotes = New-Object System.Collections.ArrayList
    $msiProcessStateUnknown = $false
    $observedProcessExitIds = @{}
    $runtimeInstallAttempts = @{}
    $runtimeRetryUsed = @{}
    $runtimeNoticeText = " Optional runtimes are deferred until the sample requests them."
    Disable-SandboxSmartScreen
    Set-RunnerStatus -State "LAUNCHING_PAYLOAD" -Details "Launching the sample and checking for a missing-runtime dialog before dynamic monitoring." -Launched $launchedCount
    foreach ($file in $filesToRun) {
        $process = Start-Payload -File $file
        if (-not $process) { throw "Start-Payload did not return a process for '$($file.Name)'." }
        $launchedProcesses += $process
        $launchedCount++
    }

    $initialRuntimePrompt = $null
    $initialDependencyPrompt = $null
    $launchPromptProbe = [System.Diagnostics.Stopwatch]::StartNew()
    while ($launchPromptProbe.Elapsed.TotalSeconds -lt $LaunchRuntimePromptGraceSeconds) {
        $initialRuntimePrompt = Find-MissingRuntimePrompt
        if ($initialRuntimePrompt) { break }
        $initialDependencyPrompt = Find-MissingDependencyPrompt
        if ($initialDependencyPrompt) { break }
        Start-Sleep -Milliseconds 500
    }
    $containsMsiPayload = @($filesToRun | Where-Object { $_.Extension -ieq ".msi" }).Count -gt 0
    $payloadObservationSeconds = if ($containsMsiPayload) { [Math]::Max($ObservationSeconds, $MsiObservationSeconds) } else { $ObservationSeconds }
    if ($initialDependencyPrompt) {
        [void](Close-MissingRuntimePrompt -Handle $initialDependencyPrompt.Handle -ProcessId $initialDependencyPrompt.ProcessId)
        $dependencyDetail = ([string]$initialDependencyPrompt.Details -replace '[\r\n]+', ' ').Trim()
        Set-RunnerStatus -State 'UNSUPPORTED' -Details "The sample could not start because a required DLL is missing. Dynamic analysis stopped before a successful launch; review the application dependency. Dialog: $dependencyDetail" -Launched 0
        exit 4
    }
    if ($initialRuntimePrompt) {
        $initialRuntimeName = if ($initialRuntimePrompt.Runtime -eq "NetFx3") { ".NET Framework 3.5" } else { "VBScript" }
        Set-RunnerStatus -State "INSTALLING_RUNTIME" -Details "RUNTIME_REMEDIATION: Detected the exact $initialRuntimeName missing-runtime dialog immediately after launch. Repairing the runtime before resuming the sample." -Launched $launchedCount
    } else {
        $payloadLaunchSummary = Get-PayloadLaunchSummary -Files $filesToRun -Processes $launchedProcesses
        $observationNote = if ($containsMsiPayload) { "Watching for at least $ObservationSeconds seconds and until the MSI installer exits, up to $payloadObservationSeconds seconds." } else { "Watching guest user folders, the writable working folder, and host canaries for $payloadObservationSeconds seconds." }
        Set-RunnerStatus -State "RUNNING" -Details ("Payload launch call completed. $payloadLaunchSummary $observationNote" + $runtimeNoticeText) -Launched $launchedCount
    }
    $lastHeartbeatUtc = [DateTime]::UtcNow
    for ($elapsed = 0; $elapsed -lt $payloadObservationSeconds; $elapsed += $ObservationIntervalSeconds) {
        $dependencyPrompt = Find-MissingDependencyPrompt
        if ($dependencyPrompt) {
            [void](Close-MissingRuntimePrompt -Handle $dependencyPrompt.Handle -ProcessId $dependencyPrompt.ProcessId)
            $dependencyDetail = ([string]$dependencyPrompt.Details -replace '[\r\n]+', ' ').Trim()
            Set-RunnerStatus -State 'UNSUPPORTED' -Details "The sample stopped at a missing-DLL error. Dynamic analysis ended and the sample was not cleared as safe. Dialog: $dependencyDetail" -Launched $launchedCount
            exit 4
        }
        $runtimePrompt = if ($initialRuntimePrompt) { $initialRuntimePrompt; $initialRuntimePrompt = $null } else { Find-MissingRuntimePrompt }
        if ($runtimePrompt) {
            $runtimeKey = [string]$runtimePrompt.Runtime
            if ($runtimeInstallAttempts.ContainsKey($runtimeKey)) {
                $repeatRuntimeName = if ($runtimeKey -eq "NetFx3") { ".NET Framework 3.5" } else { "VBScript" }
                Set-RunnerStatus -State "UNSUPPORTED" -Details "The $repeatRuntimeName missing-runtime dialog reappeared after one installation attempt. The sample was not cleared as safe; review the offline feature source and report." -Launched $launchedCount
                exit 4
            }
            $runtimeInstallAttempts[$runtimeKey] = $true
            $runtimeDisplayName = if ($runtimeKey -eq "NetFx3") { ".NET Framework 3.5" } else { "VBScript" }
            Set-RunnerStatus -State "INSTALLING_RUNTIME" -Details "RUNTIME_REMEDIATION: Detected the exact $runtimeDisplayName missing-runtime dialog. Repairing the runtime before resuming the sample." -Launched $launchedCount

            if ($runtimeKey -eq "VBScript") {
                try {
                    Initialize-VbScriptRuntime -Required -AfterLaunch -Launched $launchedCount | Out-Null
                } catch {
                    Set-RunnerStatus -State "UNSUPPORTED" -Details "VBScript was requested by the sample, but automatic offline installation failed: $($_.Exception.Message)" -Launched $launchedCount
                    exit 4
                }
            } else {
                $netFxInstallNotice = Initialize-NetFx3Runtime -AfterLaunch -Launched $launchedCount
                if ($netFxInstallNotice) {
                    Set-RunnerStatus -State "UNSUPPORTED" -Details ".NET Framework 3.5 was requested by the sample, but automatic installation failed: $netFxInstallNotice" -Launched $launchedCount
                    exit 4
                }
            }

            if (-not (Close-MissingRuntimePrompt -Handle $runtimePrompt.Handle -ProcessId $runtimePrompt.ProcessId)) {
                Set-RunnerStatus -State "UNSUPPORTED" -Details "$runtimeDisplayName was installed, but its blocking dialog could not be closed. The sample was not cleared as safe." -Launched $launchedCount
                exit 4
            }

            $runtimeNoticeText += " Runtime remediation: $runtimeDisplayName installed after its missing-runtime dialog appeared."
            if ($filesToRun.Count -ne 1) {
                Set-RunnerStatus -State "UNSUPPORTED" -Details "$runtimeDisplayName was installed, but the archive launched multiple payloads and the blocked process cannot be identified safely for a one-time retry. The sample was not cleared as safe." -Launched $launchedCount
                exit 4
            }

            $retryKey = $filesToRun[0].FullName.ToLowerInvariant() + "|" + $runtimeKey
            if ($runtimeRetryUsed.ContainsKey($retryKey)) {
                Set-RunnerStatus -State "UNSUPPORTED" -Details "$runtimeDisplayName was installed, but its single permitted retry was already used. The sample was not cleared as safe." -Launched $launchedCount
                exit 4
            }
            $runtimeRetryUsed[$retryKey] = $true

            $processStopFailed = $false
            foreach ($launchedProcess in $launchedProcesses) {
                try {
                    $launchedProcess.Refresh()
                    if (-not $launchedProcess.HasExited) {
                        Stop-Process -Id $launchedProcess.Id -Force -ErrorAction Stop
                    }
                } catch {
                    try {
                        $launchedProcess.Refresh()
                        if (-not $launchedProcess.HasExited) { $processStopFailed = $true }
                    } catch {}
                }
            }
            if ($processStopFailed) {
                Set-RunnerStatus -State "UNSUPPORTED" -Details "$runtimeDisplayName was installed, but the blocked sample process could not be stopped safely for its one-time retry. The sample was not cleared as safe." -Launched $launchedCount
                exit 4
            }

            Start-Sleep -Seconds 1
            $launchedProcesses = @()
            try {
                Set-RunnerStatus -State "LAUNCHING_PAYLOAD" -Details "RUNTIME_REMEDIATION: $runtimeDisplayName is installed; starting the one-time sample retry." -Launched $launchedCount
                $retryProcess = Start-Payload -File $filesToRun[0]
                if (-not $retryProcess) { throw "Start-Payload did not return a process for the one-time retry." }
                $launchedProcesses += $retryProcess
                $launchedCount++
                Set-RunnerStatus -State "RUNNING" -Details "RUNTIME_REMEDIATION: $runtimeDisplayName is installed; the blocked process was stopped and the sample was relaunched exactly once. Monitoring continues." -Launched $launchedCount
            } catch {
                Set-RunnerStatus -State "UNSUPPORTED" -Details "$runtimeDisplayName was installed, but the one-time sample retry failed: $($_.Exception.Message)" -Launched $launchedCount
                exit 4
            }
            $lastHeartbeatUtc = [DateTime]::UtcNow
        }

        if (([DateTime]::UtcNow - $lastHeartbeatUtc).TotalSeconds -ge 5) {
            Set-RunnerStatus -State "RUNNING" -Details ("Payload launch completed; dynamic folder and canary monitoring is active." + $runtimeNoticeText) -Launched $launchedCount
            $lastHeartbeatUtc = [DateTime]::UtcNow
        }

        for ($processIndex = 0; $processIndex -lt $launchedProcesses.Count; $processIndex++) {
            $launchedProcess = $launchedProcesses[$processIndex]
            try {
                $launchedProcess.Refresh()
                if ($launchedProcess.HasExited -and -not $observedProcessExitIds.ContainsKey([string]$launchedProcess.Id)) {
                    $observedProcessExitIds[[string]$launchedProcess.Id] = $true
                    $exitCode = [int]$launchedProcess.ExitCode
                    $launchedFile = if ($processIndex -lt $filesToRun.Count) { $filesToRun[$processIndex] } else { $null }
                    if ($launchedFile -and $launchedFile.Extension -ieq ".msi") {
                        if ($exitCode -eq 0) {
                            [void]$payloadExitNotes.Add("MSI $($launchedFile.Name) completed successfully (Windows Installer exit code 0). Verbose log: C:\Telemetry\msiexec-install.log.")
                        } elseif ($exitCode -eq 3010) {
                            [void]$payloadExitNotes.Add("MSI $($launchedFile.Name) completed successfully but requires a restart (Windows Installer exit code 3010). Verbose log: C:\Telemetry\msiexec-install.log.")
                        } elseif ($exitCode -eq 1641) {
                            [void]$payloadExitNotes.Add("MSI $($launchedFile.Name) completed successfully and requested a restart (Windows Installer exit code 1641). Verbose log: C:\Telemetry\msiexec-install.log.")
                        } elseif (-not $payloadExitFailure) {
                            $payloadExitFailure = "MSI $($launchedFile.Name) failed with Windows Installer exit code $exitCode. See C:\Telemetry\msiexec-install.log."
                        }
                    } elseif ($exitCode -ne 0 -and -not $payloadExitFailure) {
                        $payloadExitFailure = "A launched process exited with code $exitCode."
                    } elseif ($launchedFile) {
                        [void]$payloadExitNotes.Add("$($launchedFile.Name) launcher exited with code $exitCode.")
                    }
                }
            } catch {}
        }

        $behaviorSignal = Get-GuestBehaviorSignal -Baseline $baseline -Roots $monitorRoots -ExcludedPaths @($filesToRun | ForEach-Object { $_.FullName })
        if ($behaviorSignal) {
            $behaviorState = if ($behaviorSignal -match '^VIRUS:\s*') { "VIRUS" } else { "SUSPICIOUS" }
            Set-RunnerStatus -State $behaviorState -Details ($behaviorSignal + " Payload remains in the isolated Sandbox for the host demonstration window.") -Launched $launchedCount
            for ($lingerSeconds = 0; $lingerSeconds -lt $GuestReviewHeartbeatSeconds; $lingerSeconds += $ObservationIntervalSeconds) {
                if ($behaviorState -ne "VIRUS") {
                    $laterBehaviorSignal = Get-GuestBehaviorSignal -Baseline $baseline -Roots $monitorRoots -ExcludedPaths @($filesToRun | ForEach-Object { $_.FullName })
                    if ($laterBehaviorSignal -match '^VIRUS:\s*' -or $laterBehaviorSignal -match '^SUSPICIOUS: File-bomber/spammer burst detected:') {
                        $behaviorState = if ($laterBehaviorSignal -match '^VIRUS:\s*') { "VIRUS" } else { "SUSPICIOUS" }
                        $behaviorSignal = $laterBehaviorSignal
                    }
                }
                if (($lingerSeconds % 6) -eq 0) {
                    Set-RunnerStatus -State $behaviorState -Details ($behaviorSignal + " The Sandbox remains open for interactive review; guest heartbeat is active.") -Launched $launchedCount
                }
                Start-Sleep -Seconds $ObservationIntervalSeconds
            }
            Stop-GuestFileChangeMonitor
            exit 5
        }
        if ($script:GuestMonitorTruncated) {
            Set-RunnerStatus -State "INCONCLUSIVE" -Details "$($script:GuestMonitorTruncatedReason) Behavior monitoring stopped without a detected signal; the sample was not cleared as safe." -Launched $launchedCount
            Stop-GuestFileChangeMonitor
            exit 4
        }
        if ($containsMsiPayload -and $elapsed -ge $ObservationSeconds) {
            $activeMsiProcesses = @()
            for ($msiIndex = 0; $msiIndex -lt $launchedProcesses.Count; $msiIndex++) {
                if ($msiIndex -ge $filesToRun.Count -or $filesToRun[$msiIndex].Extension -ine ".msi") { continue }
                try {
                    $launchedProcesses[$msiIndex].Refresh()
                    if (-not $launchedProcesses[$msiIndex].HasExited) { $activeMsiProcesses += $launchedProcesses[$msiIndex] }
                } catch { $msiProcessStateUnknown = $true }
            }
            if ($activeMsiProcesses.Count -eq 0 -and -not $msiProcessStateUnknown) { break }
        }
        Start-Sleep -Seconds $ObservationIntervalSeconds
    }
    for ($processIndex = 0; $processIndex -lt $launchedProcesses.Count; $processIndex++) {
        $launchedProcess = $launchedProcesses[$processIndex]
        $launchedFile = if ($processIndex -lt $filesToRun.Count) { $filesToRun[$processIndex] } else { $null }
        if (-not $launchedFile -or $launchedFile.Extension -ine ".msi") { continue }
        try {
            $launchedProcess.Refresh()
            if (-not $launchedProcess.HasExited) {
                [void]$payloadExitNotes.Add("MSI $($launchedFile.Name) was still running when the $payloadObservationSeconds-second observation limit ended. The installation was not confirmed; check C:\Telemetry\msiexec-install.log for progress or errors.")
            }
        } catch { $msiProcessStateUnknown = $true }
    }

    $msiStillRunning = @($payloadExitNotes | Where-Object { $_ -match "(?i)^MSI .* was still running when the" }).Count -gt 0
    if ($payloadExitFailure) {
        $exitNoteText = if ($payloadExitNotes.Count -gt 0) { " " + ($payloadExitNotes -join " ") } else { "" }
        Set-RunnerStatus -State "INCONCLUSIVE" -Details "$payloadExitFailure$exitNoteText The observation window ended, but successful execution was not confirmed." -Launched $launchedCount
    } elseif ($msiStillRunning -or $msiProcessStateUnknown) {
        $exitNoteText = $payloadExitNotes -join " "
        if ($msiProcessStateUnknown) { $exitNoteText += " The runner could not verify the MSI process exit state." }
        Set-RunnerStatus -State "INCONCLUSIVE" -Details "$exitNoteText The installer did not have a verified completion within the bounded observation period; the sample was not cleared as safe." -Launched $launchedCount
    } else {
        $exitNoteText = if ($payloadExitNotes.Count -gt 0) { " " + ($payloadExitNotes -join " ") } else { "" }
        Set-RunnerStatus -State "COMPLETED" -Details "Observation window completed.$exitNoteText" -Launched $launchedCount
    }
    Stop-GuestFileChangeMonitor
} catch {
    Stop-GuestFileChangeMonitor
    $failureMessage = $_.Exception.Message
    $failureState = if ($failureMessage -match "(?i)^Unsupported payload runtime:") { "UNSUPPORTED" } else { "ERROR" }
    Set-RunnerStatus -State $failureState -Details $failureMessage
    exit 1
}
