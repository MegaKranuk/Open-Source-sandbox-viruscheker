$ErrorActionPreference = "Stop"

$StageFolder = "C:\Sample"
$PayloadFolder = Join-Path $StageFolder "payload"
$TelemetryFile = "C:\Telemetry\runner-status.json"
$RunnerHistoryFile = "C:\Telemetry\runner-start-history.log"
$FeatureSourceFolder = "C:\FeatureSource"
$ObservationSeconds = 120
$GuestReviewHeartbeatSeconds = 300
$PostRebootCheckSeconds = 20
$MaxZipEntries = 10000
$MaxExpandedBytes = 536870912
$MaxEntryRatio = 200
$MaxMonitoredFiles = 20000
$ObservationIntervalSeconds = 2
$LaunchRuntimePromptGraceSeconds = 5
$RunnerInstanceId = [Guid]::NewGuid().ToString("N")
$script:VbScriptEngineReady = $false
$script:VbScriptRuntimeFailure = $null

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
    $status | ConvertTo-Json -Compress | Set-Content -LiteralPath $TelemetryFile -Encoding UTF8
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

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)
    $tempFolder = Join-Path $env:TEMP ("Sample-" + [Guid]::NewGuid().ToString("N"))
    $expandedBytes = [long]0
    $actualExpandedBytes = [long]0
    $keepTempFolder = $false

    try {
        if ($archive.Entries.Count -gt $MaxZipEntries) {
            return [pscustomobject]@{ State = "ZIP_BOMB"; Details = "Archive contains more than $MaxZipEntries entries."; Files = @() }
        }
        $fileEntries = @($archive.Entries | Where-Object { -not [string]::IsNullOrEmpty($_.Name) })

        foreach ($entry in $fileEntries) {
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

        $nestedArchives = @(Get-ChildItem -LiteralPath $tempFolder -Recurse -File | Where-Object { $_.Extension -in @(".zip", ".7z", ".rar") })
        if ($nestedArchives.Count -gt 0) {
            return [pscustomobject]@{ State = "UNSUPPORTED"; Details = "Nested archives were not expanded; review this sample manually."; Files = @() }
        }

        $payloadFiles = @(Get-ChildItem -LiteralPath $tempFolder -Recurse -File)
        if ($payloadFiles.Count -eq 0) {
            return [pscustomobject]@{ State = "UNSUPPORTED"; Details = "The archive contains no files to analyze."; Files = @() }
        }

        $keepTempFolder = $true
        return [pscustomobject]@{ State = "READY"; Details = "Archive passed the extraction limits ($($fileEntries.Count) files, $actualExpandedBytes expanded bytes)."; Files = $payloadFiles; WorkFolder = $tempFolder }
    } finally {
        $archive.Dispose()
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

    $netFxSource = Join-Path $FeatureSourceFolder "sources\sxs"
    if (-not (Test-Path -LiteralPath $netFxSource)) {
        return ".NET Framework 3.5 is not enabled; to install it without internet, place the matching Windows installation media contents in C:\RBI_FeatureSource (including sources\sxs)."
    }

    $dism = Join-Path $env:SystemRoot "System32\dism.exe"
    $dismArguments = @("/Online", "/Enable-Feature", "/FeatureName:NetFx3", "/All", "/Source:$netFxSource", "/LimitAccess", "/NoRestart")
    $netFxLog = Join-Path (Split-Path -Parent $TelemetryFile) "netfx3-install.log"
    $runtimeStatusState = if ($AfterLaunch) { "INSTALLING_RUNTIME" } else { "PREPARING_RUNTIME" }
    $runtimeContext = if ($AfterLaunch) { "The sample launch is paused for runtime repair." } else { "The sample has not launched." }
    Set-RunnerStatus -State $runtimeStatusState -Details "Installing .NET Framework 3.5 from the local sources\sxs folder. $runtimeContext" -Launched $Launched
    try {
        $installResult = Invoke-DismWithProgress -Executable $dism -Arguments $dismArguments -Component ".NET Framework 3.5" -LogPath $netFxLog -StatusState $runtimeStatusState -Launched $Launched
    } catch {
        return ".NET Framework 3.5 could not be enabled from the offline source: $($_.Exception.Message)"
    }
    if ($installResult.ExitCode -eq 3010) {
        return ".NET Framework 3.5 installation requires a guest restart; the pipeline will not automatically relaunch a sample after reboot."
    }
    if ($installResult.ExitCode -ne 0) {
        return ".NET Framework 3.5 could not be installed from the offline source (DISM exit code $($installResult.ExitCode))."
    }

    $netFxState = Get-WindowsOptionalFeature -Online -FeatureName NetFx3 -ErrorAction SilentlyContinue
    if ($netFxState.State -ne "Enabled") {
        return ".NET Framework 3.5 installation did not reach the Enabled state."
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
            return Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $quotedPath /qn /norestart" -WorkingDirectory $File.DirectoryName -PassThru
        }
        ".reg" {
            return Start-Process -FilePath "reg.exe" -ArgumentList "import $quotedPath" -WorkingDirectory $File.DirectoryName -PassThru
        }
        default {
            return Start-Process -FilePath $File.FullName -WorkingDirectory $File.DirectoryName -PassThru
        }
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

function Get-GuestSnapshot {
    param ([string[]]$Roots)

    $snapshot = @{}
    foreach ($root in $Roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        $remainingCapacity = $MaxMonitoredFiles - $snapshot.Count
        if ($remainingCapacity -le 0) { break }
        $rootFiles = @(Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue | Select-Object -First $remainingCapacity)
        foreach ($file in $rootFiles) {
            $snapshot[$file.FullName] = "$($file.Length)|$($file.LastWriteTimeUtc.Ticks)"
        }
    }
    return ,$snapshot
}

function Get-GuestBehaviorSignal {
    param (
        [hashtable]$Baseline,
        [string[]]$Roots
    )

    $files = @()
    foreach ($root in $Roots) {
        if (Test-Path -LiteralPath $root) {
            $remainingCapacity = $MaxMonitoredFiles - $files.Count
            if ($remainingCapacity -le 0) { break }
            $files += @(Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue | Select-Object -First $remainingCapacity)
        }
    }

    $currentSnapshot = @{}
    foreach ($file in $files) {
        $currentSnapshot[$file.FullName] = "$($file.Length)|$($file.LastWriteTimeUtc.Ticks)"
    }

    $changedFiles = @($files | Where-Object {
        -not $Baseline.ContainsKey($_.FullName) -or $currentSnapshot[$_.FullName] -ne $Baseline[$_.FullName]
    } | ForEach-Object {
        [pscustomobject]@{ Path = $_.FullName.ToLowerInvariant(); At = $_.LastWriteTimeUtc }
    })
    $changedFiles = @($changedFiles | Sort-Object At)
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
        if ($pathCounts.Count -gt 10) {
            return "VIRUS: More than 10 distinct files changed within one second ($($pathCounts.Count) files); rapid mass file modification is consistent with ransomware or a file-bomber."
        }
    }

    $artifacts = @($files | Where-Object {
        (-not $Baseline.ContainsKey($_.FullName) -or $currentSnapshot[$_.FullName] -ne $Baseline[$_.FullName]) -and (
            $_.Name -match "(?i)(read.?me|decrypt|recover|restore|how.?to|ransom|help)" -or
            $_.Extension -match "(?i)^\.(lock|locked|encrypted|crypted|crypto|wnry|wncry|fun|pay|demons)$"
        )
    })
    if ($artifacts.Count -gt 0) {
        return "Ransom note or encrypted-file marker created in the guest: $($artifacts[0].FullName)"
    }

    foreach ($path in $Baseline.Keys) {
        if (-not $currentSnapshot.ContainsKey($path)) {
            return "A guest canary or working file was deleted: $(Split-Path -Leaf $path)"
        }
        if ($currentSnapshot[$path] -ne $Baseline[$path]) {
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
        (Join-Path $userProfile "Downloads")
    )
    $monitorRoots += @(Get-ChildItem -LiteralPath $env:TEMP -Directory -Filter "Sample-*" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
    $monitorRoots = @($monitorRoots | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -Unique)
    $baseline = Get-GuestSnapshot -Roots $monitorRoots
    $reviewState = "POST_REBOOT_CHECK"
    $reviewDetails = "Guest reboot detected after prior state $priorState. Monitoring guest folders and canaries for $PostRebootCheckSeconds seconds; the sample will not be launched again automatically.$runtimeNote"
    Set-RunnerStatus -State $reviewState -Details $reviewDetails -Launched 0

    for ($elapsed = 0; $elapsed -lt $PostRebootCheckSeconds; $elapsed += $ObservationIntervalSeconds) {
        $behaviorSignal = Get-GuestBehaviorSignal -Baseline $baseline -Roots $monitorRoots
        if ($behaviorSignal) {
            $reviewState = if ($behaviorSignal -match '^VIRUS:\s*') { "VIRUS" } else { "SUSPICIOUS" }
            $reviewDetails = "$behaviorSignal Detected during the post-reboot observation; the sample was not relaunched."
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
    Set-RunnerStatus -State "STARTED" -Details "Sandbox logon command is running."
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
            Set-RunnerStatus -State $archiveResult.State -Details $archiveResult.Details
            exit 3
        }

        $filesToRun = @($archiveResult.Files | Where-Object { $_.Extension -in @(".exe", ".com", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi", ".hta", ".lnk", ".reg") } | Select-Object -First 5)
        $workFolder = $archiveResult.WorkFolder
        if ($filesToRun.Count -eq 0) {
            Set-RunnerStatus -State "UNSUPPORTED" -Details "ZIP was inspected and extracted within limits, but it contains no supported executable payload."
            exit 4
        }
    } elseif ($sample.Extension -in @(".7z", ".rar", ".tar", ".tgz", ".gz", ".bz2", ".xz")) {
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
        (Join-Path $userProfile "Downloads"),
        $workFolder
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique

    $visibleFolders = @(
        (Join-Path $userProfile "Desktop\AnalysisData"),
        (Join-Path $userProfile "Documents\AnalysisData")
    )
    foreach ($visibleFolder in $visibleFolders) {
        if (Test-Path -LiteralPath $visibleFolder) {
            $explorerArguments = '/n,"' + $visibleFolder + '"'
            Start-Process -FilePath "explorer.exe" -ArgumentList $explorerArguments -ErrorAction SilentlyContinue | Out-Null
        }
    }
    Start-Sleep -Seconds 3

    $baseline = Get-GuestSnapshot -Roots $monitorRoots

    $launchedCount = 0
    $launchedProcesses = @()
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
    $launchPromptProbe = [System.Diagnostics.Stopwatch]::StartNew()
    while ($launchPromptProbe.Elapsed.TotalSeconds -lt $LaunchRuntimePromptGraceSeconds) {
        $initialRuntimePrompt = Find-MissingRuntimePrompt
        if ($initialRuntimePrompt) { break }
        Start-Sleep -Milliseconds 500
    }
    if ($initialRuntimePrompt) {
        $initialRuntimeName = if ($initialRuntimePrompt.Runtime -eq "NetFx3") { ".NET Framework 3.5" } else { "VBScript" }
        Set-RunnerStatus -State "INSTALLING_RUNTIME" -Details "RUNTIME_REMEDIATION: Detected the exact $initialRuntimeName missing-runtime dialog immediately after launch. Installing from the mounted offline feature source; the sample launch is paused." -Launched $launchedCount
    } else {
        Set-RunnerStatus -State "RUNNING" -Details ("Payload launch completed; watching guest user folders, the writable working folder, and host canaries for $ObservationSeconds seconds." + $runtimeNoticeText) -Launched $launchedCount
    }
    $lastHeartbeatUtc = [DateTime]::UtcNow
    for ($elapsed = 0; $elapsed -lt $ObservationSeconds; $elapsed += $ObservationIntervalSeconds) {
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
            Set-RunnerStatus -State "INSTALLING_RUNTIME" -Details "RUNTIME_REMEDIATION: Detected the exact $runtimeDisplayName missing-runtime dialog. Installing from the mounted offline feature source; the sample launch is paused." -Launched $launchedCount

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
                    Set-RunnerStatus -State "UNSUPPORTED" -Details ".NET Framework 3.5 was requested by the sample, but automatic offline installation failed: $netFxInstallNotice" -Launched $launchedCount
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

        $behaviorSignal = Get-GuestBehaviorSignal -Baseline $baseline -Roots $monitorRoots
        if ($behaviorSignal) {
            $behaviorState = if ($behaviorSignal -match '^VIRUS:\s*') { "VIRUS" } else { "SUSPICIOUS" }
            Set-RunnerStatus -State $behaviorState -Details ($behaviorSignal + " Payload remains in the isolated Sandbox for the host demonstration window.") -Launched $launchedCount
            for ($lingerSeconds = 0; $lingerSeconds -lt $GuestReviewHeartbeatSeconds; $lingerSeconds += $ObservationIntervalSeconds) {
                if ($behaviorState -ne "VIRUS") {
                    $laterBehaviorSignal = Get-GuestBehaviorSignal -Baseline $baseline -Roots $monitorRoots
                    if ($laterBehaviorSignal -match '^VIRUS:\s*') {
                        $behaviorState = "VIRUS"
                        $behaviorSignal = $laterBehaviorSignal
                    }
                }
                if (($lingerSeconds % 6) -eq 0) {
                    Set-RunnerStatus -State $behaviorState -Details ($behaviorSignal + " The Sandbox remains open for interactive review; guest heartbeat is active.") -Launched $launchedCount
                }
                Start-Sleep -Seconds $ObservationIntervalSeconds
            }
            exit 5
        }
        Start-Sleep -Seconds $ObservationIntervalSeconds
    }
    Set-RunnerStatus -State "COMPLETED" -Details "Observation window completed." -Launched $launchedCount
} catch {
    $failureMessage = $_.Exception.Message
    $failureState = if ($failureMessage -match "(?i)^Unsupported payload runtime:") { "UNSUPPORTED" } else { "ERROR" }
    Set-RunnerStatus -State $failureState -Details $failureMessage
    exit 1
}
