param(
    [Parameter(Mandatory)][string]$PackageDir,
    [string]$ProjectDir = 'C:\RBI\sandbox scripts'
)

$ErrorActionPreference = 'Stop'
$SysmonHash = '83D31F2478DC6716CFDBF69E5C384BF043072B5F0D8D7B2EEA365F709FDA4352'
$Checks = New-Object System.Collections.Generic.List[string]
function Add-Check([string]$text) { $Checks.Add($text) }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'Run this script in an elevated (Administrator) PowerShell window.' }

$manifestPath = Join-Path $PackageDir 'manifest.csv'
if (-not (Test-Path -LiteralPath $manifestPath)) { throw "manifest.csv not found in $PackageDir" }
$manifest = Import-Csv -LiteralPath $manifestPath
$bad = @()
foreach ($m in $manifest) {
    $p = Join-Path $PackageDir $m.Path
    if (-not (Test-Path -LiteralPath $p)) { $bad += "MISSING  $($m.Path)"; continue }
    $size = (Get-Item -LiteralPath $p).Length
    $hash = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash
    if ([string]$size -ne [string]$m.Size) { $bad += "SIZE     $($m.Path) ($size, expected $($m.Size))" }
    elseif ($hash -ne $m.Sha256) { $bad += "HASH     $($m.Path)" }
}
if ($bad.Count -gt 0) {
    Write-Host 'FAIL: the package does not match its manifest. Nothing was deployed:' -ForegroundColor Red
    $bad | ForEach-Object { Write-Host "  $_" }
    return
}
Add-Check ("package verified: {0} files match manifest.csv" -f $manifest.Count)

$backup = Join-Path $ProjectDir ('_backup-deploy-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
$backedUp = 0
function Copy-WithBackup([string]$src, [string]$dst) {
    if (Test-Path -LiteralPath $dst) {
        $bk = Join-Path $script:backup ([IO.Path]::GetFileName($dst))
        New-Item -ItemType Directory -Force -Path $script:backup | Out-Null
        Copy-Item -LiteralPath $dst -Destination $bk -Force
        $script:backedUp++
    }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dst) | Out-Null
    Copy-Item -LiteralPath $src -Destination $dst -Force
}

foreach ($m in $manifest) {
    if ($m.Path -eq 'baseline.zip') { continue }
    $src = Join-Path $PackageDir $m.Path
    $dst = Join-Path $ProjectDir $m.Path
    Copy-WithBackup $src $dst
}
Add-Check ("project files copied to {0} (replaced files backed up: {1})" -f $ProjectDir, $backedUp)
$baseDir = 'C:\Quarantine_Zone\Baseline'
New-Item -ItemType Directory -Force -Path $baseDir | Out-Null
$baseTmp = Join-Path $env:TEMP 'rbi-baseline-unpack'
Remove-Item $baseTmp -Recurse -Force -ErrorAction SilentlyContinue
Expand-Archive -LiteralPath (Join-Path $PackageDir 'baseline.zip') -DestinationPath $baseTmp -Force
if (Test-Path -LiteralPath (Join-Path $baseDir 'baseline.csv')) {
    New-Item -ItemType Directory -Force -Path $script:backup | Out-Null
    Copy-Item -LiteralPath (Join-Path $baseDir 'baseline.csv') -Destination (Join-Path $script:backup 'baseline.csv') -Force
    $backedUp++
}
Copy-Item -LiteralPath (Join-Path $baseTmp 'baseline.csv') -Destination (Join-Path $baseDir 'baseline.csv') -Force
Remove-Item $baseTmp -Recurse -Force
$baseLines = @(Import-Csv -LiteralPath (Join-Path $baseDir 'baseline.csv')).Count
Add-Check ("baseline unpacked to {0}\baseline.csv ({1} entries)" -f $baseDir, $baseLines)
$workingProfile = $env:USERPROFILE
$workingUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
try {
    $interactiveUser = [string](Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).UserName
    if (-not [string]::IsNullOrWhiteSpace($interactiveUser)) {
        $interactiveSid = [System.Security.Principal.NTAccount]::new($interactiveUser).Translate([System.Security.Principal.SecurityIdentifier]).Value
        $interactiveProfile = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop |
            Where-Object { $_.SID -eq $interactiveSid -and $_.Loaded } |
            Select-Object -First 1
        if ($interactiveProfile) {
            $workingProfile = [string]$interactiveProfile.LocalPath
            $workingUser = $interactiveUser
        }
    }
} catch {}
$desk = Join-Path $workingProfile 'Desktop'
foreach ($d in @((Join-Path $workingProfile 'Downloads'), (Join-Path $desk 'Safe_Files'), (Join-Path $desk 'Review_Files'),
                 'C:\Quarantine_Zone\HashCache', 'C:\Quarantine_Zone\killswitch-archive')) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
}
Add-Check ("working folders ready for {0}: Downloads, Desktop\Safe_Files, Desktop\Review_Files, Quarantine_Zone\HashCache" -f $workingUser)
$toolsDir = 'C:\RBI_EdrTools'
New-Item -ItemType Directory -Force -Path $toolsDir | Out-Null
$sysmonExe = Join-Path $toolsDir 'Sysmon64.exe'
$sysmonOk = $false
if ((Test-Path -LiteralPath $sysmonExe) -and ((Get-FileHash -LiteralPath $sysmonExe -Algorithm SHA256).Hash -eq $SysmonHash)) {
    $sysmonOk = $true
} else {
    $tmp = Join-Path $env:TEMP 'rbi-sysmon-get'
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile "$tmp\Sysmon.zip" -UseBasicParsing
    Expand-Archive -LiteralPath "$tmp\Sysmon.zip" -DestinationPath "$tmp\x" -Force
    $cand = "$tmp\x\Sysmon64.exe"
    $candHash = (Get-FileHash -LiteralPath $cand -Algorithm SHA256).Hash
    $sig = Get-AuthenticodeSignature -LiteralPath $cand
    if ($candHash -eq $SysmonHash -and [string]$sig.Status -eq 'Valid') {
        if (Test-Path -LiteralPath $sysmonExe) { Copy-Item -LiteralPath $sysmonExe -Destination (Join-Path $script:backup 'Sysmon64.exe.old') -Force -ErrorAction SilentlyContinue }
        Copy-Item -LiteralPath $cand -Destination $sysmonExe -Force
        $sysmonOk = $true
    } else {
        Write-Host ("Sysmon check FAILED: sha256={0} sig={1}. Sysmon was NOT installed." -f $candHash, $sig.Status) -ForegroundColor Red
    }
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
Add-Check ("Sysmon64.exe: {0}" -f $(if ($sysmonOk) { 'verified (SHA-256 and Microsoft signature)' } else { 'NOT installed, fix before running' }))

foreach ($src in @('C:\RBI_FeatureSource', 'C:\RBI_NetFx3Source')) { New-Item -ItemType Directory -Force -Path $src | Out-Null }
Add-Check 'RBI_FeatureSource and RBI_NetFx3Source created EMPTY: VBScript and .NET 3.5 samples will be INCONCLUSIVE until install media is copied there'

$feature = Get-WindowsOptionalFeature -Online -FeatureName 'Containers-DisposableClientVM' -ErrorAction SilentlyContinue
if ($feature -and $feature.State -eq 'Enabled') { Add-Check 'Windows Sandbox feature: enabled' }
else { Add-Check 'Windows Sandbox feature: NOT enabled. Enable it (Containers-DisposableClientVM) and reboot before running' }
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
if ($cv.CurrentBuild -eq '26100' -and $cv.UBR -eq '9974') { Add-Check 'host build matches the baseline build (26100.9974)' }
else { Add-Check ("host build is {0}.{1}; the baseline was made on 26100.9974. Expect extra SUSPICIOUS-BASELINE lines until the baseline is rebuilt here" -f $cv.CurrentBuild, $cv.UBR) }

Write-Host ''
Write-Host '=== Deploy checklist ===' -ForegroundColor Cyan
$Checks | ForEach-Object { Write-Host (' - ' + $_) }
Write-Host ''
Write-Host "Backups (if any): $backup"
Write-Host "To run: cd `"$ProjectDir`"; .\start-rbi.ps1   (or run-sandbox.bat as Administrator)"
